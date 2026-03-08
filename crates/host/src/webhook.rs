// Async webhook / SIEM egress dispatcher.
//
// When WEBHOOK_URL is set, security events are forwarded to an external endpoint
// in the background without blocking the cognitive loop.
//
// Supported SIEM_FORMAT values:
//   json  — standard JSON body (default, works with Slack, custom endpoints, Splunk HEC)
//   cef   — ArcSight Common Event Format (syslog-style header line)
//   leef  — IBM LEEF 2.0 (tab-separated key-value pairs)
//
// Security env vars:
//   WEBHOOK_HMAC_SECRET=<secret>   — signs each POST with X-EctoLedger-Signature: sha256=<hex>
//   WEBHOOK_INCLUDE_GUARD=true     — also fire for GuardDenial events (default: true)
//   WEBHOOK_INCLUDE_TRIPWIRE=true  — also fire for TripwireRejection events (default: true)
//
// Rate / capacity:
//   WEBHOOK_RATE_LIMIT_PER_SECOND  — max deliveries per second per URL (default: 10)
//   CHANNEL_CAPACITY (256)         — event queue depth; excess events are logged and dropped
//                                    to keep the agent cognitive loop non-blocking.

use crate::config::{self, WebhookConfig};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::mpsc;
use uuid::Uuid;

const CHANNEL_CAPACITY: usize = 256;
/// Maximum number of HTTP retry attempts for a single webhook delivery.
const MAX_RETRIES: u32 = 3;

/// Kind of security event being dispatched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EgressKind {
    /// An observation rule flagged or aborted the session.
    Observation,
    /// The semantic guard process denied a hostile action.
    GuardDenial,
    /// A tripwire pattern was matched and the action was rejected.
    TripwireRejection,
}

impl EgressKind {
    fn as_str(&self) -> &'static str {
        match self {
            EgressKind::Observation => "observation",
            EgressKind::GuardDenial => "guard_denial",
            EgressKind::TripwireRejection => "tripwire_rejection",
        }
    }
}

/// A security event dispatched from the cognitive loop to the egress worker.
#[derive(Clone, Debug)]
pub struct EgressEvent {
    pub session_id: Uuid,
    /// `"flag"` when an observation rule triggers a warning, `"abort"` when it terminates the session.
    pub severity: String,
    /// Short label from the `ObservationRule` / guard / tripwire that matched.
    pub rule_label: String,
    /// First 200 chars of the sanitized observation content (no raw secrets).
    pub observation_preview: String,
    /// Category of event being reported.
    pub kind: EgressKind,
}

/// Spawns the background egress worker and returns the sender end of its channel.
/// The worker dispatches to:
///   1. The legacy `WEBHOOK_URL` env-var target (if `config` is `Some`), with retry.
///   2. Any active rows in the `webhooks` database table created via the API.
///
/// The worker runs until all senders are dropped.
///
/// The channel is bounded to `CHANNEL_CAPACITY`. Callers should prefer
/// `try_enqueue_event` over direct `.send()` to avoid blocking the cognitive loop
/// when the worker cannot keep up with event production.
pub fn spawn_egress_worker(
    config: Option<WebhookConfig>,
    pool: PgPool,
) -> (mpsc::Sender<EgressEvent>, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<EgressEvent>(CHANNEL_CAPACITY);
    let handle = tokio::spawn(async move {
        loop {
            let result =
                std::panic::AssertUnwindSafe(egress_loop(config.clone(), pool.clone(), &mut rx));
            match futures_util::FutureExt::catch_unwind(result).await {
                Ok(()) => {
                    // Normal shutdown — all senders dropped.
                    tracing::info!("Webhook egress worker shutting down (all senders dropped)");
                    break;
                }
                Err(e) => {
                    // The receiver is passed by &mut reference, so it survives
                    // the panicked future.  Log, back off briefly, and restart.
                    tracing::error!(
                        "webhook egress_loop panicked: {:?} — restarting worker in 1s",
                        e
                    );
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    });
    (tx, handle)
}

/// Non-blocking enqueue: attempts `try_send`; on a full channel the event is
/// immediately dropped with a warning.  This prevents unbounded task spawning
/// under sustained load (DoS) while keeping the cognitive loop non-blocking.
pub fn try_enqueue_event(tx: &mpsc::Sender<EgressEvent>, event: EgressEvent) {
    match tx.try_send(event) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(ev)) => {
            tracing::warn!(
                "Webhook egress channel full (capacity {}); dropping {} event for session {}. System is under heavy load.",
                CHANNEL_CAPACITY,
                ev.kind.as_str(),
                ev.session_id
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!("Webhook egress channel closed; event dropped.");
        }
    }
}

/// Compute an HMAC-SHA256 signature over the body using the given secret.
/// Returns a lowercase hex string formatted as required by the
/// `X-EctoLedger-Signature` header: `sha256=<hex>`, or `None` on key error.
fn hmac_signature(body: &str, secret: &str) -> Option<String> {
    type HmacSha256 = Hmac<Sha256>;
    match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(mut mac) => {
            mac.update(body.as_bytes());
            let result = mac.finalize();
            Some(format!("sha256={}", hex::encode(result.into_bytes())))
        }
        Err(e) => {
            // InvalidLength is the only possible error; log and skip signing
            // rather than panicking inside the egress task.
            tracing::error!(
                "HMAC-SHA256 init failed (invalid key length {}): {}",
                secret.len(),
                e
            );
            None
        }
    }
}

async fn egress_loop(
    config: Option<WebhookConfig>,
    pool: PgPool,
    rx: &mut mpsc::Receiver<EgressEvent>,
) {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|e| {
            tracing::warn!(
                "reqwest Client::builder() failed in webhook egress ({e}); using default client"
            );
            reqwest::Client::new()
        });

    let include_guard = config::webhook_include_guard();
    let include_tripwire = config::webhook_include_tripwire();

    // Validate the legacy WEBHOOK_URL against SSRF via actual DNS resolution.
    if let Some(ref cfg) = config {
        if let Ok(parsed) = url::Url::parse(&cfg.url) {
            let scheme = parsed.scheme();
            if scheme != "http" && scheme != "https" {
                tracing::error!(
                    "WEBHOOK_URL has disallowed scheme '{}' — webhook egress disabled",
                    scheme
                );
                return;
            }
            if let Some(host) = parsed.host_str() {
                let port = parsed
                    .port()
                    .unwrap_or(if scheme == "https" { 443 } else { 80 });
                match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                    Ok(addrs) => {
                        for addr in addrs {
                            let ip = addr.ip();
                            let is_private = match ip {
                                std::net::IpAddr::V4(v4) => {
                                    v4.is_loopback()
                                        || v4.is_private()
                                        || v4.is_link_local()
                                        || v4.is_unspecified()
                                }
                                std::net::IpAddr::V6(v6) => {
                                    v6.is_loopback()
                                        || v6.is_unspecified()
                                        || v6.to_ipv4_mapped().is_some_and(|v4| {
                                            v4.is_loopback()
                                                || v4.is_private()
                                                || v4.is_link_local()
                                        })
                                }
                            };
                            if is_private {
                                tracing::error!(
                                    "WEBHOOK_URL host '{}' resolves to internal address {} — webhook egress disabled (SSRF/DNS-rebinding protection)",
                                    host,
                                    ip
                                );
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "WEBHOOK_URL host '{}' DNS resolution failed: {} — webhook egress disabled",
                            host,
                            e
                        );
                        return;
                    }
                }
            }
        } else {
            tracing::error!("WEBHOOK_URL is not a valid URL — webhook egress disabled");
            return;
        }
    }

    while let Some(event) = rx.recv().await {
        // Filter by kind based on env config.
        let should_send = match event.kind {
            EgressKind::Observation => true,
            EgressKind::GuardDenial => include_guard,
            EgressKind::TripwireRejection => include_tripwire,
        };
        if !should_send {
            continue;
        }

        // 1. Dispatch to the legacy env-var configured webhook (if present) in a
        //    background task so one slow/failing webhook doesn't block the loop.
        if let Some(ref cfg) = config {
            let body = format_event(&event, &cfg.siem_format);
            let hmac_secret = config::webhook_hmac_secret();
            let cfg_url = cfg.url.clone();
            let cfg_bearer = cfg.bearer_token.clone();
            let cfg_format = cfg.siem_format.clone();
            let client_clone = client.clone();
            let event_session = event.session_id;
            let event_label = event.rule_label.clone();
            let event_kind = event.kind.as_str().to_string();
            tokio::spawn(async move {
                let mut last_err: Option<String> = None;
                for attempt in 0..MAX_RETRIES {
                    if attempt > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(1 << (attempt - 1)))
                            .await;
                    }
                    let mut req = client_clone
                        .post(&cfg_url)
                        .header("Content-Type", content_type(&cfg_format))
                        .body(body.clone());
                    if let Some(ref token) = cfg_bearer {
                        req = req.header("Authorization", format!("Bearer {}", token));
                    }
                    if let Some(ref secret) = hmac_secret
                        && let Some(sig) = hmac_signature(&body, secret)
                    {
                        req = req.header("X-EctoLedger-Signature", sig);
                    }
                    match req.send().await {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                last_err = None;
                                break;
                            } else {
                                last_err = Some(format!("HTTP {}", resp.status()));
                            }
                        }
                        Err(e) => {
                            last_err = Some(e.to_string());
                        }
                    }
                }
                if let Some(err) = last_err {
                    tracing::warn!(
                        "Webhook egress failed after {} attempts (session={} label={} kind={}): {}",
                        MAX_RETRIES,
                        event_session,
                        event_label,
                        event_kind,
                        err
                    );
                }
            });
        }

        // 2. Dispatch to all active DB-configured webhook rows in the background.
        let client_for_db = client.clone();
        let pool_for_db = pool.clone();
        tokio::spawn(async move {
            dispatch_db_webhooks(&client_for_db, &pool_for_db, &event).await;
        });
    }
}

/// Loads active webhook rows from the database and dispatches the event to each one,
/// respecting each row's `filter_kinds` and applying the same retry policy as the
/// env-var webhook target.
async fn dispatch_db_webhooks(client: &reqwest::Client, pool: &PgPool, event: &EgressEvent) {
    // (url, bearer_token, siem_format, filter_kinds)
    let rows: Vec<(String, Option<String>, String, Vec<String>)> = match sqlx::query_as(
        "SELECT url, bearer_token, siem_format, filter_kinds \
         FROM webhooks WHERE enabled = true",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("Failed to load webhook rows from DB: {}", e);
            return;
        }
    };

    for (url, bearer_token, siem_format, filter_kinds) in rows {
        // Per-row kind filter: empty filter_kinds means accept everything.
        if !filter_kinds.is_empty() && !filter_kinds.contains(&event.kind.as_str().to_string()) {
            continue;
        }

        // ISSUE-10: Re-validate every DB-stored URL for SSRF via DNS resolution.
        // A URL that was valid at insertion time may have been mutated in the DB,
        // or internal DNS may have changed since the row was written.
        match url::Url::parse(&url) {
            Ok(parsed) => {
                let scheme = parsed.scheme();
                if scheme != "http" && scheme != "https" {
                    tracing::warn!(
                        "DB webhook URL has disallowed scheme '{}' — skipping (SSRF protection)",
                        scheme
                    );
                    continue;
                }
                if let Some(host) = parsed.host_str() {
                    let port = parsed
                        .port()
                        .unwrap_or(if scheme == "https" { 443 } else { 80 });
                    match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
                        Ok(addrs) => {
                            let mut blocked = false;
                            for addr in addrs {
                                let ip = addr.ip();
                                let is_private = match ip {
                                    std::net::IpAddr::V4(v4) => {
                                        v4.is_loopback()
                                            || v4.is_private()
                                            || v4.is_link_local()
                                            || v4.is_unspecified()
                                    }
                                    std::net::IpAddr::V6(v6) => {
                                        v6.is_loopback()
                                            || v6.is_unspecified()
                                            || v6.to_ipv4_mapped().is_some_and(|v4| {
                                                v4.is_loopback()
                                                    || v4.is_private()
                                                    || v4.is_link_local()
                                            })
                                    }
                                };
                                if is_private {
                                    tracing::warn!(
                                        "DB webhook host '{}' resolves to internal address {} — skipping (SSRF/DNS-rebinding)",
                                        host,
                                        ip
                                    );
                                    blocked = true;
                                    break;
                                }
                            }
                            if blocked {
                                continue;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                "DB webhook host '{}' DNS resolution failed: {} — skipping",
                                host,
                                e
                            );
                            continue;
                        }
                    }
                }
            }
            Err(_) => {
                tracing::warn!("DB webhook URL '{}' is not a valid URL — skipping", url);
                continue;
            }
        }

        let body = format_event(event, &siem_format);
        let hmac_secret = config::webhook_hmac_secret();
        let client_clone = client.clone();
        let session_id = event.session_id;
        let rule_label = event.rule_label.clone();

        // Spawn a new task so this webhook's retries don't block the next webhook
        tokio::spawn(async move {
            let mut last_err: Option<String> = None;
            for attempt in 0..MAX_RETRIES {
                if attempt > 0 {
                    let delay_secs = std::cmp::min(1u64 << (attempt - 1), 60);
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                }
                let mut req = client_clone
                    .post(&url)
                    .header("Content-Type", content_type(&siem_format))
                    .body(body.clone());
                if let Some(ref token) = bearer_token {
                    req = req.header("Authorization", format!("Bearer {}", token));
                }
                if let Some(ref secret) = hmac_secret
                    && let Some(sig) = hmac_signature(&body, secret)
                {
                    req = req.header("X-EctoLedger-Signature", sig);
                }
                match req.send().await {
                    Ok(resp) => {
                        if resp.status().is_success() {
                            last_err = None;
                            break;
                        } else {
                            last_err = Some(format!("HTTP {}", resp.status()));
                        }
                    }
                    Err(e) => {
                        last_err = Some(e.to_string());
                    }
                }
            }
            if let Some(err) = last_err {
                tracing::warn!(
                    "DB webhook {} delivery failed after {} attempts (session={} label={}): {}",
                    url,
                    MAX_RETRIES,
                    session_id,
                    rule_label,
                    err
                );
            }
        });
    }
}

fn content_type(format: &str) -> &'static str {
    match format {
        "cef" | "leef" => "text/plain",
        _ => "application/json",
    }
}

fn format_event(event: &EgressEvent, format: &str) -> String {
    match format {
        "cef" => format_cef(event),
        "leef" => format_leef(event),
        _ => format_json(event),
    }
}

fn format_json(event: &EgressEvent) -> String {
    serde_json::json!({
        "source": "ectoledger",
        "session_id": event.session_id.to_string(),
        "event_kind": event.kind.as_str(),
        "severity": event.severity,
        "rule_label": event.rule_label,
        "observation_preview": event.observation_preview,
        "timestamp": chrono::Utc::now().to_rfc3339(),
    })
    .to_string()
}

/// Sanitise a string for use in CEF header fields (pipe-delimited).
fn sanitize_cef_header(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\n', '\r'], " ")
}

/// Sanitise a string for use in CEF extension key=value pairs.
fn sanitize_cef_extension(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace(['\n', '\r'], "\\n")
}

/// ArcSight CEF (Common Event Format): syslog-like header + key-value extension.
fn format_cef(event: &EgressEvent) -> String {
    let cef_severity = if event.severity == "abort" { "9" } else { "5" };
    format!(
        "CEF:0|Ecto Ledger|EctoLedger|1.0|{kind}|{rule}|{sev}|session={sid} label={label} preview={prev}",
        kind = event.kind.as_str(),
        rule = sanitize_cef_header(&event.rule_label),
        sev = cef_severity,
        sid = event.session_id,
        label = sanitize_cef_extension(&event.rule_label),
        prev = sanitize_cef_extension(&event.observation_preview),
    )
}

/// Sanitise a string for use in LEEF header/extension fields.
fn sanitize_leef(s: &str) -> String {
    s.replace('|', "_").replace(['\t', '\n', '\r'], " ")
}

/// IBM LEEF 2.0: tab-separated key-value attributes after a header.
fn format_leef(event: &EgressEvent) -> String {
    format!(
        "LEEF:2.0|Ecto Ledger|EctoLedger|1.0|{kind}|\tsrc=ectoledger\tsessionId={sid}\tseverity={sev}\truleLabel={label}\tobservation={prev}",
        kind = event.kind.as_str(),
        sid = event.session_id,
        sev = sanitize_leef(&event.severity),
        label = sanitize_leef(&event.rule_label),
        prev = sanitize_leef(&event.observation_preview),
    )
}
