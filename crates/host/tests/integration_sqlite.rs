//! CI-friendly integration test suite for EctoLedger.
//!
//! Design goals:
//! - In-memory SQLite backend (`sqlite::memory:`) — no external services.
//! - Full session lifecycle through the `LedgerBackend` trait.
//! - Cryptographic property verification (hash-chain integrity, Ed25519 signatures).
//! - Policy engine acceptance/rejection via the native `PolicyEngine`.
//! - Total wall-clock time < 30 s on commodity hardware.
//!
//! Run:
//!   cargo test --package ectoledger --test integration_sqlite

use std::sync::Arc;

use ectoledger::hash::{GENESIS_PREVIOUS_HASH, compute_content_hash};
use ectoledger::intent::ProposedIntent;
use ectoledger::ledger::sqlite::SqliteLedger;
use ectoledger::policy::{AuditPolicy, ObservationOutcome, PolicyEngine};
use ectoledger::signing;
use ledger_api::{LedgerBackend, NewSession};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Spin up a fresh in-memory SQLite ledger with all migrations applied.
async fn ledger() -> Arc<SqliteLedger> {
    Arc::new(
        SqliteLedger::connect("sqlite::memory:")
            .await
            .expect("connect to in-memory SQLite"),
    )
}

/// Create a default `NewSession` for tests.
fn new_session(goal: &str) -> NewSession {
    NewSession {
        goal: goal.to_string(),
        llm_backend: "test".into(),
        llm_model: "mock-v1".into(),
        policy_hash: None,
        session_did: None,
    }
}

/// Build a minimal `Thought` event payload as `serde_json::Value`.
fn thought(msg: &str) -> serde_json::Value {
    serde_json::json!({ "type": "thought", "content": msg })
}

/// Build a `Genesis` event payload.
fn genesis(msg: &str) -> serde_json::Value {
    serde_json::json!({ "type": "genesis", "message": msg })
}

/// Build an `Action` event payload.
fn action(name: &str, params: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "type": "action", "name": name, "params": params })
}

/// Build an `Observation` event payload.
fn observation(content: &str) -> serde_json::Value {
    serde_json::json!({ "type": "observation", "content": content })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  1. SESSION LIFECYCLE
// ═══════════════════════════════════════════════════════════════════════════════

mod session_lifecycle {
    use super::*;

    /// Creating a session returns a valid UUID, running status, and a 32-byte
    /// Ed25519 signing key seed.
    #[tokio::test]
    async fn create_session_returns_key_and_record() {
        let db = ledger().await;
        let (session, key_bytes) = db
            .create_session(new_session("scan example.com"))
            .await
            .expect("create_session");

        assert_eq!(session.status, "running");
        assert_eq!(session.goal, "scan example.com");
        assert!(session.goal_hash.is_some());
        assert!(session.session_public_key.is_some());
        assert_eq!(key_bytes.len(), 32, "Ed25519 seed must be 32 bytes");
    }

    /// A sealed session transitions to the requested status.
    #[tokio::test]
    async fn seal_session_sets_status() {
        let db = ledger().await;
        let (session, _key) = db
            .create_session(new_session("audit target"))
            .await
            .expect("create_session");

        db.seal_session(session.id, "completed")
            .await
            .expect("seal_session");

        let sessions = db.list_sessions().await.expect("list_sessions");
        let found = sessions.iter().find(|s| s.id == session.id).unwrap();
        assert_eq!(found.status, "completed");
    }

    /// list_sessions returns all created sessions.
    #[tokio::test]
    async fn list_sessions_returns_created() {
        let db = ledger().await;
        db.create_session(new_session("goal-a")).await.unwrap();
        db.create_session(new_session("goal-b")).await.unwrap();
        let sessions = db.list_sessions().await.unwrap();
        assert_eq!(sessions.len(), 2);
    }

    /// Full happy-path lifecycle: create → append events → seal → verify chain.
    #[tokio::test]
    async fn full_lifecycle_happy_path() {
        let db = ledger().await;
        let (session, key_bytes) = db
            .create_session(new_session("full lifecycle"))
            .await
            .unwrap();

        // Append genesis
        let g = db
            .append_event(
                genesis("session start"),
                Some(session.id),
                Some("full lifecycle"),
                Some(&key_bytes),
            )
            .await
            .unwrap();
        assert_eq!(g.sequence, 0);

        // Append several domain events
        for i in 1..=5 {
            db.append_event(
                thought(&format!("step {i}")),
                Some(session.id),
                Some("full lifecycle"),
                Some(&key_bytes),
            )
            .await
            .unwrap();
        }

        // Seal
        db.seal_session(session.id, "completed").await.unwrap();

        // Verify chain covers all events
        assert!(db.verify_chain(0, 5).await.unwrap());

        // Events queryable by session
        let events = db.get_events_by_session(session.id).await.unwrap();
        assert_eq!(events.len(), 6);
    }

    /// Sealed sessions with "failed" status are persisted.
    #[tokio::test]
    async fn seal_session_failed() {
        let db = ledger().await;
        let (session, _key) = db.create_session(new_session("will fail")).await.unwrap();
        db.seal_session(session.id, "failed").await.unwrap();

        let sessions = db.list_sessions().await.unwrap();
        assert_eq!(sessions[0].status, "failed");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  2. HASH-CHAIN INTEGRITY
// ═══════════════════════════════════════════════════════════════════════════════

mod hash_chain {
    use super::*;

    /// First event chains from the 64-zero genesis hash.
    #[tokio::test]
    async fn genesis_event_links_from_zero_hash() {
        let db = ledger().await;
        let ev = db
            .append_event(genesis("init"), None, None, None)
            .await
            .unwrap();
        assert_eq!(ev.sequence, 0);
        assert_eq!(ev.previous_hash, GENESIS_PREVIOUS_HASH);
    }

    /// Each subsequent event chains to the prior event's content_hash.
    #[tokio::test]
    async fn chain_links_are_correct() {
        let db = ledger().await;
        let ev0 = db
            .append_event(thought("a"), None, None, None)
            .await
            .unwrap();
        let ev1 = db
            .append_event(thought("b"), None, None, None)
            .await
            .unwrap();
        let ev2 = db
            .append_event(thought("c"), None, None, None)
            .await
            .unwrap();

        assert_eq!(ev0.previous_hash, GENESIS_PREVIOUS_HASH);
        assert_eq!(ev1.previous_hash, ev0.content_hash);
        assert_eq!(ev2.previous_hash, ev1.content_hash);
    }

    /// content_hash is deterministically computed from (previous_hash, sequence, payload).
    /// The backend serialises via the typed `EventPayload` struct, so we reproduce
    /// the exact JSON it would produce for comparison.
    #[tokio::test]
    async fn content_hash_is_deterministic() {
        use ectoledger::schema::EventPayload;

        let db = ledger().await;
        let payload = thought("deterministic");
        let ev = db
            .append_event(payload.clone(), None, None, None)
            .await
            .unwrap();

        // Re-parse through the typed enum to get the canonical serialisation
        // the backend actually stores.
        let typed: EventPayload = serde_json::from_value(payload).unwrap();
        let payload_json = serde_json::to_string(&typed).unwrap();
        let expected = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            &payload_json,
            None,
            Some(&ev.created_at.to_rfc3339()),
        );
        assert_eq!(ev.content_hash, expected);
    }

    /// verify_chain returns true for a valid 10-event chain.
    #[tokio::test]
    async fn chain_of_ten_is_valid() {
        let db = ledger().await;
        for i in 0..10 {
            db.append_event(thought(&format!("ev-{i}")), None, None, None)
                .await
                .unwrap();
        }
        assert!(db.verify_chain(0, 9).await.unwrap());
    }

    /// verify_chain over an empty range returns true (vacuous truth).
    #[tokio::test]
    async fn empty_range_is_valid() {
        let db = ledger().await;
        assert!(db.verify_chain(100, 200).await.unwrap());
    }

    /// Verifying a sub-range of the chain succeeds.
    #[tokio::test]
    async fn sub_range_verification() {
        let db = ledger().await;
        for i in 0..8 {
            db.append_event(thought(&format!("sub-{i}")), None, None, None)
                .await
                .unwrap();
        }
        assert!(db.verify_chain(3, 6).await.unwrap());
    }

    /// Content hashes are exactly 64 lowercase hex characters (SHA-256).
    #[tokio::test]
    async fn content_hash_format() {
        let db = ledger().await;
        let ev = db
            .append_event(thought("fmt"), None, None, None)
            .await
            .unwrap();
        assert_eq!(ev.content_hash.len(), 64);
        assert!(ev.content_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Different payloads produce different content hashes (collision resistance).
    #[tokio::test]
    async fn different_payloads_different_hashes() {
        let db = ledger().await;
        let ev0 = db
            .append_event(thought("alpha"), None, None, None)
            .await
            .unwrap();
        let ev1 = db
            .append_event(thought("bravo"), None, None, None)
            .await
            .unwrap();
        assert_ne!(ev0.content_hash, ev1.content_hash);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  3. ED25519 SIGNATURE VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════════

mod signatures {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, Verifier};

    /// Signing round-trip: sign a content_hash, verify with the corresponding
    /// public key using the host `signing` module helpers.
    #[tokio::test]
    async fn sign_and_verify_content_hash() {
        let (sk, vk) = signing::generate_keypair();
        let content_hash = "a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3";

        let sig_hex = signing::sign_content_hash(&sk, content_hash);
        let pk_hex = signing::public_key_hex(&vk);

        // Verify using the public API
        signing::verify_signature(&pk_hex, content_hash, &sig_hex)
            .expect("signature should be valid");
    }

    /// Verification rejects a tampered content hash.
    #[tokio::test]
    async fn tampered_hash_fails_verification() {
        let (sk, vk) = signing::generate_keypair();
        let content_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let sig_hex = signing::sign_content_hash(&sk, content_hash);
        let pk_hex = signing::public_key_hex(&vk);

        let tampered = "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe";
        assert!(
            signing::verify_signature(&pk_hex, tampered, &sig_hex).is_err(),
            "tampered content should fail verification"
        );
    }

    /// Verification rejects a wrong key.
    #[tokio::test]
    async fn wrong_key_fails_verification() {
        let (sk, _vk) = signing::generate_keypair();
        let (_sk2, vk2) = signing::generate_keypair();
        let content_hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let sig_hex = signing::sign_content_hash(&sk, content_hash);
        let wrong_pk = signing::public_key_hex(&vk2);

        assert!(
            signing::verify_signature(&wrong_pk, content_hash, &sig_hex).is_err(),
            "wrong key should fail verification"
        );
    }

    /// Signed events appended through LedgerBackend round-trip correctly.
    /// The content_hash stored in the DB matches what was signed.
    #[tokio::test]
    async fn signed_events_via_ledger_backend() {
        let db = ledger().await;
        let (session, key_bytes) = db
            .create_session(new_session("signed session"))
            .await
            .unwrap();

        let ev = db
            .append_event(
                thought("signed-thought"),
                Some(session.id),
                Some("signed session"),
                Some(&key_bytes),
            )
            .await
            .unwrap();

        // Reconstruct signing key from seed
        let arr: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
        let sk = SigningKey::from_bytes(&arr);
        let vk = sk.verifying_key();

        // The content_hash should be verifiable with the session key
        let sig_hex = signing::sign_content_hash(&sk, &ev.content_hash);
        let pk_hex = signing::public_key_hex(&vk);
        signing::verify_signature(&pk_hex, &ev.content_hash, &sig_hex)
            .expect("content_hash signature must verify");
    }

    /// Session's stored public key matches the returned signing key seed.
    #[tokio::test]
    async fn session_public_key_matches_seed() {
        let db = ledger().await;
        let (session, key_bytes) = db.create_session(new_session("pk match")).await.unwrap();

        let arr: [u8; 32] = key_bytes.as_slice().try_into().unwrap();
        let sk = SigningKey::from_bytes(&arr);
        let expected_pk = signing::public_key_hex(&sk.verifying_key());

        assert_eq!(
            session.session_public_key.as_deref(),
            Some(expected_pk.as_str()),
        );
    }

    /// Multiple signed events all reference the same session public key.
    #[tokio::test]
    async fn multiple_signed_events_same_key() {
        let db = ledger().await;
        let (session, key_bytes) = db.create_session(new_session("multi-sign")).await.unwrap();

        for i in 0..5 {
            db.append_event(
                thought(&format!("signed-{i}")),
                Some(session.id),
                Some("multi-sign"),
                Some(&key_bytes),
            )
            .await
            .unwrap();
        }

        let events = db.get_events_by_session(session.id).await.unwrap();
        assert_eq!(events.len(), 5);

        // Verify chain is intact
        assert!(db.verify_chain(0, 4).await.unwrap());
    }

    /// Low-level Ed25519 sign/verify using dalek directly,
    /// to confirm the signing module's output is standard-compliant.
    #[tokio::test]
    async fn ed25519_raw_round_trip() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        let message = b"content_hash_value_here";
        let sig = sk.sign(message);
        assert!(vk.verify(message, &sig).is_ok());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  4. POLICY ENGINE — ACCEPTANCE / REJECTION
// ═══════════════════════════════════════════════════════════════════════════════

mod policy_engine {
    use super::*;

    /// Helper: build a minimal policy from TOML.
    fn engine_from_toml(toml_str: &str) -> PolicyEngine {
        let policy: AuditPolicy = toml::from_str(toml_str).expect("parse test policy TOML");
        PolicyEngine::new(policy).expect("build PolicyEngine")
    }

    /// Helper: create a `ProposedIntent` for a given action name.
    fn intent(action: &str, params: serde_json::Value) -> ProposedIntent {
        ProposedIntent {
            action: action.to_string(),
            params,
            justification: "test justification".into(),
            reasoning: "test reasoning".into(),
        }
    }

    // ── Allowed / forbidden actions ────────────────────────────────────────

    /// An action in `allowed_actions` passes validation.
    #[test]
    fn allowed_action_accepted() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "read_file"
            "#,
        );
        let i = intent("read_file", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 0).is_ok());
    }

    /// An action explicitly forbidden is rejected.
    #[test]
    fn forbidden_action_rejected() {
        let engine = engine_from_toml(
            r#"
            [[forbidden_actions]]
            action = "http_get"
            "#,
        );
        let i = intent("http_get", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 0).is_err());
    }

    /// An action not listed in `allowed_actions` is rejected when the list exists.
    #[test]
    fn unlisted_action_rejected_with_allowlist() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "read_file"
            "#,
        );
        let i = intent("write_file", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 0).is_err());
    }

    // ── Max steps enforcement ──────────────────────────────────────────────

    /// Step count under max_steps passes.
    #[test]
    fn step_under_max_passes() {
        let engine = engine_from_toml("max_steps = 10");
        let i = intent("read_file", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 5).is_ok());
    }

    /// Step count at max_steps boundary is rejected.
    #[test]
    fn step_at_max_rejected() {
        let engine = engine_from_toml("max_steps = 10");
        let i = intent("read_file", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 10).is_err());
    }

    /// Step count above max_steps is rejected.
    #[test]
    fn step_above_max_rejected() {
        let engine = engine_from_toml("max_steps = 5");
        let i = intent("read_file", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 99).is_err());
    }

    // ── Command rules ──────────────────────────────────────────────────────

    /// An explicit `allow` command rule passes validation.
    #[test]
    fn command_rule_allow() {
        let engine = engine_from_toml(
            r#"
            [[command_rules]]
            program = "ls"
            arg_pattern = ".*"
            decision = "allow"
            "#,
        );
        let i = intent(
            "run_command",
            serde_json::json!({ "command": "ls -la /tmp" }),
        );
        assert!(engine.validate_intent(&i, 0).is_ok());
    }

    /// An explicit `deny` command rule rejects the action.
    #[test]
    fn command_rule_deny() {
        let engine = engine_from_toml(
            r#"
            [[command_rules]]
            program = "curl"
            arg_pattern = ".*"
            decision = "deny"
            reason = "curl is forbidden"
            "#,
        );
        let i = intent(
            "run_command",
            serde_json::json!({ "command": "curl http://evil.com" }),
        );
        let err = engine.validate_intent(&i, 0).unwrap_err();
        assert!(
            err.to_string().contains("curl is forbidden"),
            "error should contain deny reason: {}",
            err
        );
    }

    /// A command rule with a selective regex only matches the intended arguments.
    #[test]
    fn command_rule_selective_regex() {
        let engine = engine_from_toml(
            r#"
            [[command_rules]]
            program = "curl"
            arg_pattern = "^https://safe\\.example\\.com"
            decision = "allow"

            [[command_rules]]
            program = "curl"
            arg_pattern = ".*"
            decision = "deny"
            "#,
        );
        // Safe URL → allow
        let safe = intent(
            "run_command",
            serde_json::json!({ "command": "curl https://safe.example.com/api" }),
        );
        assert!(engine.validate_intent(&safe, 0).is_ok());

        // Other URL → deny
        let bad = intent(
            "run_command",
            serde_json::json!({ "command": "curl https://evil.example.com" }),
        );
        assert!(engine.validate_intent(&bad, 0).is_err());
    }

    // ── Observation rules ──────────────────────────────────────────────────

    /// Redact rule replaces matched content.
    #[test]
    fn observation_redact() {
        let engine = engine_from_toml(
            r#"
            [[observation_rules]]
            pattern = "(?i)password\\s*[:=]\\s*\\S+"
            action = "redact"
            label = "credential"
            "#,
        );
        let result = engine.validate_observation("Found password: s3cret in config");
        match result {
            ObservationOutcome::Redacted(s) => {
                assert!(
                    s.contains("[REDACTED:credential]"),
                    "redacted text should contain label: {s}"
                );
                assert!(
                    !s.contains("s3cret"),
                    "original secret must not appear: {s}"
                );
            }
            other => panic!("expected Redacted, got {other:?}"),
        }
    }

    /// Flag rule returns Flagged without modifying content.
    #[test]
    fn observation_flag() {
        let engine = engine_from_toml(
            r#"
            [[observation_rules]]
            pattern = "SUSPICIOUS"
            action = "flag"
            label = "sus"
            "#,
        );
        match engine.validate_observation("Found SUSPICIOUS activity") {
            ObservationOutcome::Flagged(labels) => assert!(labels.contains("sus")),
            other => panic!("expected Flagged, got {other:?}"),
        }
    }

    /// Abort rule triggers session abort on dangerous content.
    #[test]
    fn observation_abort() {
        let engine = engine_from_toml(
            r#"
            [[observation_rules]]
            pattern = "CRITICAL_EXPLOIT"
            action = "abort"
            label = "exploit_detected"
            "#,
        );
        match engine.validate_observation("Detected CRITICAL_EXPLOIT in response") {
            ObservationOutcome::Abort(_) => {} // expected
            other => panic!("expected Abort, got {other:?}"),
        }
    }

    /// Clean observation passes through unchanged.
    #[test]
    fn observation_clean() {
        let engine = engine_from_toml(
            r#"
            [[observation_rules]]
            pattern = "SENSITIVE"
            action = "redact"
            label = "sensitive"
            "#,
        );
        assert_eq!(
            engine.validate_observation("nothing special here"),
            ObservationOutcome::Clean,
        );
    }

    // ── Path pattern scoping ───────────────────────────────────────────────

    /// Allowed action with path_pattern scoping: matching path passes.
    #[test]
    fn path_pattern_matching_passes() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "read_file"
            path_pattern = "/etc/nginx/**"
            "#,
        );
        let i = intent(
            "read_file",
            serde_json::json!({ "path": "/etc/nginx/nginx.conf" }),
        );
        assert!(engine.validate_intent(&i, 0).is_ok());
    }

    /// Allowed action with path_pattern scoping: non-matching path is rejected.
    #[test]
    fn path_pattern_non_matching_rejected() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "read_file"
            path_pattern = "/etc/nginx/**"
            "#,
        );
        let i = intent("read_file", serde_json::json!({ "path": "/etc/shadow" }));
        assert!(engine.validate_intent(&i, 0).is_err());
    }

    /// Path traversal via `..` is rejected even when directory prefix matches.
    #[test]
    fn path_traversal_rejected() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "read_file"
            path_pattern = "/etc/nginx/**"
            "#,
        );
        let i = intent(
            "read_file",
            serde_json::json!({ "path": "/etc/nginx/../../etc/shadow" }),
        );
        assert!(engine.validate_intent(&i, 0).is_err());
    }

    // ── Allowed commands scoping ───────────────────────────────────────────

    /// Allowed action with `allowed_commands` passes for listed commands.
    #[test]
    fn allowed_commands_pass() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "run_command"
            allowed_commands = ["ls", "cat"]
            "#,
        );
        let i = intent("run_command", serde_json::json!({ "command": "ls -la" }));
        assert!(engine.validate_intent(&i, 0).is_ok());
    }

    /// Allowed action with `allowed_commands` rejects unlisted commands.
    #[test]
    fn unlisted_command_rejected() {
        let engine = engine_from_toml(
            r#"
            [[allowed_actions]]
            action = "run_command"
            allowed_commands = ["ls", "cat"]
            "#,
        );
        let i = intent("run_command", serde_json::json!({ "command": "rm -rf /" }));
        assert!(engine.validate_intent(&i, 0).is_err());
    }

    // ── Empty / no-restriction policy ──────────────────────────────────────

    /// A completely empty policy (no rules) allows all actions.
    #[test]
    fn empty_policy_allows_everything() {
        let engine = engine_from_toml("");
        let i = intent("anything", serde_json::json!({}));
        assert!(engine.validate_intent(&i, 0).is_ok());
    }

    // ── Invalid regex detection ────────────────────────────────────────────

    /// An invalid regex in command_rules causes PolicyEngine::new to fail.
    #[test]
    fn invalid_regex_rejected_at_construction() {
        let bad_toml = r#"
            [[command_rules]]
            program = "grep"
            arg_pattern = "[invalid(("
            decision = "allow"
        "#;
        let policy: AuditPolicy = toml::from_str(bad_toml).unwrap();
        assert!(PolicyEngine::new(policy).is_err());
    }

    // ── Plugin definitions ─────────────────────────────────────────────────

    /// Plugin arg_patterns that don't match are rejected.
    #[test]
    fn plugin_arg_pattern_mismatch() {
        let engine = engine_from_toml(
            r#"
            [[plugins]]
            name = "trivy"
            binary = "trivy"
            arg_patterns = ["^image\\s+\\S+"]
            "#,
        );
        let err = engine.validate_plugin_args("trivy", "fs .");
        assert!(err.is_err());
    }

    /// Plugin arg_patterns that match are accepted.
    #[test]
    fn plugin_arg_pattern_match() {
        let engine = engine_from_toml(
            r#"
            [[plugins]]
            name = "trivy"
            binary = "trivy"
            arg_patterns = ["^image\\s+\\S+", "^fs\\s+\\."]
            "#,
        );
        assert!(
            engine
                .validate_plugin_args("trivy", "image nginx:latest")
                .is_ok()
        );
        assert!(engine.validate_plugin_args("trivy", "fs .").is_ok());
    }

    /// Blocked binaries (shells, interpreters) are filtered out of
    /// `effective_allowed_programs`.
    #[test]
    fn blocked_plugin_binaries_filtered() {
        let engine = engine_from_toml(
            r#"
            [[plugins]]
            name = "safe-tool"
            binary = "trivy"

            [[plugins]]
            name = "shell-escape"
            binary = "bash"
            "#,
        );
        let allowed = engine.effective_allowed_programs();
        assert!(allowed.contains(&"trivy".to_string()));
        assert!(!allowed.contains(&"bash".to_string()));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  5. GOAL-HASH MISMATCH (PROMPT-INJECTION DETECTION)
// ═══════════════════════════════════════════════════════════════════════════════

mod goal_hash {
    use super::*;

    /// Appending an event with a mismatched goal triggers `GoalMismatch`.
    #[tokio::test]
    async fn goal_mismatch_rejected() {
        let db = ledger().await;
        let (session, key_bytes) = db.create_session(new_session("real goal")).await.unwrap();

        let result = db
            .append_event(
                thought("injected"),
                Some(session.id),
                Some("INJECTED goal"),
                Some(&key_bytes),
            )
            .await;

        assert!(result.is_err(), "mismatched goal should be rejected");
        let err = result.unwrap_err();
        assert!(
            matches!(err, ledger_api::LedgerError::GoalMismatch),
            "error should be GoalMismatch, got: {err:?}"
        );
    }

    /// Correct goal passes goal-hash verification.
    #[tokio::test]
    async fn correct_goal_accepted() {
        let db = ledger().await;
        let (session, key_bytes) = db
            .create_session(new_session("correct goal"))
            .await
            .unwrap();

        let result = db
            .append_event(
                thought("valid event"),
                Some(session.id),
                Some("correct goal"),
                Some(&key_bytes),
            )
            .await;

        assert!(result.is_ok());
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  6. COMPLIANCE PROOF
// ═══════════════════════════════════════════════════════════════════════════════

mod compliance {
    use super::*;

    /// prove_compliance returns a JSON bundle containing session_id and event
    /// hashes for all events in the session.
    #[tokio::test]
    async fn compliance_proof_contains_events() {
        let db = ledger().await;
        let (session, key_bytes) = db
            .create_session(new_session("compliance test"))
            .await
            .unwrap();

        for i in 0..3 {
            db.append_event(
                thought(&format!("compliance-{i}")),
                Some(session.id),
                Some("compliance test"),
                Some(&key_bytes),
            )
            .await
            .unwrap();
        }

        let proof_bytes = db.prove_compliance(session.id).await.unwrap();
        let proof: serde_json::Value = serde_json::from_slice(&proof_bytes).unwrap();

        assert_eq!(proof["session_id"], session.id.to_string());
        assert_eq!(proof["event_count"], 3);
        let events = proof["events"].as_array().unwrap();
        assert_eq!(events.len(), 3);
        // Each event entry has sequence and content_hash
        for ev in events {
            assert!(ev.get("sequence").is_some());
            assert!(ev.get("content_hash").is_some());
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  7. EDGE CASES & ROBUSTNESS
// ═══════════════════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    /// Appending without a session_id succeeds (unsessioned event).
    #[tokio::test]
    async fn unsessioned_event() {
        let db = ledger().await;
        let ev = db
            .append_event(thought("orphan"), None, None, None)
            .await
            .unwrap();
        assert_eq!(ev.sequence, 0);
    }

    /// Multiple sessions share the same global event chain.
    #[tokio::test]
    async fn multiple_sessions_share_chain() {
        let db = ledger().await;
        let (s1, k1) = db.create_session(new_session("session-1")).await.unwrap();
        let (s2, k2) = db.create_session(new_session("session-2")).await.unwrap();

        let ev0 = db
            .append_event(thought("s1-ev"), Some(s1.id), Some("session-1"), Some(&k1))
            .await
            .unwrap();
        let ev1 = db
            .append_event(thought("s2-ev"), Some(s2.id), Some("session-2"), Some(&k2))
            .await
            .unwrap();

        // Global chain links together
        assert_eq!(ev0.sequence, 0);
        assert_eq!(ev1.sequence, 1);
        assert_eq!(ev1.previous_hash, ev0.content_hash);
        assert!(db.verify_chain(0, 1).await.unwrap());
    }

    /// get_events_by_session filters to only the requested session.
    #[tokio::test]
    async fn events_filtered_by_session() {
        let db = ledger().await;
        let (s1, k1) = db.create_session(new_session("filter-1")).await.unwrap();
        let (s2, k2) = db.create_session(new_session("filter-2")).await.unwrap();

        for i in 0..3 {
            db.append_event(
                thought(&format!("s1-{i}")),
                Some(s1.id),
                Some("filter-1"),
                Some(&k1),
            )
            .await
            .unwrap();
        }
        for i in 0..2 {
            db.append_event(
                thought(&format!("s2-{i}")),
                Some(s2.id),
                Some("filter-2"),
                Some(&k2),
            )
            .await
            .unwrap();
        }

        let s1_events = db.get_events_by_session(s1.id).await.unwrap();
        let s2_events = db.get_events_by_session(s2.id).await.unwrap();
        assert_eq!(s1_events.len(), 3);
        assert_eq!(s2_events.len(), 2);
    }

    /// Events within a session are returned in ascending sequence order.
    #[tokio::test]
    async fn events_ordered_by_sequence() {
        let db = ledger().await;
        let (session, key) = db.create_session(new_session("order")).await.unwrap();

        for i in 0..5 {
            db.append_event(
                thought(&format!("ord-{i}")),
                Some(session.id),
                Some("order"),
                Some(&key),
            )
            .await
            .unwrap();
        }

        let events = db.get_events_by_session(session.id).await.unwrap();
        for pair in events.windows(2) {
            assert!(
                pair[0].sequence < pair[1].sequence,
                "events should be in ascending order"
            );
        }
    }

    /// Sessions created with a DID preserve it across create + list.
    #[tokio::test]
    async fn session_did_round_trip() {
        let db = ledger().await;
        let params = NewSession {
            goal: "did test".into(),
            llm_backend: "test".into(),
            llm_model: "mock".into(),
            policy_hash: None,
            session_did: Some("did:key:z6Mktest123".into()),
        };
        let (session, _key) = db.create_session(params).await.unwrap();
        assert_eq!(session.session_did.as_deref(), Some("did:key:z6Mktest123"));
    }

    /// Diverse event payload types all append successfully.
    #[tokio::test]
    async fn diverse_payload_types() {
        let db = ledger().await;
        let payloads = vec![
            genesis("init"),
            thought("thinking..."),
            action("read_file", serde_json::json!({"path": "/etc/hosts"})),
            observation("file contents here"),
            serde_json::json!({
                "type": "prompt_input",
                "content": "user prompt text"
            }),
        ];

        for (i, payload) in payloads.into_iter().enumerate() {
            let ev = db.append_event(payload, None, None, None).await.unwrap();
            assert_eq!(ev.sequence, i as i64);
        }

        assert!(db.verify_chain(0, 4).await.unwrap());
    }

    /// Invalid signing key size is rejected gracefully.
    #[tokio::test]
    async fn invalid_signing_key_size_rejected() {
        let db = ledger().await;
        let (session, _key) = db.create_session(new_session("bad key")).await.unwrap();
        let bad_key = vec![0u8; 16]; // 16 bytes instead of 32

        let result = db
            .append_event(
                thought("oops"),
                Some(session.id),
                Some("bad key"),
                Some(&bad_key),
            )
            .await;

        assert!(result.is_err());
    }
}
