// EctoLedger GUI — Tauri 2 Rust entry point.
//
// Self-contained desktop application: an embedded Axum server backed by
// SQLite starts automatically during the Tauri `setup` hook.  The Svelte
// front-end communicates via Tauri IPC commands that proxy to the local
// server (see `commands.rs`).
//
// The tauri.conf.json defines a placeholder window labelled
// "_bundler_placeholder" (visible: false, required for Windows WiX/NSIS
// bundling).  During setup we close it and create the real "main" window
// programmatically so we can inject a CSP with the ephemeral server port.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{Manager, WebviewUrl, WebviewWindowBuilder};

mod commands;
mod embedded;
mod setup;

fn main() {
    // Initialise tracing (logs go to stderr in debug, nowhere in release).
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,ectoledger=debug,ectoledger_gui=debug".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let handle = app.handle().clone();

            // Start the embedded Axum server asynchronously.
            // Tauri 2 runs setup on the async runtime, so we can block on
            // the future directly via `tauri::async_runtime::block_on`.
            let server = tauri::async_runtime::block_on(embedded::start(&handle))
                .map_err(|e| format!("Failed to start embedded server: {e}"))?;

            tracing::info!(
                port = server.port,
                "Embedded server ready — GUI will connect to http://127.0.0.1:{}",
                server.port
            );

            let port = server.port;

            // Store the server handle in Tauri managed state so commands can
            // read the port / token if needed in the future.
            app.manage(server);

            // The tauri.conf.json defines a placeholder window with label
            // "_bundler_placeholder" (visible: false) to satisfy the Windows
            // WiX/NSIS bundler.  Close it now — it is not needed at runtime.
            if let Some(placeholder) = app.get_webview_window("_bundler_placeholder") {
                let _ = placeholder.destroy();
            }

            WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                .title("EctoLedger")
                .inner_size(1400.0, 900.0)
                .min_inner_size(1024.0, 640.0)
                // NOTE: `transparent` is NOT set — windows are opaque by default in Tauri 2.
                // The tauri.conf.json "transparent": false ensures the bundler never
                // enables compositor transparency, preventing Linux/Windows DWM glitches.
                .center()
                .on_web_resource_request(move |_request: tauri::http::Request<Vec<u8>>, response: &mut tauri::http::Response<std::borrow::Cow<'static, [u8]>>| {
                    // Inject CSP on text/html responses (the Tauri entry
                    // document).  The browser then enforces this policy for
                    // all resources loaded by that document.
                    let is_html = response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .map(|ct| ct.contains("text/html"))
                        .unwrap_or(false);

                    if is_html {
                        let csp = format!(
                            "default-src 'self'; \
                             connect-src 'self' http://127.0.0.1:{port}; \
                             script-src 'self'; \
                             style-src 'self' 'unsafe-inline'; \
                             font-src 'self'; \
                             frame-src 'self' http://127.0.0.1:{port}; \
                             img-src 'self' data:",
                        );
                        if let Ok(val) = csp.parse() {
                            response
                                .headers_mut()
                                .insert("content-security-policy", val);
                        }
                    }
                })
                .build()
                .map_err(|e| format!("Failed to create main window: {e}"))?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_sessions,
            commands::get_session,
            commands::get_events,
            commands::run_prompt,
            commands::chat,
            commands::get_metrics,
            commands::get_prometheus_metrics,
            commands::export_certificate,
            commands::get_config,
            commands::save_config,
            commands::get_ollama_models,
            commands::get_tripwire_config,
            commands::save_tripwire_config,
            commands::get_policies,
            commands::get_policy_content,
            commands::save_policy,
            commands::delete_policy,
            commands::download_report,
            commands::server_url,
            commands::is_demo_mode,
            commands::reset_demo_data,
            commands::dashboard_url,
            commands::observer_token,
            commands::open_devtools,
            // Session VC
            commands::get_session_vc,
            commands::verify_session_vc,
            commands::get_pending_approval,
            commands::post_approval_decision,
            // Token management
            commands::get_tokens,
            commands::create_token,
            commands::delete_token,
            // Webhook management
            commands::get_webhooks,
            commands::create_webhook,
            commands::delete_webhook,
            commands::toggle_webhook,
            // First-launch wizard (Track 3)
            setup::detect_system_state,
            setup::check_setup_complete,
            setup::mark_setup_complete,
            setup::initialize_database,
            setup::install_ollama,
            setup::pull_model,
            // Developer Hub (server-side allowlisted shell commands)
            commands::run_shell_command,
            commands::run_shell_command_streaming,
        ])
        .run(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("Fatal: EctoLedger GUI failed to start: {e}");
            std::process::exit(1);
        });
}
