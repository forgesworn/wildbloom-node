//! Explicit debug-only stdio driver for the real native webview and lifecycle.
//! No socket, mock IPC, alternate daemon, or release-build entry point.
#[cfg(not(debug_assertions))]
compile_error!("native-acceptance must never be included in a release build");

use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use tauri::{AppHandle, Manager};

pub fn isolate(mut context: tauri::Context<tauri::Wry>) -> tauri::Context<tauri::Wry> {
    let id = std::env::var("WILDBLOOM_ACCEPTANCE_ID").expect("acceptance requires a disposable ID");
    assert!(id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()));
    context.config_mut().identifier = format!("dev.forgesworn.wildbloom-acceptance.{id}");
    context
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    op: String,
    #[serde(default)]
    script: String,
}

fn reply(id: u64, value: Value) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", json!({"id":id,"value":value})).ok();
    out.flush().ok();
}

pub fn ready() {
    reply(0, json!({"webview_ready": true}));
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || {
        let input = std::io::stdin();
        let mut input = input.lock();
        loop {
            // Bound each command before parsing or passing it to WebKit.
            let mut line = Vec::new();
            loop {
                let available = input.fill_buf().expect("acceptance stdin");
                if available.is_empty() {
                    app.exit(0);
                    return;
                }
                let count = available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |i| i + 1);
                if line.len() + count > 256 * 1024 {
                    app.exit(1);
                    return;
                }
                line.extend_from_slice(&available[..count]);
                input.consume(count);
                if line.last() == Some(&b'\n') {
                    break;
                }
            }
            let Ok(request) = serde_json::from_slice::<Request>(&line) else {
                app.exit(1);
                return;
            };
            let Some(window) = app.get_webview_window("main") else {
                app.exit(1);
                return;
            };
            match request.op.as_str() {
                "eval" => {
                    let id = request.id;
                    if window
                        .eval_with_callback(request.script, move |result| {
                            reply(id, serde_json::from_str(&result).unwrap_or(Value::Null));
                        })
                        .is_err()
                    {
                        reply(id, json!({"driver_error":"evaluation failed"}));
                    }
                }
                "close" => reply(request.id, json!({"ok":window.close().is_ok()})),
                "show" => reply(request.id, json!({"ok":window.show().is_ok()})),
                "status" => reply(
                    request.id,
                    json!({
                        "visible":window.is_visible().ok(),
                        "data_dir":app.path().app_local_data_dir().ok(),
                        "config_dir":app.path().app_config_dir().ok(),
                    }),
                ),
                "quit" => {
                    reply(request.id, json!({"ok":true}));
                    app.exit(0);
                    return;
                }
                _ => {
                    app.exit(1);
                    return;
                }
            }
        }
    });
}
