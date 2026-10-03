//! Module: ntfs_permissions::slate_ntfs_policy
//! Purpose: Serve privileged drive-policy, mount-option and label requests.
//! Created: 2026-10-01
//! Architecture: The GTK session sends line-delimited JSON to this root helper. options
//! supplies mount policy; save persists and applies changes; serve handles
//! session requests. Defaults allow only the mounting user. Environment
//! settings are never trusted because pkexec runs this process as root.

use ntfs_permissions::core;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;

const USAGE: &str = "usage: slate-ntfs-policy options DEVICE UID GID | save | serve";

fn reply(out: &mut impl Write, message: &Value) -> std::io::Result<()> {
    writeln!(out, "{message}")?;
    out.flush()
}

fn serve() -> i32 {
    let dir = Path::new(core::POLICY_DIR);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if reply(&mut out, &json!({"ready": true})).is_err() {
        return 1;
    }
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let answer = match serde_json::from_str::<Value>(&line) {
            Ok(request) => match (request.get("cmd").and_then(Value::as_str), request.get("changes")) {
                (Some("save"), Some(Value::Object(changes))) => {
                    json!({"ok": true, "result": core::save_and_apply(dir, changes)})
                }
                (Some("ping"), _) => json!({"ok": true, "result": "pong"}),
                (Some("rename"), _) => {
                    match (request.get("uuid").and_then(Value::as_str), request.get("label").and_then(Value::as_str)) {
                        (Some(uuid), Some(label)) => {
                            let result = ntfs_permissions::label::rename_drive(uuid, label);
                            json!({"ok": true, "result": {"status": result.status.name(),
                            "message": result.message, "detail": result.detail}})
                        }
                        _ => json!({"ok": false, "error": "rename needs uuid and label"}),
                    }
                }
                _ => json!({"ok": false, "error": "unknown request"}),
            },
            Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
        };
        if reply(&mut out, &answer).is_err() {
            break;
        }
    }
    0
}

fn run(args: &[String]) -> Result<i32, String> {
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["options", device, uid, gid] => {
            let uid: u32 = uid.parse().map_err(|_| "UID and GID must be numbers")?;
            let gid: u32 = gid.parse().map_err(|_| "UID and GID must be numbers")?;
            let policy = match core::device_uuid(device) {
                Some(uuid) => core::read_policy(Path::new(core::POLICY_DIR), &uuid)?.unwrap_or_default(),
                None => core::Policy::default(),
            };
            println!("{}", core::mount_options(&policy, uid, Some(gid))?);
            Ok(0)
        }
        ["save"] => {
            if !core::is_root() {
                return Err("save requires administrator rights".into());
            }
            let changes: Value = serde_json::from_reader(std::io::stdin()).map_err(|e| e.to_string())?;
            let Value::Object(changes) = changes else {
                return Err("expected a JSON object".into());
            };
            println!("{}", core::save_and_apply(Path::new(core::POLICY_DIR), &changes));
            Ok(0)
        }
        ["serve"] => {
            if !core::is_root() {
                return Err("serve requires administrator rights".into());
            }
            Ok(serve())
        }
        _ => {
            eprintln!("{USAGE}");
            Ok(64)
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("slate-ntfs-policy: {error}");
            std::process::exit(1);
        }
    }
}
