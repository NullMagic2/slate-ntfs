//! Module: ntfs_permissions::session
//! Purpose: Keep one administrator helper for the frontend session.
//! Created: 2026-10-01
//! Architecture: The GTK application starts the policy server through pkexec at launch;
//! requests share that process so authentication occurs once.

use ntfs_permissions::core;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

pub const HELPER: &str = "/usr/lib/slate-ntfs/slate-ntfs-policy";

struct Helper {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

#[derive(Default)]
pub struct RootSession {
    helper: Mutex<Option<Helper>>,
}

/// Why unlocking failed: an English interface text (translated when shown),
/// or a raw message from pkexec.
pub enum Refusal {
    Text(&'static str),
    Raw(String),
}

impl RootSession {
    pub fn active(&self) -> bool {
        if core::is_root() {
            return true;
        }
        let mut guard = self.helper.lock().unwrap();
        match guard.as_mut() {
            Some(helper) => matches!(helper.child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Blocking (run it off the main thread). None on success.
    pub fn start(&self) -> Option<Refusal> {
        if core::is_root() {
            return None;
        }
        let mut child = match Command::new("pkexec")
            .arg(HELPER)
            .arg("serve")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => return Some(Refusal::Text("The pkexec program is not installed.")),
        };
        let input = child.stdin.take().unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        let ready = output.read_line(&mut line).is_ok()
            && serde_json::from_str::<Value>(&line).ok().and_then(|v| v.get("ready")?.as_bool()) == Some(true);
        if ready {
            *self.helper.lock().unwrap() = Some(Helper { child, input, output });
            return None;
        }
        drop(input);
        let mut error = String::new();
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut error);
        }
        let status = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
        let lower = error.to_lowercase();
        Some(if status == 126 {
            Refusal::Text("Authentication was cancelled.")
        } else if lower.contains("no authentication agent") {
            Refusal::Text("No password dialog is available in this session.")
        } else if status == 127 || lower.contains("not authorized") {
            Refusal::Text("Authentication failed.")
        } else if error.trim().is_empty() {
            Refusal::Raw(format!("status {status}"))
        } else {
            Refusal::Raw(error.trim().to_owned())
        })
    }

    /// Blocking. Sends one request to the helper and returns its result.
    pub fn request(&self, message: &Value) -> Result<Value, String> {
        if core::is_root() {
            if message.get("cmd").and_then(Value::as_str) == Some("save") {
                if let Some(Value::Object(changes)) = message.get("changes") {
                    return Ok(ntfs_permissions::core::save_and_apply(
                        std::path::Path::new(ntfs_permissions::core::POLICY_DIR),
                        changes,
                    ));
                }
            }
            if message.get("cmd").and_then(Value::as_str) == Some("rename") {
                let uuid = message.get("uuid").and_then(Value::as_str).unwrap_or("");
                let label = message.get("label").and_then(Value::as_str).unwrap_or("");
                let result = ntfs_permissions::label::rename_drive(uuid, label);
                return Ok(json!({"status": result.status.name(), "message": result.message,
                    "detail": result.detail}));
            }
            return Err("unknown request".into());
        }
        let mut guard = self.helper.lock().unwrap();
        let helper = guard.as_mut().ok_or("administrator session ended")?;
        let ended = |e: std::io::Error| format!("administrator session ended ({e})");
        writeln!(helper.input, "{message}").map_err(ended)?;
        helper.input.flush().map_err(ended)?;
        let mut line = String::new();
        if helper.output.read_line(&mut line).map_err(ended)? == 0 {
            return Err("administrator session ended".into());
        }
        let reply: Value = serde_json::from_str(&line).map_err(|e| e.to_string())?;
        if reply.get("ok").and_then(Value::as_bool) != Some(true) {
            return Err(reply.get("error").and_then(Value::as_str).unwrap_or("request failed").to_owned());
        }
        Ok(reply.get("result").cloned().unwrap_or(json!(null)))
    }

    pub fn stop(&self) {
        if let Some(mut helper) = self.helper.lock().unwrap().take() {
            drop(helper.input); // the helper exits when its input closes
            let _ = helper.child.wait();
        }
    }
}
