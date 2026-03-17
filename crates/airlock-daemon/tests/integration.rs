use airlock_daemon::commands::CommandRegistry;
use airlock_daemon::hooks::HookRunner;
use airlock_daemon::logging::AuditLogger;
use airlock_daemon::{run_daemon, ConcurrencyLocks, MountCache};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::RwLock;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_socket_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("airlock-test-{}-{}.sock", name, std::process::id()))
}

fn unique_hooks_dir() -> std::path::PathBuf {
    let id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("airlock-hooks-{}-{}", std::process::id(), id));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn unique_log_path() -> std::path::PathBuf {
    let dir = unique_hooks_dir();
    dir.join("airlock.log")
}

async fn start_daemon(sock_path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    start_daemon_with_hooks(sock_path, &unique_hooks_dir(), &unique_log_path()).await
}

async fn start_daemon_with_hooks(
    sock_path: &std::path::Path,
    hooks_dir: &std::path::Path,
    log_path: &std::path::Path,
) -> tokio::task::JoinHandle<()> {
    let _ = std::fs::remove_file(sock_path);
    let listener = tokio::net::UnixListener::bind(sock_path).unwrap();
    let cache: MountCache = Arc::new(RwLock::new(HashMap::new()));
    let mut registry = CommandRegistry::new();
    registry.load_builtins();
    let registry = Arc::new(registry);
    let locks: ConcurrencyLocks = Arc::new(RwLock::new(HashMap::new()));
    let hook_runner = Arc::new(HookRunner::new(hooks_dir.to_path_buf()));
    let logger = Arc::new(AuditLogger::new(log_path.to_path_buf(), 50, 5));
    tokio::spawn(async move {
        run_daemon(listener, cache, registry, locks, hook_runner, logger).await;
    })
}

async fn send_and_collect(sock_path: &std::path::Path, request_json: &str) -> Vec<String> {
    let mut stream = UnixStream::connect(sock_path).await.unwrap();
    stream
        .write_all(format!("{request_json}\n").as_bytes())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();

    let mut reader = BufReader::new(stream);
    let mut lines = Vec::new();
    let mut buf = String::new();
    while reader.read_line(&mut buf).await.unwrap() > 0 {
        lines.push(buf.trim().to_string());
        buf.clear();
    }
    lines
}

#[derive(Deserialize)]
struct AnyResponse {
    method: Option<String>,
    result: Option<serde_json::Value>,
    error: Option<serde_json::Value>,
    params: Option<serde_json::Value>,
}

fn write_hook(hooks_dir: &std::path::Path, name: &str, script: &str) {
    let path = hooks_dir.join(name);
    std::fs::write(&path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
}

mod trust_boundary {
    use super::*;

    #[tokio::test]
    async fn rejects_unknown_commands() {
        let sock = test_socket_path("reject-unknown");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"kubectl","args":["get","pods"]}}"#;
        let lines = send_and_collect(&sock, request).await;
        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some());
        assert!(resp.result.is_none());
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("kubectl"),
            "error should name the command, got: {message}"
        );

        let request =
            r#"{"jsonrpc":"2.0","id":2,"method":"exec","params":{"command":"","args":[]}}"#;
        let lines = send_and_collect(&sock, request).await;
        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some());

        let request = r#"{"jsonrpc":"2.0","id":3,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;
        let final_resp = lines.iter().find_map(|l| {
            let r: AnyResponse = serde_json::from_str(l).ok()?;
            if r.result.is_some() {
                Some(r)
            } else {
                None
            }
        });
        assert!(
            final_resp.is_some(),
            "git should be accepted and produce a result"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn args_are_never_interpreted_by_shell() {
        let sock = test_socket_path("shell-safety");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["$(whoami)","hello; rm -rf /","&&"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let mut stderr_data = String::new();
        for line in &lines {
            let resp: AnyResponse = serde_json::from_str(line).unwrap();
            if resp.method.as_deref() == Some("output") {
                if let Some(params) = &resp.params {
                    if params["stream"] == "stderr" {
                        stderr_data.push_str(params["data"].as_str().unwrap());
                    }
                }
            }
        }

        assert!(
            stderr_data.contains("$(whoami)") || stderr_data.contains("hello; rm -rf /"),
            "args should be passed literally, not shell-expanded. stderr: {stderr_data}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_forbidden_args() {
        let sock = test_socket_path("deny-args");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["push","--upload-pack","evil"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "denied arg should produce error");
        assert!(resp.result.is_none());
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );
        assert!(
            message.contains("--upload-pack"),
            "error should name the arg, got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn allows_args_not_in_deny_list() {
        let sock = test_socket_path("allow-args");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let final_resp = lines.iter().find_map(|l| {
            let r: AnyResponse = serde_json::from_str(l).ok()?;
            if r.result.is_some() {
                Some(r)
            } else {
                None
            }
        });
        assert!(
            final_resp.is_some(),
            "allowed args should produce a result, not a denial"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn pre_exec_hook_can_reject() {
        let hooks_dir = unique_hooks_dir();
        write_hook(
            &hooks_dir,
            "pre-exec",
            "#!/bin/bash\necho '{\"error\": \"not today\"}'\nexit 1\n",
        );

        let sock = test_socket_path("hook-reject");
        let _handle = start_daemon_with_hooks(&sock, &hooks_dir, &unique_log_path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            resp.error.is_some(),
            "pre-exec rejection should produce error"
        );
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("not today"),
            "error should contain hook message, got: {message}"
        );

        // No output notifications should exist (command never ran)
        let has_output = lines.iter().any(|l| {
            serde_json::from_str::<AnyResponse>(l)
                .ok()
                .and_then(|r| r.method)
                .as_deref()
                == Some("output")
        });
        assert!(!has_output, "command should not have executed");

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn pre_exec_hook_can_modify_request() {
        let hooks_dir = unique_hooks_dir();
        // Hook reads stdin, replaces args with ["status", "--short"], writes modified JSON
        write_hook(
            &hooks_dir,
            "pre-exec",
            r#"#!/bin/bash
INPUT=$(cat)
echo "$INPUT" | sed 's/"args":\[.*\]/"args":["status","--short"]/'
exit 0
"#,
        );

        let sock = test_socket_path("hook-modify");
        let _handle = start_daemon_with_hooks(&sock, &hooks_dir, &unique_log_path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        // Should succeed (git status --short is valid)
        let final_resp = lines.iter().find_map(|l| {
            let r: AnyResponse = serde_json::from_str(l).ok()?;
            if r.result.is_some() {
                Some(r)
            } else {
                None
            }
        });
        assert!(
            final_resp.is_some(),
            "modified request should still execute"
        );

        let _ = std::fs::remove_file(&sock);
    }
}

mod faithful_proxy {
    use super::*;

    #[tokio::test]
    async fn output_streams_before_final_response() {
        let sock = test_socket_path("streaming-order");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        assert!(
            lines.len() >= 2,
            "expected at least one notification + final response, got {} lines",
            lines.len()
        );

        let mut saw_notification = false;
        let mut saw_final = false;
        for line in &lines {
            let resp: AnyResponse = serde_json::from_str(line).unwrap();
            if resp.method.as_deref() == Some("output") {
                assert!(!saw_final, "notification arrived after final response");
                saw_notification = true;
            }
            if resp.result.is_some() {
                saw_final = true;
            }
        }

        assert!(
            saw_notification,
            "expected at least one output notification"
        );
        assert!(saw_final, "expected a final response with result");

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn airlock_errors_are_distinguishable_from_command_errors() {
        let sock = test_socket_path("error-distinguish");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let denied = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"kubectl","args":["get","pods"]}}"#;
        let lines = send_and_collect(&sock, denied).await;
        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            resp.error.is_some(),
            "airlock denial should be an error response"
        );
        assert!(
            resp.result.is_none(),
            "airlock denial should not have result"
        );

        let fail = r#"{"jsonrpc":"2.0","id":2,"method":"exec","params":{"command":"git","args":["status"],"cwd":"/tmp/airlock-nonexistent-dir-test"}}"#;
        let lines = send_and_collect(&sock, fail).await;

        let final_resp = lines
            .iter()
            .find_map(|l| {
                let r: AnyResponse = serde_json::from_str(l).ok()?;
                if r.result.is_some() || r.error.is_some() {
                    Some(r)
                } else {
                    None
                }
            })
            .expect("expected a final response");

        if let Some(result) = final_resp.result {
            let exit_code = result["exit_code"].as_i64().unwrap();
            assert_ne!(exit_code, 0, "git status in bad dir should fail");
        }
        if let Some(error) = final_resp.error {
            let code = error["code"].as_i64().unwrap();
            assert_ne!(
                code, -32601,
                "command failure should not use the 'unknown command' error code"
            );
        }

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn post_exec_hook_can_modify_output() {
        let hooks_dir = unique_hooks_dir();
        // Hook replaces all occurrences of "branch" with "REDACTED" in stdout
        write_hook(
            &hooks_dir,
            "post-exec",
            r#"#!/bin/bash
INPUT=$(cat)
echo "$INPUT" | sed 's/branch/REDACTED/g'
exit 0
"#,
        );

        let sock = test_socket_path("hook-postexec-modify");
        let _handle = start_daemon_with_hooks(&sock, &hooks_dir, &unique_log_path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let mut stdout_data = String::new();
        for line in &lines {
            if let Ok(resp) = serde_json::from_str::<AnyResponse>(line) {
                if resp.method.as_deref() == Some("output") {
                    if let Some(params) = &resp.params {
                        if params["stream"] == "stdout" {
                            stdout_data.push_str(params["data"].as_str().unwrap());
                        }
                    }
                }
            }
        }

        assert!(
            stdout_data.contains("REDACTED"),
            "post-exec hook should have modified output, got: {stdout_data}"
        );
        assert!(
            !stdout_data.contains("branch"),
            "original 'branch' should have been replaced, got: {stdout_data}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn post_exec_hook_failure_passes_through() {
        let hooks_dir = unique_hooks_dir();
        write_hook(&hooks_dir, "post-exec", "#!/bin/bash\nexit 1\n");

        let sock = test_socket_path("hook-postexec-fail");
        let _handle = start_daemon_with_hooks(&sock, &hooks_dir, &unique_log_path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        // Should still get a result (hook failure = passthrough)
        let final_resp = lines.iter().find_map(|l| {
            let r: AnyResponse = serde_json::from_str(l).ok()?;
            if r.result.is_some() {
                Some(r)
            } else {
                None
            }
        });
        assert!(
            final_resp.is_some(),
            "hook failure should not block the response"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn missing_hooks_are_skipped() {
        let hooks_dir = unique_hooks_dir();
        // Empty hooks dir — no pre-exec, no post-exec

        let sock = test_socket_path("no-hooks");
        let _handle = start_daemon_with_hooks(&sock, &hooks_dir, &unique_log_path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let final_resp = lines.iter().find_map(|l| {
            let r: AnyResponse = serde_json::from_str(l).ok()?;
            if r.result.is_some() {
                Some(r)
            } else {
                None
            }
        });
        assert!(final_resp.is_some(), "no hooks should not break execution");

        let _ = std::fs::remove_file(&sock);
    }
}

mod audit_log {
    use super::*;

    #[tokio::test]
    async fn logs_allowed_request() {
        let sock = test_socket_path("log-allowed");
        let log_path = unique_log_path();
        let _handle = start_daemon_with_hooks(&sock, &unique_hooks_dir(), &log_path).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"]}}"#;
        let _ = send_and_collect(&sock, request).await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(&log_path).expect("log file should exist");
        let last_line = content.lines().last().expect("log should have entries");
        let entry: serde_json::Value =
            serde_json::from_str(last_line).expect("log entry should be valid JSON");

        assert_eq!(entry["outcome"], "allowed");
        assert_eq!(entry["command"], "git");
        assert!(entry["exit_code"].is_number());
        assert!(entry["ts"].as_str().unwrap().ends_with('Z'));
        assert!(entry.get("reason").is_none());

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn logs_denied_request() {
        let sock = test_socket_path("log-denied");
        let log_path = unique_log_path();
        let _handle = start_daemon_with_hooks(&sock, &unique_hooks_dir(), &log_path).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"kubectl","args":["get","pods"],"cwd":"/workspace"}}"#;
        let _ = send_and_collect(&sock, request).await;

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let content = std::fs::read_to_string(&log_path).expect("log file should exist");
        let last_line = content.lines().last().expect("log should have entries");
        let entry: serde_json::Value =
            serde_json::from_str(last_line).expect("log entry should be valid JSON");

        assert_eq!(entry["outcome"], "denied");
        assert_eq!(entry["command"], "kubectl");
        assert!(entry["exit_code"].is_null());
        assert!(entry["reason"]
            .as_str()
            .unwrap()
            .contains("unknown command"));

        let _ = std::fs::remove_file(&sock);
    }
}
