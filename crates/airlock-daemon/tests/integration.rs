use airlock_daemon::commands::CommandRegistry;
use airlock_daemon::hooks::HookRunner;
use airlock_daemon::logging::AuditLogger;
use airlock_daemon::profile::Profile;
use airlock_daemon::{bind_profile_socket, run_daemon, ConcurrencyLocks, MountCache, ProfileMap};
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

fn default_profiles() -> ProfileMap {
    let mut map = HashMap::new();
    map.insert("default".to_string(), Profile::default());
    Arc::new(map)
}

async fn start_daemon(sock_path: &std::path::Path) -> tokio::task::JoinHandle<()> {
    start_daemon_with_hooks(sock_path, &unique_hooks_dir(), &unique_log_path()).await
}

async fn start_daemon_with_hooks(
    sock_path: &std::path::Path,
    hooks_dir: &std::path::Path,
    log_path: &std::path::Path,
) -> tokio::task::JoinHandle<()> {
    start_daemon_with_profile(sock_path, hooks_dir, log_path, default_profiles()).await
}

async fn start_daemon_with_profile(
    sock_path: &std::path::Path,
    hooks_dir: &std::path::Path,
    log_path: &std::path::Path,
    profiles: ProfileMap,
) -> tokio::task::JoinHandle<()> {
    let profile_name = profiles.keys().next().unwrap().clone();
    let listener = bind_profile_socket(sock_path).unwrap();
    let listeners = vec![(profile_name, listener)];
    let cache: MountCache = Arc::new(RwLock::new(HashMap::new()));
    let mut registry = CommandRegistry::new();
    registry.load_builtins();
    let registry = Arc::new(registry);
    let locks: ConcurrencyLocks = Arc::new(RwLock::new(HashMap::new()));
    let hook_runner = Arc::new(HookRunner::new(hooks_dir.to_path_buf()));
    let logger = Arc::new(AuditLogger::new(log_path.to_path_buf(), 50, 5));
    tokio::spawn(async move {
        run_daemon(
            listeners,
            profiles,
            cache,
            registry,
            locks,
            hook_runner,
            logger,
        )
        .await;
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
    async fn denies_long_flag_with_equals_value() {
        let sock = test_socket_path("deny-flag-equals");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["--config=evil","status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "flag=value should be denied");
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );
        assert!(
            message.contains("--config"),
            "error should name the flag, got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_short_flag_with_attached_value() {
        let sock = test_socket_path("deny-short-attached");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["-cevil","status"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            resp.error.is_some(),
            "short flag with attached value should be denied"
        );
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );
        assert!(
            message.contains("-c"),
            "error should name the flag, got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_docker_volume_root_mount() {
        let sock = test_socket_path("deny-volume-root");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"docker","args":["run","-v","/:/host","alpine"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "root volume mount should be denied");
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_docker_pid_host_split() {
        let sock = test_socket_path("deny-pid-host");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"docker","args":["run","--pid","host","alpine"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "--pid host (split) should be denied");
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_docker_pid_host_joined() {
        let sock = test_socket_path("deny-pid-host-joined");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"docker","args":["run","--pid=host","alpine"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "--pid=host (joined) should be denied");
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn denies_terraform_apply_auto_approve() {
        let sock = test_socket_path("deny-tf-auto-approve");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"terraform","args":["apply","-auto-approve"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            resp.error.is_some(),
            "terraform apply -auto-approve should be denied"
        );
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("denied"),
            "error should say 'denied', got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn allows_terraform_apply_alone() {
        let sock = test_socket_path("allow-tf-apply");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"terraform","args":["apply"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        // terraform may not be installed, so we just verify the request
        // was NOT denied by the deny rules (it should pass through to execution)
        for line in &lines {
            if let Ok(r) = serde_json::from_str::<AnyResponse>(line) {
                if let Some(err) = &r.error {
                    let msg = err["message"].as_str().unwrap_or("");
                    assert!(
                        !msg.contains("denied"),
                        "terraform apply alone should not be denied, got: {msg}"
                    );
                }
            }
        }

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn allows_docker_named_volume() {
        let sock = test_socket_path("allow-docker-named-vol");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"docker","args":["run","-v","mydata:/data","alpine"]}}"#;
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
            "docker named volume should be allowed"
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

    #[tokio::test]
    async fn profile_rejects_command_not_in_whitelist() {
        let sock = test_socket_path("profile-deny");
        let mut map = HashMap::new();
        map.insert(
            "restricted".to_string(),
            Profile::parse(r#"commands = ["git"]"#).unwrap(),
        );
        let profiles: ProfileMap = Arc::new(map);
        let _handle =
            start_daemon_with_profile(&sock, &unique_hooks_dir(), &unique_log_path(), profiles)
                .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"terraform","args":["plan"]}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(resp.error.is_some(), "unlisted command should be denied");
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("not permitted by profile"),
            "error should mention profile, got: {message}"
        );
        assert!(
            message.contains("restricted"),
            "error should name the profile, got: {message}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn cwd_translation_failure_returns_explicit_error() {
        let sock = test_socket_path("cwd-fail");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let request = r#"{"jsonrpc":"2.0","id":1,"method":"exec","params":{"command":"git","args":["status"],"cwd":"/workspace","container_id":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
        let lines = send_and_collect(&sock, request).await;

        let resp: AnyResponse = serde_json::from_str(&lines[0]).unwrap();
        assert!(
            resp.error.is_some(),
            "cwd translation failure should produce error"
        );
        assert!(resp.result.is_none());
        let message = resp.error.unwrap()["message"].as_str().unwrap().to_string();
        assert!(
            message.contains("cwd translation failed"),
            "error should mention cwd translation, got: {message}"
        );

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
    async fn socket_created_with_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let sock = test_socket_path("sock-perms");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let meta = std::fs::metadata(&sock).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket should be owner-only, got {mode:o}");

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
echo "$INPUT" | sed 's/commit/REDACTED/g'
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
            !stdout_data.contains("commit"),
            "original 'commit' should have been replaced, got: {stdout_data}"
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
        assert_eq!(entry["profile"], "default");
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

mod smoke_test_issue_22 {
    use super::*;

    struct Case {
        name: &'static str,
        command: &'static str,
        args: Vec<&'static str>,
        expect_denied: bool,
    }

    #[tokio::test]
    async fn all_issue_22_bypasses_are_blocked() {
        let cases = vec![
            // === Previously bypassed, now denied ===
            Case {
                name: "terraform apply -auto-approve (sequence)",
                command: "terraform",
                args: vec!["apply", "-auto-approve"],
                expect_denied: true,
            },
            Case {
                name: "docker -v /:/host (root volume mount, detached)",
                command: "docker",
                args: vec!["run", "-v", "/:/host", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker --volume=/etc:/mnt (root mount, equals form)",
                command: "docker",
                args: vec!["run", "--volume=/etc:/mnt", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker --pid host (flag split)",
                command: "docker",
                args: vec!["run", "--pid", "host", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker --pid=host (flag joined)",
                command: "docker",
                args: vec!["run", "--pid=host", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker --net=host (network namespace escape)",
                command: "docker",
                args: vec!["run", "--net=host", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker --cap-add=ALL (all capabilities)",
                command: "docker",
                args: vec!["run", "--cap-add=ALL", "alpine"],
                expect_denied: true,
            },
            Case {
                name: "docker -v docker.sock (socket mount)",
                command: "docker",
                args: vec![
                    "run",
                    "-v",
                    "/var/run/docker.sock:/var/run/docker.sock",
                    "alpine",
                ],
                expect_denied: true,
            },
            Case {
                name: "git --config=evil (flag=value bypass)",
                command: "git",
                args: vec!["--config=evil", "status"],
                expect_denied: true,
            },
            Case {
                name: "git -cevil (short flag attached value bypass)",
                command: "git",
                args: vec!["-cevil", "status"],
                expect_denied: true,
            },
            // === Must still be allowed ===
            Case {
                name: "terraform apply alone (no -auto-approve)",
                command: "terraform",
                args: vec!["apply"],
                expect_denied: false,
            },
            Case {
                name: "docker named volume (not root path)",
                command: "docker",
                args: vec!["run", "-v", "mydata:/data", "alpine"],
                expect_denied: false,
            },
            Case {
                name: "git status (benign command)",
                command: "git",
                args: vec!["status"],
                expect_denied: false,
            },
            Case {
                name: "git push origin main (benign flags)",
                command: "git",
                args: vec!["push", "origin", "main"],
                expect_denied: false,
            },
        ];

        let sock = test_socket_path("smoke-issue-22");
        let _handle = start_daemon(&sock).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let mut passed = 0;
        let mut failed = Vec::new();

        for case in &cases {
            let args_json: Vec<String> = case.args.iter().map(|a| format!("\"{}\"", a)).collect();
            let request = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"exec","params":{{"command":"{}","args":[{}]}}}}"#,
                case.command,
                args_json.join(",")
            );

            let lines = send_and_collect(&sock, &request).await;
            let got_denied = lines.iter().any(|line| {
                serde_json::from_str::<AnyResponse>(line)
                    .ok()
                    .and_then(|r| r.error)
                    .and_then(|e| e["message"].as_str().map(|m| m.contains("denied")))
                    .unwrap_or(false)
            });

            if got_denied == case.expect_denied {
                passed += 1;
                eprintln!("  PASS: {}", case.name);
            } else {
                let status = if got_denied { "DENIED" } else { "ALLOWED" };
                let expected = if case.expect_denied {
                    "DENIED"
                } else {
                    "ALLOWED"
                };
                failed.push(format!(
                    "  FAIL: {} — expected {}, got {}",
                    case.name, expected, status
                ));
            }
        }

        eprintln!("\n{}/{} cases passed", passed, cases.len());
        if !failed.is_empty() {
            for f in &failed {
                eprintln!("{}", f);
            }
            panic!("{} smoke test case(s) failed", failed.len());
        }

        let _ = std::fs::remove_file(&sock);
    }
}
