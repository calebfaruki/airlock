pub mod commands;
pub mod config;
pub mod doctor;
pub mod hooks;
pub mod init;
pub mod logging;
pub mod profile;
pub mod test;

use commands::{CommandModule, CommandRegistry};
use hooks::{HookRunner, PostExecResult, PreExecResult};
use logging::{AuditLogger, LogEntry};
use profile::Profile;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::process::Command;
use tokio::sync::RwLock;

#[derive(Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub method: String,
    pub params: Option<ExecParams>,
}

#[derive(Deserialize)]
pub struct ExecParams {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<String>,
    pub container_id: Option<String>,
}

#[derive(Serialize)]
pub struct SuccessResponse {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub result: ExecResult,
}

#[derive(Serialize)]
pub struct ExecResult {
    pub exit_code: i32,
}

#[derive(Serialize, Debug)]
pub struct ErrorResponse {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub error: RpcError,
}

#[derive(Serialize, Debug)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

#[derive(Serialize)]
pub struct Notification {
    pub jsonrpc: &'static str,
    pub method: &'static str,
    pub params: OutputParams,
}

#[derive(Serialize)]
pub struct OutputParams {
    pub stream: &'static str,
    pub data: String,
}

#[derive(Deserialize, Clone)]
pub struct DockerMount {
    #[serde(rename = "Type")]
    pub _type: Option<String>,
    #[serde(rename = "Source")]
    pub source: String,
    #[serde(rename = "Destination")]
    pub destination: String,
}

pub type MountCache = Arc<RwLock<HashMap<String, Vec<DockerMount>>>>;
pub type ConcurrencyLocks = Arc<RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>;
pub type ProfileMap = Arc<HashMap<String, Profile>>;

fn is_path_prefix(prefix: &str, path: &str) -> bool {
    if path == prefix {
        return true;
    }
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/')
}

pub fn translate_path(mounts: &[DockerMount], container_cwd: &str) -> Option<String> {
    let mut best_match: Option<&DockerMount> = None;
    let mut best_len: Option<usize> = None;

    for mount in mounts {
        if is_path_prefix(&mount.destination, container_cwd) {
            let len = mount
                .destination
                .strip_suffix('/')
                .unwrap_or(&mount.destination)
                .len();
            if best_len.is_none() || len > best_len.unwrap() {
                best_len = Some(len);
                best_match = Some(mount);
            }
        }
    }

    best_match.map(|m| {
        let dest = m.destination.strip_suffix('/').unwrap_or(&m.destination);
        let suffix = &container_cwd[dest.len()..];
        let source = m.source.strip_suffix('/').unwrap_or(&m.source);
        format!("{source}{suffix}")
    })
}

pub fn validate_request(raw: &str) -> Result<(u64, String, ExecParams), ErrorResponse> {
    let request: Request = serde_json::from_str(raw.trim()).map_err(|e| ErrorResponse {
        jsonrpc: "2.0",
        id: 0,
        error: RpcError {
            code: -32700,
            message: format!("parse error: {e}"),
        },
    })?;

    let id = request.id.unwrap_or(0);

    if request.jsonrpc != "2.0" || (request.method != "exec" && request.method != "check") {
        return Err(ErrorResponse {
            jsonrpc: "2.0",
            id,
            error: RpcError {
                code: -32600,
                message: "invalid request".to_string(),
            },
        });
    }

    let params = request.params.ok_or_else(|| ErrorResponse {
        jsonrpc: "2.0",
        id,
        error: RpcError {
            code: -32600,
            message: "missing params".to_string(),
        },
    })?;

    Ok((id, request.method, params))
}

pub fn build_error_response(id: u64, code: i32, message: String) -> ErrorResponse {
    ErrorResponse {
        jsonrpc: "2.0",
        id,
        error: RpcError { code, message },
    }
}

pub fn build_success_response(id: u64, exit_code: i32) -> SuccessResponse {
    SuccessResponse {
        jsonrpc: "2.0",
        id,
        result: ExecResult { exit_code },
    }
}

fn send_line(line: &str) -> Vec<u8> {
    let mut buf = line.as_bytes().to_vec();
    buf.push(b'\n');
    buf
}

async fn resolve_host_cwd(
    container_id: &str,
    container_cwd: &str,
    cache: &MountCache,
) -> Option<String> {
    {
        let c = cache.read().await;
        if let Some(mounts) = c.get(container_id) {
            return translate_path(mounts, container_cwd);
        }
    }

    let output = match Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{json .Mounts}}")
        .arg(container_id)
        .output()
        .await
    {
        Ok(output) => output,
        Err(_) => {
            eprintln!("airlock: docker not found — the daemon's PATH may not include docker's install location");
            return None;
        }
    };

    if !output.status.success() {
        eprintln!("airlock: docker inspect failed for container {container_id} — is docker in the daemon's PATH?");
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mounts: Vec<DockerMount> = serde_json::from_str(stdout.trim()).ok()?;

    let result = translate_path(&mounts, container_cwd);

    {
        let mut c = cache.write().await;
        c.insert(container_id.to_string(), mounts);
    }

    result
}

fn log_denied(
    logger: &AuditLogger,
    id: u64,
    profile: &str,
    params: &ExecParams,
    start: std::time::Instant,
    reason: String,
) {
    logger.log(&LogEntry {
        ts: logging::now_utc(),
        id,
        profile: profile.to_string(),
        event: "exec".to_string(),
        command: params.command.clone(),
        args: params.args.clone(),
        cwd: params.cwd.clone().unwrap_or_default(),
        exit_code: None,
        duration_ms: start.elapsed().as_millis() as u64,
        outcome: "denied".to_string(),
        reason: Some(reason),
    });
}

#[allow(clippy::too_many_arguments)]
async fn deny_request(
    writer: &mut (impl AsyncWriteExt + Unpin),
    logger: &AuditLogger,
    id: u64,
    profile_name: &str,
    params: &ExecParams,
    start: std::time::Instant,
    code: i32,
    reason: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let err = build_error_response(id, code, reason.clone());
    writer
        .write_all(&send_line(&serde_json::to_string(&err)?))
        .await?;
    log_denied(logger, id, profile_name, params, start, reason);
    Ok(())
}

fn spawn_stream_forwarder(
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    stream_name: &'static str,
    writer: Arc<tokio::sync::Mutex<impl AsyncWriteExt + Unpin + Send + 'static>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::with_capacity(4096);
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf).await {
                Ok(0) => break,
                Ok(_) => {
                    let data = String::from_utf8_lossy(&buf).to_string();
                    let notif = Notification {
                        jsonrpc: "2.0",
                        method: "output",
                        params: OutputParams {
                            stream: stream_name,
                            data,
                        },
                    };
                    if let Ok(json) = serde_json::to_string(&notif) {
                        let mut w = writer.lock().await;
                        let _ = w.write_all(&send_line(&json)).await;
                        let _ = w.flush().await;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

pub enum EvalDecision<'a> {
    Allowed(&'a CommandModule),
    Denied { code: i32, reason: String },
}

pub fn evaluate_request<'a>(
    params: &ExecParams,
    profile: &Profile,
    profile_name: &str,
    registry: &'a CommandRegistry,
) -> EvalDecision<'a> {
    let module = match registry.get(&params.command) {
        Some(m) => m,
        None => {
            return EvalDecision::Denied {
                code: -32601,
                reason: format!("unknown command: {}", params.command),
            };
        }
    };

    if let Some(reason) = module.check_policy(&params.args) {
        return EvalDecision::Denied {
            code: -32600,
            reason: format!("{} for '{}'", reason, params.command),
        };
    }

    if !profile.allows_command(&params.command) {
        return EvalDecision::Denied {
            code: -32600,
            reason: format!(
                "command '{}' not permitted by profile '{}'",
                params.command, profile_name
            ),
        };
    }

    EvalDecision::Allowed(module)
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_connection(
    stream: tokio::net::UnixStream,
    profile_name: String,
    profiles: ProfileMap,
    mount_cache: MountCache,
    registry: Arc<CommandRegistry>,
    cmd_locks: ConcurrencyLocks,
    hook_runner: Arc<HookRunner>,
    logger: Arc<AuditLogger>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = std::time::Instant::now();
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);

    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let (mut id, method, mut params) = match validate_request(&line) {
        Ok(r) => r,
        Err(err) => {
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            return Ok(());
        }
    };

    let profile = profiles
        .get(&profile_name)
        .expect("profile must exist in map");

    // Handle check method: evaluate without execution, hooks, or logging
    if method == "check" {
        match evaluate_request(&params, profile, &profile_name, &registry) {
            EvalDecision::Allowed(_) => {
                let resp = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "decision": "allowed" }
                });
                writer.write_all(&send_line(&resp.to_string())).await?;
            }
            EvalDecision::Denied { code, reason } => {
                let resp = build_error_response(id, code, reason);
                writer
                    .write_all(&send_line(&serde_json::to_string(&resp)?))
                    .await?;
            }
        }
        return Ok(());
    }

    // Exec path: evaluate, then continue to hooks and execution
    let mut module = match evaluate_request(&params, profile, &profile_name, &registry) {
        EvalDecision::Allowed(m) => m,
        EvalDecision::Denied { code, reason } => {
            deny_request(
                &mut writer,
                &logger,
                id,
                &profile_name,
                &params,
                start,
                code,
                reason,
            )
            .await?;
            return Ok(());
        }
    };

    // Pre-exec hook
    let request_value = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "exec",
        "params": {
            "command": params.command,
            "args": params.args,
            "cwd": params.cwd,
            "container_id": params.container_id,
        }
    });
    let request_json = serde_json::to_string(&request_value)?;

    match hook_runner.run_pre_exec(&request_json).await {
        PreExecResult::Proceed => {}
        PreExecResult::Modified(json) => {
            let (new_id, _method, new_params) = match validate_request(&json) {
                Ok(r) => r,
                Err(err) => {
                    writer
                        .write_all(&send_line(&serde_json::to_string(&err)?))
                        .await?;
                    return Ok(());
                }
            };

            let new_module = match evaluate_request(&new_params, profile, &profile_name, &registry)
            {
                EvalDecision::Allowed(m) => m,
                EvalDecision::Denied { code, reason } => {
                    deny_request(
                        &mut writer,
                        &logger,
                        new_id,
                        &profile_name,
                        &new_params,
                        start,
                        code,
                        reason,
                    )
                    .await?;
                    return Ok(());
                }
            };

            id = new_id;
            params = new_params;
            module = new_module;
        }
        PreExecResult::Rejected(msg) => {
            deny_request(
                &mut writer,
                &logger,
                id,
                &profile_name,
                &params,
                start,
                -32600,
                msg,
            )
            .await?;
            return Ok(());
        }
    }

    let host_cwd = match (&params.container_id, &params.cwd) {
        (Some(cid), Some(cwd)) => match resolve_host_cwd(cid, cwd, &mount_cache).await {
            Some(path) => path,
            None => {
                let reason = format!("cwd translation failed: docker inspect failed for container {cid} — is docker in the daemon's PATH?");
                deny_request(
                    &mut writer,
                    &logger,
                    id,
                    &profile_name,
                    &params,
                    start,
                    -32603,
                    reason,
                )
                .await?;
                return Ok(());
            }
        },
        (None, Some(cwd)) => cwd.clone(),
        (_, None) => ".".to_string(),
    };

    // Acquire per-command lock if not concurrent
    let _lock_guard = if !module.is_concurrent() {
        let lock = {
            let mut locks = cmd_locks.write().await;
            locks
                .entry(params.command.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        Some(lock.lock_owned().await)
    } else {
        None
    };

    let mut cmd = Command::new(&module.command.bin);
    cmd.args(&params.args);
    if let Some(ref args_section) = module.args {
        cmd.args(&args_section.append);
    }
    cmd.current_dir(&host_cwd);
    // Three-layer env merge: strip → profile → command hardening
    if let Some(ref env_section) = module.env {
        if let Some(ref strip) = env_section.strip {
            for key in strip {
                cmd.env_remove(key);
            }
        }
    }
    if let Some(ref profile_env) = profile.env {
        if let Some(ref set) = profile_env.set {
            for (key, val) in set {
                cmd.env(key, val);
            }
        }
    }
    if let Some(ref env_section) = module.env {
        if let Some(ref set) = env_section.set {
            for (key, val) in set {
                cmd.env(key, val);
            }
        }
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let msg = if e.kind() == std::io::ErrorKind::NotFound
                && !module.command.bin.contains('/')
            {
                format!(
                    "failed to execute {}: {e} (hint: use an absolute path in the command module, e.g. bin = \"/opt/homebrew/bin/{}\")",
                    module.command.bin, module.command.bin
                )
            } else {
                format!("failed to execute {}: {e}", module.command.bin)
            };
            let err = build_error_response(id, -32603, msg.clone());
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            log_denied(&logger, id, &profile_name, &params, start, msg);
            return Ok(());
        }
    };

    let has_post_exec = hook_runner.has_post_exec();
    let exit_code;

    if has_post_exec {
        let mut stdout_handle = child.stdout.take().unwrap();
        let mut stderr_handle = child.stderr.take().unwrap();

        let mut stdout_buf = String::new();
        let mut stderr_buf = String::new();
        let _ = stdout_handle.read_to_string(&mut stdout_buf).await;
        let _ = stderr_handle.read_to_string(&mut stderr_buf).await;

        let status = child.wait().await?;
        exit_code = status.code().unwrap_or(1);

        let response_value = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "exit_code": exit_code,
                "stdout": stdout_buf,
                "stderr": stderr_buf,
            }
        });
        let response_json = serde_json::to_string(&response_value)?;

        let (final_stdout, final_stderr, final_exit_code) =
            match hook_runner.run_post_exec(&response_json).await {
                PostExecResult::Passthrough => (stdout_buf, stderr_buf, exit_code),
                PostExecResult::Modified(json) => {
                    match serde_json::from_str::<serde_json::Value>(&json) {
                        Ok(v) => {
                            let r = v.get("result").cloned().unwrap_or(serde_json::json!({}));
                            let out = r
                                .get("stdout")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string();
                            let err = r
                                .get("stderr")
                                .and_then(|s| s.as_str())
                                .unwrap_or("")
                                .to_string();
                            let code =
                                r.get("exit_code").and_then(|c| c.as_i64()).unwrap_or(1) as i32;
                            (out, err, code)
                        }
                        Err(_) => (stdout_buf, stderr_buf, exit_code),
                    }
                }
            };

        if !final_stdout.is_empty() {
            let notif = Notification {
                jsonrpc: "2.0",
                method: "output",
                params: OutputParams {
                    stream: "stdout",
                    data: final_stdout,
                },
            };
            writer
                .write_all(&send_line(&serde_json::to_string(&notif)?))
                .await?;
        }
        if !final_stderr.is_empty() {
            let notif = Notification {
                jsonrpc: "2.0",
                method: "output",
                params: OutputParams {
                    stream: "stderr",
                    data: final_stderr,
                },
            };
            writer
                .write_all(&send_line(&serde_json::to_string(&notif)?))
                .await?;
        }

        let resp = build_success_response(id, final_exit_code);
        writer
            .write_all(&send_line(&serde_json::to_string(&resp)?))
            .await?;
        writer.flush().await?;
    } else {
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let writer = Arc::new(tokio::sync::Mutex::new(writer));

        let stdout_task = spawn_stream_forwarder(stdout, "stdout", writer.clone());
        let stderr_task = spawn_stream_forwarder(stderr, "stderr", writer.clone());

        let _ = tokio::join!(stdout_task, stderr_task);
        let status = child.wait().await?;
        exit_code = status.code().unwrap_or(1);

        let resp = build_success_response(id, exit_code);
        let mut w = writer.lock().await;
        w.write_all(&send_line(&serde_json::to_string(&resp)?))
            .await?;
        w.flush().await?;
    }

    logger.log(&LogEntry {
        ts: logging::now_utc(),
        id,
        profile: profile_name,
        event: "exec".to_string(),
        command: params.command.clone(),
        args: params.args.clone(),
        cwd: params.cwd.clone().unwrap_or_default(),
        exit_code: Some(exit_code),
        duration_ms: start.elapsed().as_millis() as u64,
        outcome: "allowed".to_string(),
        reason: None,
    });

    Ok(())
}

pub fn bind_profile_socket(path: &Path) -> Result<UnixListener, Box<dyn std::error::Error>> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub async fn run_daemon(
    listeners: Vec<(String, UnixListener)>,
    profiles: ProfileMap,
    mount_cache: MountCache,
    registry: Arc<CommandRegistry>,
    cmd_locks: ConcurrencyLocks,
    hook_runner: Arc<HookRunner>,
    logger: Arc<AuditLogger>,
) {
    for (profile_name, listener) in listeners {
        let name = profile_name;
        let profs = profiles.clone();
        let cache = mount_cache.clone();
        let reg = registry.clone();
        let locks = cmd_locks.clone();
        let hooks = hook_runner.clone();
        let log = logger.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        eprintln!("accept error: {e}");
                        continue;
                    }
                };

                let n = name.clone();
                let p = profs.clone();
                let c = cache.clone();
                let r = reg.clone();
                let l = locks.clone();
                let h = hooks.clone();
                let lg = log.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, n, p, c, r, l, h, lg).await {
                        eprintln!("connection error: {e}");
                    }
                });
            }
        });
    }
    std::future::pending::<()>().await;
}

#[cfg(test)]
mod container_awareness {
    use super::*;

    fn mount(source: &str, destination: &str) -> DockerMount {
        DockerMount {
            _type: None,
            source: source.to_string(),
            destination: destination.to_string(),
        }
    }

    #[test]
    fn container_cwd_translated_to_host_path() {
        let mounts = vec![mount("/home/caleb/myapp", "/workspace")];

        // Exact mount match
        assert_eq!(
            translate_path(&mounts, "/workspace"),
            Some("/home/caleb/myapp".to_string())
        );

        // Subdirectory translation
        assert_eq!(
            translate_path(&mounts, "/workspace/src/lib"),
            Some("/home/caleb/myapp/src/lib".to_string())
        );

        // Different mount
        let data_mounts = vec![mount("/mnt/datasets", "/data")];
        assert_eq!(
            translate_path(&data_mounts, "/data/files"),
            Some("/mnt/datasets/files".to_string())
        );

        // Longest prefix wins
        let multi = vec![
            mount("/home/caleb/myapp", "/workspace"),
            mount("/mnt/deep", "/workspace/deep"),
        ];
        assert_eq!(
            translate_path(&multi, "/workspace/deep/path"),
            Some("/mnt/deep/path".to_string())
        );

        // No matching mount returns None
        assert_eq!(translate_path(&mounts, "/unmapped/path"), None);

        // Must match on path boundary — /workspacefoo must NOT match /workspace
        assert_eq!(translate_path(&mounts, "/workspacefoo"), None);
    }
}
