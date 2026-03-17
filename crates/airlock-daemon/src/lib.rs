pub mod commands;
pub mod config;
pub mod hooks;
pub mod init;
pub mod logging;

use commands::CommandRegistry;
use hooks::{HookRunner, PostExecResult, PreExecResult};
use logging::{AuditLogger, LogEntry};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

pub fn validate_request(raw: &str) -> Result<(u64, ExecParams), ErrorResponse> {
    let request: Request = serde_json::from_str(raw.trim()).map_err(|e| ErrorResponse {
        jsonrpc: "2.0",
        id: 0,
        error: RpcError {
            code: -32700,
            message: format!("parse error: {e}"),
        },
    })?;

    let id = request.id.unwrap_or(0);

    if request.jsonrpc != "2.0" || request.method != "exec" {
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

    Ok((id, params))
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

    let output = Command::new("docker")
        .arg("inspect")
        .arg("--format")
        .arg("{{json .Mounts}}")
        .arg(container_id)
        .output()
        .await
        .ok()?;

    if !output.status.success() {
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
    params: &ExecParams,
    start: std::time::Instant,
    reason: String,
) {
    logger.log(&LogEntry {
        ts: logging::now_utc(),
        id,
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

pub async fn handle_connection(
    stream: tokio::net::UnixStream,
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

    let (mut id, mut params) = match validate_request(&line) {
        Ok(r) => r,
        Err(err) => {
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            return Ok(());
        }
    };

    let mut module = match registry.get(&params.command) {
        Some(m) => m,
        None => {
            let reason = format!("unknown command: {}", params.command);
            let err = build_error_response(id, -32601, reason.clone());
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            log_denied(&logger, id, &params, start, reason);
            return Ok(());
        }
    };

    if let Some(denied_arg) = module.check_deny(&params.args) {
        let reason = format!("denied arg: {}", denied_arg);
        let err = build_error_response(
            id,
            -32600,
            format!(
                "denied: arg '{}' not permitted for '{}'",
                denied_arg, params.command
            ),
        );
        writer
            .write_all(&send_line(&serde_json::to_string(&err)?))
            .await?;
        log_denied(&logger, id, &params, start, reason);
        return Ok(());
    }

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
            let (new_id, new_params) = match validate_request(&json) {
                Ok(r) => r,
                Err(err) => {
                    writer
                        .write_all(&send_line(&serde_json::to_string(&err)?))
                        .await?;
                    return Ok(());
                }
            };

            let new_module = match registry.get(&new_params.command) {
                Some(m) => m,
                None => {
                    let reason = format!("unknown command: {}", new_params.command);
                    let err = build_error_response(new_id, -32601, reason.clone());
                    writer
                        .write_all(&send_line(&serde_json::to_string(&err)?))
                        .await?;
                    log_denied(&logger, new_id, &new_params, start, reason);
                    return Ok(());
                }
            };

            if let Some(denied_arg) = new_module.check_deny(&new_params.args) {
                let reason = format!("denied arg: {}", denied_arg);
                let err = build_error_response(
                    new_id,
                    -32600,
                    format!(
                        "denied: arg '{}' not permitted for '{}'",
                        denied_arg, new_params.command
                    ),
                );
                writer
                    .write_all(&send_line(&serde_json::to_string(&err)?))
                    .await?;
                log_denied(&logger, new_id, &new_params, start, reason);
                return Ok(());
            }

            id = new_id;
            params = new_params;
            module = new_module;
        }
        PreExecResult::Rejected(msg) => {
            let err = build_error_response(id, -32600, msg.clone());
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            log_denied(
                &logger,
                id,
                &params,
                start,
                "pre-exec hook rejected".to_string(),
            );
            return Ok(());
        }
    }

    let host_cwd = match (&params.container_id, &params.cwd) {
        (Some(cid), Some(cwd)) => match resolve_host_cwd(cid, cwd, &mount_cache).await {
            Some(path) => path,
            None => {
                let reason = format!("cwd translation failed: could not inspect container {cid}");
                let err = build_error_response(id, -32603, reason.clone());
                writer
                    .write_all(&send_line(&serde_json::to_string(&err)?))
                    .await?;
                log_denied(&logger, id, &params, start, reason);
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
    if let Some(ref env_section) = module.env {
        if let Some(ref strip) = env_section.strip {
            for key in strip {
                cmd.env_remove(key);
            }
        }
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
            let msg = format!("failed to execute {}: {e}", module.command.bin);
            let err = build_error_response(id, -32603, msg.clone());
            writer
                .write_all(&send_line(&serde_json::to_string(&err)?))
                .await?;
            log_denied(&logger, id, &params, start, msg);
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

        let stdout_writer = writer.clone();
        let stdout_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
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
                                stream: "stdout",
                                data,
                            },
                        };
                        if let Ok(json) = serde_json::to_string(&notif) {
                            let mut w = stdout_writer.lock().await;
                            let _ = w.write_all(&send_line(&json)).await;
                            let _ = w.flush().await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let stderr_writer = writer.clone();
        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
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
                                stream: "stderr",
                                data,
                            },
                        };
                        if let Ok(json) = serde_json::to_string(&notif) {
                            let mut w = stderr_writer.lock().await;
                            let _ = w.write_all(&send_line(&json)).await;
                            let _ = w.flush().await;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

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

pub async fn run_daemon(
    listener: UnixListener,
    mount_cache: MountCache,
    registry: Arc<CommandRegistry>,
    cmd_locks: ConcurrencyLocks,
    hook_runner: Arc<HookRunner>,
    logger: Arc<AuditLogger>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };

        let cache = mount_cache.clone();
        let reg = registry.clone();
        let locks = cmd_locks.clone();
        let hooks = hook_runner.clone();
        let log = logger.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, cache, reg, locks, hooks, log).await {
                eprintln!("connection error: {e}");
            }
        });
    }
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
