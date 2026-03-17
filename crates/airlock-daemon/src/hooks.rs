use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

pub struct HookRunner {
    hooks_dir: PathBuf,
}

pub enum PreExecResult {
    Proceed,
    Modified(String),
    Rejected(String),
}

pub enum PostExecResult {
    Passthrough,
    Modified(String),
}

impl HookRunner {
    pub fn new(hooks_dir: PathBuf) -> Self {
        Self { hooks_dir }
    }

    pub fn has_post_exec(&self) -> bool {
        is_executable(&self.hooks_dir.join("post-exec"))
    }

    pub async fn run_pre_exec(&self, request_json: &str) -> PreExecResult {
        let path = self.hooks_dir.join("pre-exec");

        if !path.exists() {
            return PreExecResult::Proceed;
        }

        if !is_executable(&path) {
            eprintln!(
                "airlock: warning — pre-exec hook at {} is not executable, skipping",
                path.display()
            );
            return PreExecResult::Proceed;
        }

        match run_hook(&path, request_json).await {
            HookOutput::Success { stdout } if stdout.trim().is_empty() => PreExecResult::Proceed,
            HookOutput::Success { stdout } => PreExecResult::Modified(stdout),
            HookOutput::Failed { stdout } => {
                let msg = extract_error_message(&stdout)
                    .unwrap_or_else(|| "airlock: pre-exec hook rejected request".to_string());
                PreExecResult::Rejected(msg)
            }
            HookOutput::Timeout => {
                eprintln!("airlock: pre-exec hook timed out");
                PreExecResult::Rejected("airlock: pre-exec hook timed out".to_string())
            }
            HookOutput::SpawnError(e) => {
                eprintln!("airlock: pre-exec hook error: {e}");
                PreExecResult::Proceed
            }
        }
    }

    pub async fn run_post_exec(&self, response_json: &str) -> PostExecResult {
        let path = self.hooks_dir.join("post-exec");

        if !path.exists() {
            return PostExecResult::Passthrough;
        }

        if !is_executable(&path) {
            eprintln!(
                "airlock: warning — post-exec hook at {} is not executable, skipping",
                path.display()
            );
            return PostExecResult::Passthrough;
        }

        match run_hook(&path, response_json).await {
            HookOutput::Success { stdout } if stdout.trim().is_empty() => {
                PostExecResult::Passthrough
            }
            HookOutput::Success { stdout } => PostExecResult::Modified(stdout),
            HookOutput::Failed { .. } => PostExecResult::Passthrough,
            HookOutput::Timeout => {
                eprintln!("airlock: post-exec hook timed out, passing through original response");
                PostExecResult::Passthrough
            }
            HookOutput::SpawnError(e) => {
                eprintln!("airlock: post-exec hook error: {e}");
                PostExecResult::Passthrough
            }
        }
    }
}

enum HookOutput {
    Success { stdout: String },
    Failed { stdout: String },
    Timeout,
    SpawnError(String),
}

fn is_executable(path: &std::path::Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

fn hook_env() -> Vec<(String, String)> {
    let mut env = Vec::new();
    if let Ok(v) = std::env::var("PATH") {
        env.push(("PATH".to_string(), v));
    }
    if let Ok(v) = std::env::var("HOME") {
        env.push(("HOME".to_string(), v));
    }
    if let Ok(v) = std::env::var("USER") {
        env.push(("USER".to_string(), v));
    }
    env
}

async fn run_hook(path: &std::path::Path, input: &str) -> HookOutput {
    let mut child = match Command::new(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .env_clear()
        .envs(hook_env())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return HookOutput::SpawnError(format!("failed to spawn hook: {e}")),
    };

    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
        drop(stdin);
    }

    // Read stdout manually so we can still kill on timeout
    let mut stdout_handle = child.stdout.take().unwrap();
    let mut stdout_buf = Vec::new();

    let wait_result = tokio::time::timeout(HOOK_TIMEOUT, async {
        let _ = stdout_handle.read_to_end(&mut stdout_buf).await;
        child.wait().await
    })
    .await;

    match wait_result {
        Ok(Ok(status)) => {
            let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
            if status.success() {
                HookOutput::Success { stdout }
            } else {
                HookOutput::Failed { stdout }
            }
        }
        Ok(Err(e)) => HookOutput::SpawnError(format!("hook execution failed: {e}")),
        Err(_) => HookOutput::Timeout,
    }
}

fn extract_error_message(stdout: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    value.get("error")?.as_str().map(|s| s.to_string())
}
