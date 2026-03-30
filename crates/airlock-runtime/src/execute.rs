use std::collections::HashMap;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExecuteError {
    #[error("missing parameter: {0}")]
    MissingParam(String),

    #[error("parameter '{key}' contains forbidden character '{ch}'")]
    ForbiddenChar { key: String, ch: char },

    #[error("command failed: {0}")]
    CommandFailed(#[from] std::io::Error),
}

const FORBIDDEN_CHARS: &[char] = &[';', '|', '&', '`', '$', '(', ')', '>', '<'];

/// Validate that a parameter value contains no shell metacharacters.
pub fn validate_param_value(key: &str, value: &str) -> Result<(), ExecuteError> {
    for ch in FORBIDDEN_CHARS {
        if value.contains(*ch) {
            return Err(ExecuteError::ForbiddenChar {
                key: key.to_string(),
                ch: *ch,
            });
        }
    }
    Ok(())
}

/// Replace `{param_name}` placeholders in a command template with values from params.
pub fn interpolate(
    template: &str,
    params: &HashMap<String, String>,
) -> Result<String, ExecuteError> {
    let mut result = template.to_string();
    let mut pos = 0;

    while let Some(open) = result[pos..].find('{') {
        let open = pos + open;
        if let Some(close) = result[open..].find('}') {
            let close = open + close;
            let key = &result[open + 1..close];
            let value = params
                .get(key)
                .ok_or_else(|| ExecuteError::MissingParam(key.to_string()))?;
            validate_param_value(key, value)?;
            result.replace_range(open..=close, value);
            pos = open + value.len();
        } else {
            break;
        }
    }

    Ok(result)
}

pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl From<std::process::Output> for CommandResult {
    fn from(output: std::process::Output) -> Self {
        Self {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }
}

/// Execute an interpolated command string via `sh -c`.
pub async fn execute_command(
    command: &str,
    working_dir: &str,
) -> Result<CommandResult, ExecuteError> {
    let output = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(working_dir)
        .output()
        .await?;

    Ok(output.into())
}

/// Execute a command string via execve (no shell). The command is parsed into
/// an argv array using shell-words (shlex-style lexing without shell execution).
/// Shell metacharacters become literal arguments.
pub async fn execute_command_execve(
    command: &str,
    working_dir: &str,
) -> Result<CommandResult, ExecuteError> {
    let argv = shell_words::split(command).map_err(|e| {
        ExecuteError::CommandFailed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            e.to_string(),
        ))
    })?;

    if argv.is_empty() {
        return Err(ExecuteError::CommandFailed(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty command",
        )));
    }

    let output = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .current_dir(working_dir)
        .output()
        .await?;

    Ok(output.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn interpolate_basic() {
        let result = interpolate(
            "git push {remote} {branch}",
            &params(&[("remote", "origin"), ("branch", "main")]),
        )
        .unwrap();
        assert_eq!(result, "git push origin main");
    }

    #[test]
    fn interpolate_single_param() {
        let result = interpolate(
            "git checkout -b {branch}",
            &params(&[("branch", "feature")]),
        )
        .unwrap();
        assert_eq!(result, "git checkout -b feature");
    }

    #[test]
    fn interpolate_no_params() {
        let result = interpolate("git status", &params(&[])).unwrap();
        assert_eq!(result, "git status");
    }

    #[test]
    fn interpolate_missing_param() {
        let err = interpolate(
            "git push {remote} {branch}",
            &params(&[("remote", "origin")]),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::MissingParam(ref k) if k == "branch"));
    }

    #[test]
    fn validate_rejects_semicolon() {
        let err = validate_param_value("branch", "main; rm -rf /").unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: ';', .. }));
    }

    #[test]
    fn validate_rejects_pipe() {
        let err = validate_param_value("arg", "foo | bar").unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: '|', .. }));
    }

    #[test]
    fn validate_rejects_ampersand() {
        let err = validate_param_value("arg", "foo && bar").unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: '&', .. }));
    }

    #[test]
    fn validate_rejects_backtick() {
        let err = validate_param_value("arg", "`whoami`").unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: '`', .. }));
    }

    #[test]
    fn validate_rejects_dollar() {
        let err = validate_param_value("arg", "$(whoami)").unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: '$', .. }));
    }

    #[test]
    fn validate_rejects_parens() {
        assert!(validate_param_value("arg", "foo(bar)").is_err());
    }

    #[test]
    fn validate_rejects_redirect() {
        assert!(validate_param_value("arg", "foo > /etc/passwd").is_err());
        assert!(validate_param_value("arg", "foo < /dev/null").is_err());
    }

    #[test]
    fn validate_allows_safe_values() {
        assert!(validate_param_value("branch", "main").is_ok());
        assert!(validate_param_value("branch", "feature/my-branch").is_ok());
        assert!(validate_param_value("remote", "origin").is_ok());
        assert!(validate_param_value("message", "fix: update the thing").is_ok());
        assert!(validate_param_value("path", "/workspace/src/lib.rs").is_ok());
        assert!(validate_param_value("url", "https://github.com/user/repo.git").is_ok());
    }

    #[test]
    fn interpolate_rejects_forbidden_in_value() {
        let err = interpolate(
            "git push {remote} {branch}",
            &params(&[("remote", "origin"), ("branch", "main; echo pwned")]),
        )
        .unwrap_err();
        assert!(matches!(err, ExecuteError::ForbiddenChar { ch: ';', .. }));
    }

    #[test]
    fn interpolate_empty_template() {
        let result = interpolate("", &params(&[])).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn interpolate_adjacent_placeholders() {
        let result = interpolate("{a}{b}", &params(&[("a", "hello"), ("b", "world")])).unwrap();
        assert_eq!(result, "helloworld");
    }

    #[test]
    fn interpolate_duplicate_placeholder() {
        let result = interpolate("{x} and {x}", &params(&[("x", "val")])).unwrap();
        assert_eq!(result, "val and val");
    }

    #[test]
    fn interpolate_empty_param_value() {
        let result = interpolate("cmd {arg}", &params(&[("arg", "")])).unwrap();
        assert_eq!(result, "cmd ");
    }

    #[test]
    fn interpolate_extra_params_ignored() {
        let result = interpolate("echo hello", &params(&[("unused", "value")])).unwrap();
        assert_eq!(result, "echo hello");
    }

    #[test]
    fn interpolate_unmatched_open_brace() {
        let result = interpolate("echo {unclosed", &params(&[])).unwrap();
        assert_eq!(result, "echo {unclosed");
    }

    #[test]
    fn interpolate_placeholder_at_start() {
        let result = interpolate("{cmd} --flag", &params(&[("cmd", "ls")])).unwrap();
        assert_eq!(result, "ls --flag");
    }

    #[test]
    fn interpolate_placeholder_at_end() {
        let result = interpolate("echo {msg}", &params(&[("msg", "hi")])).unwrap();
        assert_eq!(result, "echo hi");
    }

    #[test]
    fn validate_all_forbidden_chars_individually() {
        for &ch in FORBIDDEN_CHARS {
            let val = format!("before{ch}after");
            let err = validate_param_value("test", &val).unwrap_err();
            assert!(
                matches!(err, ExecuteError::ForbiddenChar { ch: got, .. } if got == ch),
                "expected ForbiddenChar for '{ch}'"
            );
        }
    }

    #[test]
    fn validate_empty_value_allowed() {
        assert!(validate_param_value("key", "").is_ok());
    }

    #[tokio::test]
    async fn execute_nonexistent_working_dir() {
        let result = execute_command("echo hi", "/nonexistent/path/that/does/not/exist").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execute_command_not_found() {
        let result = execute_command("command_that_does_not_exist_xyz", "/tmp")
            .await
            .unwrap();
        assert_ne!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn execute_echo() {
        let result = execute_command("echo hello", "/tmp").await.unwrap();
        assert_eq!(result.stdout.trim(), "hello");
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn execute_exit_code() {
        let result = execute_command("exit 42", "/tmp").await.unwrap();
        assert_eq!(result.exit_code, 42);
    }

    #[tokio::test]
    async fn execute_stderr() {
        let result = execute_command("echo err >&2", "/tmp").await.unwrap();
        assert_eq!(result.stderr.trim(), "err");
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn execute_killed_by_signal_returns_negative() {
        // kill -9 $$ sends SIGKILL to the shell itself — no exit code, code() returns None
        let result = execute_command("kill -9 $$", "/tmp").await.unwrap();
        assert_eq!(result.exit_code, -1);
    }

    // --- execve adversarial tests ---

    fn split(cmd: &str) -> Vec<String> {
        shell_words::split(cmd).unwrap()
    }

    #[test]
    fn execve_semicolon_is_literal() {
        let argv = split("git push; cat /etc/passwd");
        assert_eq!(argv, ["git", "push;", "cat", "/etc/passwd"]);
    }

    #[test]
    fn execve_ampersand_is_literal() {
        let argv = split("git push && cat /secrets");
        assert_eq!(argv, ["git", "push", "&&", "cat", "/secrets"]);
    }

    #[test]
    fn execve_pipe_is_literal() {
        let argv = split("git log | grep secret");
        assert_eq!(argv, ["git", "log", "|", "grep", "secret"]);
    }

    #[test]
    fn execve_redirect_is_literal() {
        let argv = split("echo secret > /workspace/leak");
        assert_eq!(argv, ["echo", "secret", ">", "/workspace/leak"]);
    }

    #[test]
    fn execve_backtick_is_literal() {
        let argv = split("git commit -m `cat /secrets/key`");
        assert_eq!(argv, ["git", "commit", "-m", "`cat", "/secrets/key`"]);
    }

    #[test]
    fn execve_dollar_expansion_is_literal() {
        let argv = split("git commit -m $(cat /secrets/key)");
        assert_eq!(argv, ["git", "commit", "-m", "$(cat", "/secrets/key)"]);
    }

    #[test]
    fn execve_quoted_string_preserved() {
        let argv = split(r#"git commit -m "fix: the bug""#);
        assert_eq!(argv, ["git", "commit", "-m", "fix: the bug"]);
    }

    #[test]
    fn execve_empty_command_rejected() {
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(execute_command_execve("", "/tmp"));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn execve_echo_no_shell() {
        let result = execute_command_execve("echo hello", "/tmp").await.unwrap();
        assert_eq!(result.stdout.trim(), "hello");
        assert_eq!(result.exit_code, 0);
    }

    #[tokio::test]
    async fn execve_semicolon_not_executed() {
        // With sh -c this would run two commands. With execve, echo gets
        // "hello;" as a literal argument — the semicolon is not a separator.
        let result = execute_command_execve("echo hello; echo pwned", "/tmp")
            .await
            .unwrap();
        // All args printed on one line: "hello; echo pwned"
        let line = result.stdout.trim();
        assert!(
            line.contains("hello;"),
            "semicolon should be literal in arg"
        );
        assert_eq!(
            result.stdout.lines().count(),
            1,
            "should be one command, not two"
        );
    }

    #[tokio::test]
    async fn execve_pipe_not_executed() {
        // With sh -c, pipe would send echo output to cat. With execve,
        // echo gets "|" and "cat" as literal args.
        let result = execute_command_execve("echo secret | cat", "/tmp")
            .await
            .unwrap();
        let line = result.stdout.trim();
        assert!(line.contains("|"), "pipe should be literal");
        assert!(
            line.contains("cat"),
            "cat should be a literal arg, not a separate process"
        );
        assert_eq!(result.stdout.lines().count(), 1);
    }
}
