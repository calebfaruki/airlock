use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExecuteError {
    #[error("command failed: {0}")]
    CommandFailed(#[from] std::io::Error),
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

    #[test]
    fn execve_semicolon_is_literal() {
        let argv = shell_words::split("git push; cat /etc/passwd").unwrap();
        assert_eq!(argv, ["git", "push;", "cat", "/etc/passwd"]);
    }

    #[test]
    fn execve_ampersand_is_literal() {
        let argv = shell_words::split("git push && cat /secrets").unwrap();
        assert_eq!(argv, ["git", "push", "&&", "cat", "/secrets"]);
    }

    #[test]
    fn execve_pipe_is_literal() {
        let argv = shell_words::split("git log | grep secret").unwrap();
        assert_eq!(argv, ["git", "log", "|", "grep", "secret"]);
    }

    #[test]
    fn execve_redirect_is_literal() {
        let argv = shell_words::split("echo secret > /workspace/leak").unwrap();
        assert_eq!(argv, ["echo", "secret", ">", "/workspace/leak"]);
    }

    #[test]
    fn execve_backtick_is_literal() {
        let argv = shell_words::split("git commit -m `cat /secrets/key`").unwrap();
        assert_eq!(argv, ["git", "commit", "-m", "`cat", "/secrets/key`"]);
    }

    #[test]
    fn execve_dollar_expansion_is_literal() {
        let argv = shell_words::split("git commit -m $(cat /secrets/key)").unwrap();
        assert_eq!(argv, ["git", "commit", "-m", "$(cat", "/secrets/key)"]);
    }

    #[test]
    fn execve_quoted_string_preserved() {
        let argv = shell_words::split(r#"git commit -m "fix: the bug""#).unwrap();
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
        let result = execute_command_execve("echo hello; echo pwned", "/tmp")
            .await
            .unwrap();
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
