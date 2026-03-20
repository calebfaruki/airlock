use crate::commands::CommandRegistry;
use std::process::Command;

pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

pub struct CheckResult {
    pub status: CheckStatus,
    pub label: String,
    pub detail: String,
}

fn resolve_binary(bin: &str) -> Option<String> {
    let output = Command::new("which").arg(bin).output().ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

pub fn check_commands(registry: &CommandRegistry) -> Vec<CheckResult> {
    let mut results = Vec::new();
    for name in registry.command_names() {
        let module = registry.get(name).unwrap();
        let bin = &module.command.bin;
        match resolve_binary(bin) {
            Some(path) => results.push(CheckResult {
                status: CheckStatus::Ok,
                label: name.to_string(),
                detail: path,
            }),
            None => results.push(CheckResult {
                status: CheckStatus::Fail,
                label: name.to_string(),
                detail: format!("{bin} not found on PATH"),
            }),
        }
    }
    results
}

pub fn check_docker() -> Vec<CheckResult> {
    let mut results = Vec::new();

    let docker_path = match resolve_binary("docker") {
        Some(path) => {
            results.push(CheckResult {
                status: CheckStatus::Ok,
                label: "docker".to_string(),
                detail: path,
            });
            true
        }
        None => {
            results.push(CheckResult {
                status: CheckStatus::Warn,
                label: "docker".to_string(),
                detail: "not found on PATH — CWD mapping will not work".to_string(),
            });
            return results;
        }
    };

    if docker_path {
        match Command::new("docker").arg("info").output() {
            Ok(output) if output.status.success() => {
                results.push(CheckResult {
                    status: CheckStatus::Ok,
                    label: "daemon".to_string(),
                    detail: "docker daemon running".to_string(),
                });

                if cfg!(target_os = "macos") {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    if stdout.contains("Docker Desktop") {
                        results.push(CheckResult {
                            status: CheckStatus::Warn,
                            label: "desktop".to_string(),
                            detail: "Docker Desktop on macOS — containers need --group-add 0 for socket access".to_string(),
                        });
                    }
                }
            }
            _ => {
                results.push(CheckResult {
                    status: CheckStatus::Warn,
                    label: "daemon".to_string(),
                    detail: "docker daemon not running".to_string(),
                });
            }
        }
    }

    results
}

pub fn print_results(category: &str, results: &[CheckResult]) {
    eprintln!("{category}");
    for r in results {
        let marker = match r.status {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "fail",
        };
        eprintln!("  {marker:<6} {:<10} {}", r.label, r.detail);
    }
}

pub fn has_failures(results: &[CheckResult]) -> bool {
    results
        .iter()
        .any(|r| matches!(r.status, CheckStatus::Fail))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_known_binary() {
        let path = resolve_binary("sh");
        assert!(path.is_some());
        assert!(path.unwrap().contains("sh"));
    }

    #[test]
    fn reports_missing_binary() {
        let path = resolve_binary("nonexistent-binary-xyz-999");
        assert!(path.is_none());
    }

    #[test]
    fn has_failures_detects_fail() {
        let results = vec![
            CheckResult {
                status: CheckStatus::Ok,
                label: "a".into(),
                detail: "ok".into(),
            },
            CheckResult {
                status: CheckStatus::Fail,
                label: "b".into(),
                detail: "bad".into(),
            },
        ];
        assert!(has_failures(&results));
    }

    #[test]
    fn has_failures_false_without_fail() {
        let results = vec![
            CheckResult {
                status: CheckStatus::Ok,
                label: "a".into(),
                detail: "ok".into(),
            },
            CheckResult {
                status: CheckStatus::Warn,
                label: "b".into(),
                detail: "meh".into(),
            },
        ];
        assert!(!has_failures(&results));
    }
}
