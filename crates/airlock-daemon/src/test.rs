use crate::commands::deny::NormalizedArg;
use crate::commands::module::PolicyMode;
use crate::commands::CommandRegistry;
use crate::profile::Profile;
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::Path;

pub enum StepResult {
    Ok(String),
    Denied(String),
    NotReached,
}

pub struct WhyResult {
    pub outcome: String,
    pub profile: String,
    pub command: String,
    pub args: Vec<String>,
    pub normalized: Option<Vec<NormalizedArg>>,
    pub steps: Vec<(&'static str, StepResult)>,
    pub policy_detail: Option<String>,
    pub hook_notice: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn evaluate(
    profile_name: &str,
    profile: &Profile,
    command: &str,
    args: &[String],
    enabled: &HashSet<String>,
    registry: &CommandRegistry,
    hooks_dir: &Path,
    agent_name: Option<&str>,
) -> WhyResult {
    let mut steps: Vec<(&str, StepResult)> = Vec::with_capacity(4);
    let mut normalized = None;
    let mut policy_detail = None;

    let build_result = |outcome: &str,
                        steps: Vec<(&'static str, StepResult)>,
                        normalized: Option<Vec<NormalizedArg>>,
                        policy_detail: Option<String>,
                        hook_notice: bool| WhyResult {
        outcome: outcome.to_string(),
        profile: profile_name.to_string(),
        command: command.to_string(),
        args: args.to_vec(),
        normalized,
        steps,
        policy_detail,
        hook_notice,
    };

    // Step 1: command enabled?
    if !enabled.contains(command) {
        steps.push((
            "command enabled",
            StepResult::Denied(format!("{command} is not in commands.enable")),
        ));
        steps.push(("module found", StepResult::NotReached));
        steps.push(("policy rules", StepResult::NotReached));
        steps.push(("profile check", StepResult::NotReached));
        return build_result(
            "DENIED -- command not enabled",
            steps,
            normalized,
            policy_detail,
            false,
        );
    }
    steps.push((
        "command enabled",
        StepResult::Ok(format!("{command} is in commands.enable")),
    ));

    // Step 2: module found (informational — always succeeds if step 1 passed)
    let module = registry.get_for_agent(command, agent_name).unwrap();
    let source = "built-in";
    steps.push((
        "module found",
        StepResult::Ok(format!("{command} ({source})")),
    ));

    // Step 3: policy rules
    let eval = module.check_policy_verbose(args);
    normalized = Some(eval.normalized);
    let step_label: &'static str = match eval.mode {
        PolicyMode::Allow => "allow rules",
        PolicyMode::Deny => "deny rules",
    };

    if eval.denied {
        let detail = match eval.mode {
            PolicyMode::Deny => format!("matched '{}'", eval.matched_rule.as_ref().unwrap()),
            PolicyMode::Allow => {
                format!("{} rules checked, none matched", eval.rules_checked)
            }
        };
        steps.push((step_label, StepResult::Denied(detail)));
        policy_detail = eval.matched_detail;
        steps.push(("profile check", StepResult::NotReached));
        let outcome = match eval.mode {
            PolicyMode::Deny => "DENIED by deny rule",
            PolicyMode::Allow => "DENIED by allow rule (not in allow list)",
        };
        return build_result(outcome, steps, normalized, policy_detail, false);
    }

    let ok_detail = match eval.mode {
        PolicyMode::Deny => format!("{} rules checked, 0 matched", eval.rules_checked),
        PolicyMode::Allow => {
            format!(
                "matched '{}' ({} rules)",
                eval.matched_rule.as_ref().unwrap(),
                eval.rules_checked
            )
        }
    };
    steps.push((step_label, StepResult::Ok(ok_detail)));

    // Step 4: profile allows?
    let outcome = if !profile.allows_command(command) {
        let allowed: Vec<&str> = profile.commands.iter().map(|s| s.as_str()).collect();
        steps.push((
            "profile check",
            StepResult::Denied(format!("{command} not in [{}]", allowed.join(", "))),
        ));
        "DENIED by profile"
    } else if profile.commands.is_empty() {
        steps.push((
            "profile check",
            StepResult::Ok("commands: [] (all allowed)".to_string()),
        ));
        "ALLOWED"
    } else {
        steps.push((
            "profile check",
            StepResult::Ok(format!("{command} in commands list")),
        ));
        "ALLOWED"
    };

    let hook_notice = hooks_dir.join("pre-exec").exists();
    build_result(outcome, steps, normalized, policy_detail, hook_notice)
}

fn format_normalized(normalized: &[NormalizedArg]) -> String {
    let parts: Vec<String> = normalized
        .iter()
        .map(|na| {
            let flag = match &na.flag {
                Some(f) => format!("flag={f:?}"),
                None => "flag=none".to_string(),
            };
            let role = format!("{:?}", na.role);
            format!("({:?}, {flag}, {role})", na.raw)
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

pub fn print_result(result: &WhyResult) {
    eprintln!("{}", result.outcome);
    eprintln!();
    eprintln!("  profile:    {}", result.profile);
    eprintln!("  command:    {}", result.command);

    let args_display: Vec<String> = result.args.iter().map(|a| format!("{a:?}")).collect();
    eprintln!("  args:       [{}]", args_display.join(", "));

    if let Some(ref norm) = result.normalized {
        eprintln!("  normalized: {}", format_normalized(norm));
    }

    eprintln!();
    for (i, (label, step)) in result.steps.iter().enumerate() {
        let num = i + 1;
        match step {
            StepResult::Ok(detail) => {
                eprintln!("  {num}. {label:<16} ok -- {detail}");
            }
            StepResult::Denied(detail) => {
                eprintln!("  {num}. {label:<16} DENIED -- {detail}");
            }
            StepResult::NotReached => {
                eprintln!("  {num}. {label:<16} (not reached)");
            }
        }
    }

    if let Some(ref detail) = result.policy_detail {
        eprintln!("     {detail}");
    }

    if result.hook_notice {
        eprintln!();
        eprintln!("  note: pre-exec hook configured but not evaluated");
    }
}

pub enum LiveResult {
    Agree(bool),
    Mismatch {
        static_says: String,
        daemon_says: String,
    },
    Skipped(String),
}

pub fn check_live(
    profile_name: &str,
    command: &str,
    args: &[String],
    sockets_dir: &Path,
    static_allowed: bool,
) -> LiveResult {
    let sock_path = sockets_dir.join(format!("{profile_name}.sock"));
    let stream = match std::os::unix::net::UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(_) => {
            return LiveResult::Skipped(format!("could not connect to {}", sock_path.display()));
        }
    };

    let args_json: Vec<String> = args.iter().map(|a| format!("{a:?}")).collect();
    let request = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"check","params":{{"command":"{command}","args":[{}]}}}}"#,
        args_json.join(",")
    );

    let mut writer = std::io::BufWriter::new(&stream);
    if writer.write_all(format!("{request}\n").as_bytes()).is_err() {
        return LiveResult::Skipped("failed to send request".to_string());
    }
    if writer.flush().is_err() {
        return LiveResult::Skipped("failed to flush request".to_string());
    }
    // Shut down write half so daemon knows we're done
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let reader = std::io::BufReader::new(&stream);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        // Look for the final response (has an "id" field)
        if parsed.get("id").is_none() {
            continue;
        }
        let daemon_allowed = parsed.get("result").is_some();
        if daemon_allowed == static_allowed {
            return LiveResult::Agree(!static_allowed);
        }
        let static_says = if static_allowed { "ALLOWED" } else { "DENIED" };
        let daemon_says = if daemon_allowed { "ALLOWED" } else { "DENIED" };
        return LiveResult::Mismatch {
            static_says: static_says.to_string(),
            daemon_says: daemon_says.to_string(),
        };
    }

    LiveResult::Skipped("no response from daemon".to_string())
}

pub fn print_live_result(result: &LiveResult) {
    match result {
        LiveResult::Agree(was_denied) => {
            if *was_denied {
                eprintln!("  live: ok -- daemon agrees (denied)");
            } else {
                eprintln!("  live: ok -- daemon agrees");
            }
        }
        LiveResult::Mismatch {
            static_says,
            daemon_says,
        } => {
            eprintln!("  live: MISMATCH -- static says {static_says}, daemon says {daemon_says}");
            eprintln!(
                "        (daemon may be running with different config -- restart to pick up changes)"
            );
        }
        LiveResult::Skipped(reason) => {
            eprintln!("  live: skipped -- {reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::CommandRegistry;
    use crate::profile::Profile;

    fn enabled_set(cmds: &[&str]) -> HashSet<String> {
        cmds.iter().map(|s| s.to_string()).collect()
    }

    fn make_registry(cmds: &[&str]) -> CommandRegistry {
        let mut reg = CommandRegistry::new();
        let enabled = enabled_set(cmds);
        reg.load_builtins_filtered(&enabled);
        reg
    }

    #[test]
    fn non_enabled_command_denied_at_step_1() {
        let enabled = enabled_set(&["git"]);
        let registry = make_registry(&["git"]);
        let profile = Profile {
            commands: vec![],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");

        let result = evaluate(
            "default",
            &profile,
            "kubectl",
            &[],
            &enabled,
            &registry,
            &hooks,
            None,
        );

        assert!(result.outcome.contains("DENIED"));
        assert!(matches!(result.steps[0].1, StepResult::Denied(_)));
        assert!(matches!(result.steps[1].1, StepResult::NotReached));
        assert!(matches!(result.steps[2].1, StepResult::NotReached));
        assert!(matches!(result.steps[3].1, StepResult::NotReached));
    }

    #[test]
    fn denied_by_deny_rule_at_step_3() {
        let enabled = enabled_set(&["git"]);
        let registry = make_registry(&["git"]);
        let profile = Profile {
            commands: vec![],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");
        let args: Vec<String> = vec!["-cevil".to_string(), "status".to_string()];

        let result = evaluate(
            "default", &profile, "git", &args, &enabled, &registry, &hooks, None,
        );

        assert!(result.outcome.contains("DENIED by deny rule"));
        assert!(matches!(result.steps[0].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[1].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[2].1, StepResult::Denied(_)));
        assert!(matches!(result.steps[3].1, StepResult::NotReached));
    }

    #[test]
    fn denied_by_profile_at_step_4() {
        let enabled = enabled_set(&["git"]);
        let registry = make_registry(&["git"]);
        let profile = Profile {
            commands: vec!["terraform".to_string()],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");
        let args: Vec<String> = vec!["status".to_string()];

        let result = evaluate(
            "agent-a", &profile, "git", &args, &enabled, &registry, &hooks, None,
        );

        assert!(result.outcome.contains("DENIED by profile"));
        assert!(matches!(result.steps[0].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[1].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[2].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[3].1, StepResult::Denied(_)));
    }

    #[test]
    fn allowed_passes_all_steps() {
        let enabled = enabled_set(&["git"]);
        let registry = make_registry(&["git"]);
        let profile = Profile {
            commands: vec![],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");
        let args: Vec<String> = vec!["push".to_string(), "origin".to_string()];

        let result = evaluate(
            "default", &profile, "git", &args, &enabled, &registry, &hooks, None,
        );

        assert_eq!(result.outcome, "ALLOWED");
        assert!(matches!(result.steps[0].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[1].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[2].1, StepResult::Ok(_)));
        assert!(matches!(result.steps[3].1, StepResult::Ok(_)));
    }

    #[test]
    fn allow_mode_denied_at_step_3() {
        let mut registry = CommandRegistry::new();
        registry
            .load_from_str(
                "aws",
                r#"
[command]
bin = "aws"

[allow]
args = ["s3", "sts"]
"#,
            )
            .unwrap();
        let enabled = enabled_set(&["aws"]);
        let profile = Profile {
            commands: vec![],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");
        let args: Vec<String> = vec!["iam".into(), "create-access-key".into()];

        let result = evaluate(
            "default", &profile, "aws", &args, &enabled, &registry, &hooks, None,
        );

        assert!(result.outcome.contains("DENIED"));
        assert!(result.outcome.contains("allow"));
        assert!(matches!(result.steps[2].1, StepResult::Denied(_)));
    }

    #[test]
    fn allow_mode_passes_step_3() {
        let mut registry = CommandRegistry::new();
        registry
            .load_from_str(
                "aws",
                r#"
[command]
bin = "aws"

[allow]
args = ["s3", "sts"]
"#,
            )
            .unwrap();
        let enabled = enabled_set(&["aws"]);
        let profile = Profile {
            commands: vec![],
            env: None,
        };
        let hooks = std::path::PathBuf::from("/nonexistent");
        let args: Vec<String> = vec!["s3".into(), "ls".into()];

        let result = evaluate(
            "default", &profile, "aws", &args, &enabled, &registry, &hooks, None,
        );

        assert_eq!(result.outcome, "ALLOWED");
        assert!(matches!(result.steps[2].1, StepResult::Ok(_)));
    }
}
