use serde::Deserialize;
use std::collections::HashMap;

use super::deny::{normalize_args, parse_rule_entry, NormalizedArg, Rule};

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum PolicyMode {
    Allow,
    #[default]
    Deny,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandModule {
    pub command: CommandSection,
    pub deny: Option<DenySection>,
    pub allow: Option<AllowSection>,
    pub env: Option<EnvSection>,
    pub args: Option<ArgsSection>,
    pub exec: Option<ExecSection>,
    #[serde(skip)]
    rules: Vec<Rule>,
    #[serde(skip)]
    policy_mode: PolicyMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSection {
    pub bin: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenySection {
    pub args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowSection {
    pub args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSection {
    pub strip: Option<Vec<String>>,
    pub set: Option<HashMap<String, String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArgsSection {
    pub append: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecSection {
    pub concurrent: Option<bool>,
}

impl CommandModule {
    pub fn parse(toml_str: &str) -> Result<Self, String> {
        let mut module: Self =
            toml::from_str(toml_str).map_err(|e| format!("failed to parse command module: {e}"))?;

        let (rules_source, policy_mode) = match (&module.allow, &module.deny) {
            (Some(_), Some(_)) => {
                return Err(
                    "module has both [allow] and [deny] sections; only one is permitted".into(),
                );
            }
            (None, None) => {
                return Err("module must have an [allow] or [deny] section".into());
            }
            (Some(a), None) => (&a.args, PolicyMode::Allow),
            (None, Some(d)) => (&d.args, PolicyMode::Deny),
        };

        module.rules = rules_source
            .iter()
            .map(|a| parse_rule_entry(a))
            .collect::<Result<Vec<_>, _>>()?;
        module.policy_mode = policy_mode;
        Ok(module)
    }

    pub fn policy_mode(&self) -> PolicyMode {
        self.policy_mode
    }

    pub fn is_concurrent(&self) -> bool {
        self.exec
            .as_ref()
            .and_then(|e| e.concurrent)
            .unwrap_or(true)
    }

    /// Returns Some(reason) if the command should be denied, None if permitted.
    pub fn check_policy(&self, args: &[String]) -> Option<String> {
        let normalized = normalize_args(args);
        match self.policy_mode {
            PolicyMode::Deny => {
                for rule in &self.rules {
                    if let Some(reason) = rule.matches(&normalized) {
                        return Some(format!("denied by deny rule: '{reason}'"));
                    }
                }
                None
            }
            PolicyMode::Allow => {
                for rule in &self.rules {
                    if rule.matches(&normalized).is_some() {
                        return None;
                    }
                }
                Some("not in allow list".into())
            }
        }
    }

    pub fn check_policy_verbose(&self, args: &[String]) -> PolicyEvaluation {
        let normalized = normalize_args(args);
        let rules_checked = self.rules.len();
        let mut matched_rule = None;
        let mut matched_detail = None;

        for rule in &self.rules {
            if let Some(reason) = rule.matches(&normalized) {
                for na in &normalized {
                    if let Some(ref flag) = na.flag {
                        if reason.contains(flag) {
                            matched_detail = Some(format!(
                                "arg {:?} role={:?}, flag={:?}, value={:?}",
                                na.raw,
                                na.role,
                                flag,
                                na.value.as_deref().unwrap_or("(none)")
                            ));
                            break;
                        }
                    }
                    if reason == na.raw {
                        matched_detail = Some(format!(
                            "arg {:?} role={:?}, matched as literal",
                            na.raw, na.role
                        ));
                        break;
                    }
                }
                matched_rule = Some(reason);
                break;
            }
        }

        let denied = match self.policy_mode {
            PolicyMode::Deny => matched_rule.is_some(),
            PolicyMode::Allow => matched_rule.is_none(),
        };

        PolicyEvaluation {
            mode: self.policy_mode,
            rules_checked,
            matched_rule,
            matched_detail,
            denied,
            normalized,
        }
    }
}

pub struct PolicyEvaluation {
    pub mode: PolicyMode,
    pub rules_checked: usize,
    pub matched_rule: Option<String>,
    pub matched_detail: Option<String>,
    pub denied: bool,
    pub normalized: Vec<NormalizedArg>,
}
