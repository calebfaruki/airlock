use serde::Deserialize;
use std::collections::HashMap;

use super::deny::{normalize_args, parse_deny_entry, DenyRule, NormalizedArg};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandModule {
    pub command: CommandSection,
    pub deny: Option<DenySection>,
    pub env: Option<EnvSection>,
    pub args: Option<ArgsSection>,
    pub exec: Option<ExecSection>,
    #[serde(skip)]
    deny_rules: Vec<DenyRule>,
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
        module.deny_rules = match &module.deny {
            Some(d) => d
                .args
                .iter()
                .map(|a| parse_deny_entry(a))
                .collect::<Result<Vec<_>, _>>()?,
            None => Vec::new(),
        };
        Ok(module)
    }

    pub fn is_concurrent(&self) -> bool {
        self.exec
            .as_ref()
            .and_then(|e| e.concurrent)
            .unwrap_or(true)
    }

    pub fn check_deny(&self, args: &[String]) -> Option<String> {
        if self.deny_rules.is_empty() {
            return None;
        }
        let normalized = normalize_args(args);
        for rule in &self.deny_rules {
            if let Some(reason) = rule.matches(&normalized) {
                return Some(reason);
            }
        }
        None
    }

    pub fn check_deny_verbose(&self, args: &[String]) -> DenyEvaluation {
        let normalized = normalize_args(args);
        let rules_checked = self.deny_rules.len();
        let mut matched_rule = None;
        let mut matched_detail = None;

        for rule in &self.deny_rules {
            if let Some(reason) = rule.matches(&normalized) {
                // Find which normalized arg triggered the match
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

        DenyEvaluation {
            rules_checked,
            matched_rule,
            matched_detail,
            normalized,
        }
    }
}

pub struct DenyEvaluation {
    pub rules_checked: usize,
    pub matched_rule: Option<String>,
    pub matched_detail: Option<String>,
    pub normalized: Vec<NormalizedArg>,
}
