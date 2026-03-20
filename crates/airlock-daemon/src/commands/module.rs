use serde::Deserialize;
use std::collections::HashMap;

use super::deny::{normalize_args, parse_deny_entry, DenyRule};

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
        module.deny_rules = module
            .deny
            .as_ref()
            .map(|d| d.args.iter().map(|a| parse_deny_entry(a)).collect())
            .unwrap_or_default();
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
}
