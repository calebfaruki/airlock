use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandModule {
    pub command: CommandSection,
    pub deny: Option<DenySection>,
    pub env: Option<EnvSection>,
    pub args: Option<ArgsSection>,
    pub exec: Option<ExecSection>,
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
        toml::from_str(toml_str).map_err(|e| format!("failed to parse command module: {e}"))
    }

    pub fn is_concurrent(&self) -> bool {
        self.exec
            .as_ref()
            .and_then(|e| e.concurrent)
            .unwrap_or(true)
    }

    pub fn check_deny(&self, args: &[String]) -> Option<&str> {
        let deny = self.deny.as_ref()?;
        for arg in args {
            for denied in &deny.args {
                if arg == denied {
                    return Some(denied);
                }
            }
        }
        None
    }
}
