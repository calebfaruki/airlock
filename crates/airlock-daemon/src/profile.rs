use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub commands: Option<Vec<String>>,
    pub env: Option<ProfileEnv>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEnv {
    pub set: Option<HashMap<String, String>>,
}

impl Profile {
    pub fn parse(toml_str: &str) -> Result<Self, String> {
        if toml_str.trim().is_empty() {
            return Ok(Self::default());
        }
        toml::from_str(toml_str).map_err(|e| format!("failed to parse profile: {e}"))
    }

    pub fn allows_command(&self, command: &str) -> bool {
        match &self.commands {
            Some(list) => list.iter().any(|c| c == command),
            None => true,
        }
    }
}

#[cfg(test)]
mod credential_isolation {
    use super::*;

    #[test]
    fn parse_empty_produces_default_profile() {
        let profile = Profile::parse("").unwrap();
        assert!(profile.commands.is_none());
        assert!(profile.env.is_none());
    }

    #[test]
    fn parse_commands_only() {
        let profile = Profile::parse(r#"commands = ["git", "gh"]"#).unwrap();
        let cmds = profile.commands.unwrap();
        assert_eq!(cmds, vec!["git", "gh"]);
        assert!(profile.env.is_none());
    }

    #[test]
    fn parse_env_only() {
        let profile = Profile::parse(
            r#"
[env]
set = { AWS_PROFILE = "readonly", GIT_SSH_COMMAND = "ssh -i ~/.ssh/key" }
"#,
        )
        .unwrap();
        assert!(profile.commands.is_none());
        let set = profile.env.unwrap().set.unwrap();
        assert_eq!(set["AWS_PROFILE"], "readonly");
        assert_eq!(set["GIT_SSH_COMMAND"], "ssh -i ~/.ssh/key");
    }

    #[test]
    fn parse_invalid_toml_returns_error() {
        let result = Profile::parse("commands = [");
        assert!(result.is_err());
    }

    #[test]
    fn parse_unknown_field_returns_error() {
        let result = Profile::parse(r#"unknown_field = true"#);
        assert!(result.is_err());
    }

    #[test]
    fn allows_command_with_list() {
        let profile = Profile::parse(r#"commands = ["git", "aws"]"#).unwrap();
        assert!(profile.allows_command("git"));
        assert!(profile.allows_command("aws"));
        assert!(!profile.allows_command("terraform"));
        assert!(!profile.allows_command("kubectl"));
    }

    #[test]
    fn allows_command_without_list() {
        let profile = Profile::parse("").unwrap();
        assert!(profile.allows_command("git"));
        assert!(profile.allows_command("terraform"));
        assert!(profile.allows_command("anything"));
    }
}
