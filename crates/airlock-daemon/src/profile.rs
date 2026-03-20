use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub commands: Vec<String>,
    pub env: Option<ProfileEnv>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileEnv {
    pub set: Option<HashMap<String, String>>,
}

impl Profile {
    pub fn parse(toml_str: &str) -> Result<Self, String> {
        toml::from_str(toml_str).map_err(|e| format!("failed to parse profile: {e}"))
    }

    pub fn allows_command(&self, command: &str) -> bool {
        self.commands.is_empty() || self.commands.iter().any(|c| c == command)
    }
}

#[cfg(test)]
mod credential_isolation {
    use super::*;

    #[test]
    fn parse_empty_returns_error() {
        assert!(Profile::parse("").is_err());
    }

    #[test]
    fn parse_commands_only() {
        let profile = Profile::parse(r#"commands = ["git", "gh"]"#).unwrap();
        assert_eq!(profile.commands, vec!["git", "gh"]);
        assert!(profile.env.is_none());
    }

    #[test]
    fn parse_env_only() {
        let profile = Profile::parse(
            r#"
commands = []

[env]
set = { AWS_PROFILE = "readonly", GIT_SSH_COMMAND = "ssh -i ~/.ssh/key" }
"#,
        )
        .unwrap();
        assert!(profile.commands.is_empty());
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
        let profile = Profile::parse(r#"commands = []"#).unwrap();
        assert!(profile.allows_command("git"));
        assert!(profile.allows_command("terraform"));
        assert!(profile.allows_command("anything"));
    }
}
