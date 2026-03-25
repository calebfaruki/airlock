use crate::profile::Profile;
use std::path::{Path, PathBuf};

pub struct DaemonPaths {
    pub config_dir: PathBuf,
    pub sockets_dir: PathBuf,
}

impl DaemonPaths {
    pub fn from_home(home: &Path) -> Self {
        let config_dir = home.join(".config").join("airlock");
        Self {
            sockets_dir: config_dir.join("sockets"),
            config_dir,
        }
    }

    pub fn detect() -> Self {
        let home = std::env::var("HOME").expect("HOME not set");
        Self::from_home(Path::new(&home))
    }
}

pub struct AgentPaths {
    pub root: PathBuf,
}

impl AgentPaths {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn profile_path(&self) -> PathBuf {
        self.root.join("airlock.toml")
    }

    pub fn commands_dir(&self) -> PathBuf {
        self.root.join("commands")
    }

    pub fn hooks_dir(&self) -> PathBuf {
        self.root.join("hooks")
    }

    pub fn load_profile(&self) -> Result<Profile, String> {
        let content = std::fs::read_to_string(self.profile_path())
            .map_err(|e| format!("failed to read {}: {e}", self.profile_path().display()))?;
        Profile::parse(&content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_home_derives_standard_paths() {
        let p = DaemonPaths::from_home(Path::new("/home/testuser"));
        assert_eq!(
            p.config_dir,
            PathBuf::from("/home/testuser/.config/airlock")
        );
        assert_eq!(
            p.sockets_dir,
            PathBuf::from("/home/testuser/.config/airlock/sockets")
        );
    }

    #[test]
    fn agent_paths_derive_from_root() {
        let a = AgentPaths::new(PathBuf::from("/home/admin/my-agents/hello-world"));
        assert_eq!(
            a.profile_path(),
            PathBuf::from("/home/admin/my-agents/hello-world/airlock.toml")
        );
        assert_eq!(
            a.commands_dir(),
            PathBuf::from("/home/admin/my-agents/hello-world/commands")
        );
        assert_eq!(
            a.hooks_dir(),
            PathBuf::from("/home/admin/my-agents/hello-world/hooks")
        );
    }

    #[test]
    fn agent_load_profile_reads_and_parses() {
        let dir = std::env::temp_dir().join(format!("airlock-agent-rg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("airlock.toml"), "commands = [\"git\"]\n").unwrap();

        let a = AgentPaths::new(dir.clone());
        let profile = a.load_profile().unwrap();
        assert_eq!(profile.commands, vec!["git".to_string()]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_load_profile_errors_on_missing() {
        let a = AgentPaths::new(PathBuf::from("/nonexistent/agent"));
        assert!(a.load_profile().is_err());
    }
}
