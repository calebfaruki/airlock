use super::builtin;
use super::module::CommandModule;
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub struct CommandRegistry {
    modules: HashMap<String, CommandModule>,
    builtin_sources: HashMap<String, String>,
    agent_modules: HashMap<String, HashMap<String, CommandModule>>,
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            modules: HashMap::new(),
            builtin_sources: HashMap::new(),
            agent_modules: HashMap::new(),
        }
    }

    pub fn load_builtins(&mut self) {
        for (name, toml_str) in builtin::builtins() {
            match CommandModule::parse(toml_str) {
                Ok(module) => {
                    self.modules.insert(name.to_string(), module);
                    self.builtin_sources
                        .insert(name.to_string(), toml_str.to_string());
                }
                Err(e) => {
                    eprintln!("airlock: failed to parse built-in module '{name}': {e}");
                }
            }
        }
    }

    pub fn load_builtins_filtered(&mut self, enabled: &HashSet<String>) {
        for (name, toml_str) in builtin::builtins() {
            if !enabled.contains(name) {
                continue;
            }
            match CommandModule::parse(toml_str) {
                Ok(module) => {
                    self.modules.insert(name.to_string(), module);
                    self.builtin_sources
                        .insert(name.to_string(), toml_str.to_string());
                }
                Err(e) => {
                    eprintln!("airlock: failed to parse built-in module '{name}': {e}");
                }
            }
        }
    }

    pub fn load_agent_overrides(
        &mut self,
        agent_name: &str,
        dir: &Path,
        enabled: Option<&HashSet<String>>,
    ) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        let mods = self
            .agent_modules
            .entry(agent_name.to_string())
            .or_default();

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if let Some(set) = enabled {
                if !set.contains(&name) {
                    continue;
                }
            }
            let toml_str = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "airlock: failed to read agent override '{}': {e}",
                        path.display()
                    );
                    continue;
                }
            };
            match CommandModule::parse(&toml_str) {
                Ok(module) => {
                    mods.insert(name, module);
                }
                Err(e) => {
                    eprintln!(
                        "airlock: failed to parse agent override '{}': {e}",
                        path.display()
                    );
                }
            }
        }
    }

    pub fn get_for_agent(&self, command: &str, agent_name: Option<&str>) -> Option<&CommandModule> {
        if let Some(name) = agent_name {
            if let Some(agent_mods) = self.agent_modules.get(name) {
                if let Some(module) = agent_mods.get(command) {
                    return Some(module);
                }
            }
        }
        self.modules.get(command)
    }

    pub fn active_toml(&self, command: &str) -> Option<&str> {
        self.builtin_sources.get(command).map(|s| s.as_str())
    }

    pub fn has_builtin(&self, command: &str) -> bool {
        self.builtin_sources.contains_key(command)
    }

    pub fn command_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.modules.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    pub fn load_from_str(&mut self, name: &str, toml_str: &str) -> Result<(), String> {
        let module = CommandModule::parse(toml_str)?;
        self.modules.insert(name.to_string(), module);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtered_loads_only_enabled() {
        let mut reg = CommandRegistry::new();
        let enabled: HashSet<String> = ["git"].iter().map(|s| s.to_string()).collect();
        reg.load_builtins_filtered(&enabled);
        assert!(reg.get_for_agent("git", None).is_some());
        assert!(reg.get_for_agent("terraform", None).is_none());
        assert!(reg.get_for_agent("aws", None).is_none());
        assert!(reg.get_for_agent("ssh", None).is_none());
        assert!(reg.get_for_agent("docker", None).is_none());
        assert_eq!(reg.command_names(), vec!["git"]);
    }

    #[test]
    fn filtered_with_empty_set_loads_nothing() {
        let mut reg = CommandRegistry::new();
        let enabled: HashSet<String> = HashSet::new();
        reg.load_builtins_filtered(&enabled);
        assert!(reg.command_names().is_empty());
    }

    #[test]
    fn filtered_ignores_nonexistent_names() {
        let mut reg = CommandRegistry::new();
        let enabled: HashSet<String> = ["git", "nonexistent"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        reg.load_builtins_filtered(&enabled);
        assert_eq!(reg.command_names(), vec!["git"]);
    }

    #[test]
    fn agent_override_wins_over_builtin() {
        let dir = std::env::temp_dir().join(format!("airlock-rg-prec-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("git.toml"),
            "[command]\nbin = \"git-agent\"\n\n[deny]\nargs = []\n",
        )
        .unwrap();

        let mut reg = CommandRegistry::new();
        reg.load_builtins();
        reg.load_agent_overrides("agent-a", &dir, None);

        let m = reg.get_for_agent("git", Some("agent-a")).unwrap();
        assert_eq!(m.command.bin, "git-agent");

        let m = reg.get_for_agent("git", None).unwrap();
        assert_eq!(m.command.bin, "git");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_overrides_are_isolated() {
        let dir = std::env::temp_dir().join(format!("airlock-rg-iso-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("git.toml"),
            "[command]\nbin = \"git-agent-a\"\n\n[deny]\nargs = []\n",
        )
        .unwrap();

        let mut reg = CommandRegistry::new();
        reg.load_builtins();
        reg.load_agent_overrides("agent-a", &dir, None);

        let m = reg.get_for_agent("git", Some("agent-b")).unwrap();
        assert_eq!(m.command.bin, "git");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_missing_override_falls_back_to_builtin() {
        let dir = std::env::temp_dir().join(format!("airlock-rg-fb-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("git.toml"),
            "[command]\nbin = \"git-agent\"\n\n[deny]\nargs = []\n",
        )
        .unwrap();

        let mut reg = CommandRegistry::new();
        reg.load_builtins();
        reg.load_agent_overrides("agent-a", &dir, None);

        let m = reg.get_for_agent("terraform", Some("agent-a")).unwrap();
        assert_eq!(m.command.bin, "terraform");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
