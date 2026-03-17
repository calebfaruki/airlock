use super::builtin;
use super::module::CommandModule;
use std::collections::HashMap;
use std::path::Path;

pub struct CommandRegistry {
    modules: HashMap<String, CommandModule>,
    builtin_sources: HashMap<String, String>,
    user_sources: HashMap<String, String>,
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
            user_sources: HashMap::new(),
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

    pub fn load_user_overrides(&mut self, dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }

            let name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };

            let toml_str = match std::fs::read_to_string(&path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "airlock: failed to read user override '{}': {e}",
                        path.display()
                    );
                    continue;
                }
            };

            match CommandModule::parse(&toml_str) {
                Ok(module) => {
                    if self.builtin_sources.contains_key(&name) {
                        eprintln!(
                            "airlock: warning — user override for '{name}' may be behind built-in. Run 'airlock-daemon diff {name}' to compare."
                        );
                    }
                    self.modules.insert(name.clone(), module);
                    self.user_sources.insert(name, toml_str);
                }
                Err(e) => {
                    eprintln!(
                        "airlock: failed to parse user override '{}': {e}",
                        path.display()
                    );
                }
            }
        }
    }

    pub fn get(&self, command: &str) -> Option<&CommandModule> {
        self.modules.get(command)
    }

    pub fn active_toml(&self, command: &str) -> Option<&str> {
        self.user_sources
            .get(command)
            .or_else(|| self.builtin_sources.get(command))
            .map(|s| s.as_str())
    }

    pub fn builtin_toml(&self, command: &str) -> Option<&str> {
        self.builtin_sources.get(command).map(|s| s.as_str())
    }

    pub fn user_toml(&self, command: &str) -> Option<&str> {
        self.user_sources.get(command).map(|s| s.as_str())
    }

    pub fn has_builtin(&self, command: &str) -> bool {
        self.builtin_sources.contains_key(command)
    }

    pub fn has_user_override(&self, command: &str) -> bool {
        self.user_sources.contains_key(command)
    }
}
