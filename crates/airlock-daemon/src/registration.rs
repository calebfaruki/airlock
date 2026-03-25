use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
struct AgentEntry {
    path: String,
}

#[derive(Debug)]
pub struct AgentRegistration {
    pub name: String,
    pub path: PathBuf,
}

pub fn load_registration(path: &Path) -> Result<Vec<AgentRegistration>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    parse_registration(&content)
}

pub fn parse_registration(content: &str) -> Result<Vec<AgentRegistration>, String> {
    let map: HashMap<String, AgentEntry> =
        toml::from_str(content).map_err(|e| format!("failed to parse agents file: {e}"))?;

    let mut agents = Vec::new();
    for (name, entry) in map {
        let path = PathBuf::from(&entry.path);
        if !path.is_dir() {
            return Err(format!(
                "agent '{}': path {} does not exist",
                name,
                path.display()
            ));
        }
        if !path.join("airlock.toml").exists() {
            return Err(format!(
                "agent '{}': {} missing airlock.toml",
                name,
                path.display()
            ));
        }
        agents.push(AgentRegistration { name, path });
    }
    agents.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(agents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_two_agents() {
        let dir1 = std::env::temp_dir().join(format!("airlock-reg1-{}", std::process::id()));
        let dir2 = std::env::temp_dir().join(format!("airlock-reg2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
        std::fs::create_dir_all(&dir1).unwrap();
        std::fs::create_dir_all(&dir2).unwrap();
        std::fs::write(dir1.join("airlock.toml"), "commands = []\n").unwrap();
        std::fs::write(dir2.join("airlock.toml"), "commands = [\"git\"]\n").unwrap();

        let content = format!(
            "[hello]\npath = \"{}\"\n\n[dev]\npath = \"{}\"\n",
            dir1.display(),
            dir2.display()
        );
        let agents = parse_registration(&content).unwrap();
        assert_eq!(agents.len(), 2);
        let names: Vec<&str> = agents.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"hello"));
        assert!(names.contains(&"dev"));

        let _ = std::fs::remove_dir_all(&dir1);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn missing_directory_errors() {
        let content = "[broken]\npath = \"/nonexistent/agent/dir\"\n";
        let err = parse_registration(content).unwrap_err();
        assert!(err.contains("broken"));
        assert!(err.contains("/nonexistent/agent/dir"));
    }

    #[test]
    fn missing_airlock_toml_errors() {
        let dir = std::env::temp_dir().join(format!("airlock-reg-no-toml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let content = format!("[no-profile]\npath = \"{}\"\n", dir.display());
        let err = parse_registration(&content).unwrap_err();
        assert!(err.contains("no-profile"));
        assert!(err.contains("airlock.toml"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_file_returns_empty_vec() {
        let agents = parse_registration("").unwrap();
        assert!(agents.is_empty());
    }
}
