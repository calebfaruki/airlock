use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub log: LogConfig,
}

#[derive(Deserialize)]
#[serde(default)]
pub struct DaemonConfig {
    pub socket: Option<String>,
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: None,
            log_level: "info".to_string(),
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
pub struct LogConfig {
    pub path: String,
    pub max_size_mb: u64,
    pub max_files: u32,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            path: "~/.local/share/airlock/airlock.log".to_string(),
            max_size_mb: 50,
            max_files: 5,
        }
    }
}

impl Config {
    pub fn load(config_dir: &Path) -> Self {
        let path = config_dir.join("config.toml");
        if path.exists() {
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            match toml::from_str(&content) {
                Ok(config) => config,
                Err(e) => {
                    eprintln!("airlock: warning — failed to parse config.toml: {e}");
                    Config::default()
                }
            }
        } else {
            Config::default()
        }
    }
}

pub fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix('~') {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".to_string());
        format!("{home}{rest}")
    } else {
        path.to_string()
    }
}
