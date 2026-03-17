use std::path::{Path, PathBuf};

pub struct InitConfig {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub bin_path: PathBuf,
    pub socket_path: PathBuf,
}

#[derive(Debug, PartialEq)]
pub enum ServiceResult {
    Installed,
    Updated,
    Unchanged,
}

impl InitConfig {
    pub fn detect() -> Self {
        let home = std::env::var("HOME").expect("HOME not set");
        let home = PathBuf::from(home);

        let bin_path =
            std::env::current_exe().unwrap_or_else(|_| home.join(".local/bin/airlock-daemon"));

        let socket_path = if cfg!(target_os = "macos") {
            home.join(".config/airlock/docker-airlock.sock")
        } else {
            PathBuf::from("/var/run/docker-airlock.sock")
        };

        Self {
            config_dir: home.join(".config/airlock"),
            data_dir: home.join(".local/share/airlock"),
            bin_path,
            socket_path,
        }
    }
}

pub fn run_init(config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let created = create_directories(config)?;
    for dir in &created {
        println!("airlock: created {dir}");
    }

    let result = install_service(config)?;
    match result {
        ServiceResult::Installed => println!("airlock: installed service"),
        ServiceResult::Updated => println!("airlock: updated service"),
        ServiceResult::Unchanged => println!("airlock: service already installed (up to date)"),
    }

    if result != ServiceResult::Unchanged {
        start_service(config)?;
        println!("airlock: daemon started");
    }

    println!("airlock:");
    println!("airlock: Docker volume mount flag:");
    if cfg!(target_os = "macos") {
        println!(
            "airlock:   -v {}:/run/docker-airlock.sock",
            config.socket_path.display()
        );
    } else {
        println!("airlock:   -v /var/run/docker-airlock.sock:/run/docker-airlock.sock");
    }

    Ok(())
}

pub fn run_uninstall(config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    stop_service(config)?;
    println!("airlock: stopped service");

    remove_service(config)?;
    println!("airlock: removed service file");

    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path)?;
        println!("airlock: removed socket {}", config.socket_path.display());
    }

    Ok(())
}

pub fn create_directories(config: &InitConfig) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut created = Vec::new();

    let dirs = [
        config.config_dir.join("hooks"),
        config.config_dir.join("commands"),
        config.data_dir.clone(),
    ];

    for dir in &dirs {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            created.push(dir.to_string_lossy().to_string());
        }
    }

    Ok(created)
}

fn write_service_file(
    path: &Path,
    content: &str,
) -> Result<ServiceResult, Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if path.exists() {
        let existing = std::fs::read_to_string(path)?;
        if existing == content {
            return Ok(ServiceResult::Unchanged);
        }
        std::fs::write(path, content)?;
        Ok(ServiceResult::Updated)
    } else {
        std::fs::write(path, content)?;
        Ok(ServiceResult::Installed)
    }
}

// --- systemd (Linux) ---

pub fn generate_systemd_unit(bin_path: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=Airlock daemon — CLI proxy for Docker credential isolation\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={} start\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         Environment=RUST_LOG=info\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        bin_path.display()
    )
}

fn systemd_unit_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config/systemd/user/airlock.service")
}

fn install_systemd_service(
    config: &InitConfig,
) -> Result<ServiceResult, Box<dyn std::error::Error>> {
    let content = generate_systemd_unit(&config.bin_path);
    let path = systemd_unit_path();
    let result = write_service_file(&path, &content)?;

    if result != ServiceResult::Unchanged {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .status();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "enable", "airlock.service"])
            .status();
    }

    // Linger check
    let username = std::env::var("USER").unwrap_or_default();
    let linger_path = PathBuf::from("/var/lib/systemd/linger").join(&username);
    if !linger_path.exists() {
        eprintln!("airlock: warning — systemd linger not enabled for user '{username}'");
        eprintln!("airlock: the daemon will stop when you log out");
        eprintln!("airlock: run 'loginctl enable-linger {username}' to keep it running");
    }

    Ok(result)
}

fn start_systemd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let status = std::process::Command::new("systemctl")
        .args(["--user", "start", "airlock.service"])
        .status()?;

    if !status.success() {
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "restart", "airlock.service"])
            .status();
    }

    Ok(())
}

fn stop_systemd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "airlock.service"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "airlock.service"])
        .status();
    Ok(())
}

fn remove_systemd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = systemd_unit_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(())
}

// --- launchd (macOS) ---

pub fn generate_launchd_plist(bin_path: &Path, data_dir: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.airlock.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>{}/airlock-stdout.log</string>
    <key>StandardErrorPath</key>
    <string>{}/airlock-stderr.log</string>
</dict>
</plist>
"#,
        bin_path.display(),
        data_dir.display(),
        data_dir.display()
    )
}

fn launchd_plist_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join("Library/LaunchAgents/dev.airlock.daemon.plist")
}

fn get_uid() -> String {
    let output = std::process::Command::new("id")
        .arg("-u")
        .output()
        .expect("failed to run id -u");
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn install_launchd_service(
    config: &InitConfig,
) -> Result<ServiceResult, Box<dyn std::error::Error>> {
    let content = generate_launchd_plist(&config.bin_path, &config.data_dir);
    let path = launchd_plist_path();
    write_service_file(&path, &content)
}

fn start_launchd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let uid = get_uid();
    let path = launchd_plist_path();

    // Unload first (ignore errors — might not be loaded)
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}"), &path.to_string_lossy()])
        .status();

    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}"), &path.to_string_lossy()])
        .status()?;

    if !status.success() {
        eprintln!("airlock: warning — launchctl bootstrap failed");
    }

    Ok(())
}

fn stop_launchd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let uid = get_uid();
    let path = launchd_plist_path();
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}"), &path.to_string_lossy()])
        .status();
    Ok(())
}

fn remove_launchd_service(_config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = launchd_plist_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

// --- Platform dispatch ---

fn install_service(config: &InitConfig) -> Result<ServiceResult, Box<dyn std::error::Error>> {
    if cfg!(target_os = "linux") {
        install_systemd_service(config)
    } else if cfg!(target_os = "macos") {
        install_launchd_service(config)
    } else {
        Err("unsupported platform".into())
    }
}

fn start_service(config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(target_os = "linux") {
        start_systemd_service(config)
    } else if cfg!(target_os = "macos") {
        start_launchd_service(config)
    } else {
        Err("unsupported platform".into())
    }
}

fn stop_service(config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(target_os = "linux") {
        stop_systemd_service(config)
    } else if cfg!(target_os = "macos") {
        stop_launchd_service(config)
    } else {
        Err("unsupported platform".into())
    }
}

fn remove_service(config: &InitConfig) -> Result<(), Box<dyn std::error::Error>> {
    if cfg!(target_os = "linux") {
        remove_systemd_service(config)
    } else if cfg!(target_os = "macos") {
        remove_launchd_service(config)
    } else {
        Err("unsupported platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(base: &Path) -> InitConfig {
        InitConfig {
            config_dir: base.join("config/airlock"),
            data_dir: base.join("share/airlock"),
            bin_path: PathBuf::from("/usr/local/bin/airlock-daemon"),
            socket_path: base.join("airlock.sock"),
        }
    }

    #[test]
    fn init_creates_directory_structure() {
        let base = std::env::temp_dir().join(format!("airlock-init-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let config = temp_config(&base);

        let created = create_directories(&config).unwrap();
        assert_eq!(created.len(), 3);
        assert!(config.config_dir.join("hooks").is_dir());
        assert!(config.config_dir.join("commands").is_dir());
        assert!(config.data_dir.is_dir());

        // Idempotent: second call creates nothing
        let created = create_directories(&config).unwrap();
        assert!(created.is_empty());

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn init_generates_correct_systemd_unit() {
        let content = generate_systemd_unit(Path::new("/home/user/.local/bin/airlock-daemon"));
        assert!(content.contains("ExecStart=/home/user/.local/bin/airlock-daemon start"));
        assert!(content.contains("Type=simple"));
        assert!(content.contains("Restart=on-failure"));
        assert!(content.contains("WantedBy=default.target"));
    }

    #[test]
    fn init_generates_correct_launchd_plist() {
        let content = generate_launchd_plist(
            Path::new("/usr/local/bin/airlock-daemon"),
            Path::new("/Users/test/.local/share/airlock"),
        );
        assert!(content.contains("<string>dev.airlock.daemon</string>"));
        assert!(content.contains("<string>/usr/local/bin/airlock-daemon</string>"));
        assert!(content.contains("<string>start</string>"));
        assert!(content.contains("<key>RunAtLoad</key>"));
        assert!(content.contains("<key>KeepAlive</key>"));
        assert!(content.contains("<key>SuccessfulExit</key>"));
        assert!(content.contains("/Users/test/.local/share/airlock/airlock-stdout.log"));
    }

    #[test]
    fn init_skips_unchanged_service_file() {
        let base = std::env::temp_dir().join(format!("airlock-svc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let path = base.join("test.service");
        let content = "test content";

        // First write: Installed
        let result = write_service_file(&path, content).unwrap();
        assert_eq!(result, ServiceResult::Installed);

        // Same content: Unchanged
        let result = write_service_file(&path, content).unwrap();
        assert_eq!(result, ServiceResult::Unchanged);

        // Different content: Updated
        let result = write_service_file(&path, "new content").unwrap();
        assert_eq!(result, ServiceResult::Updated);

        let _ = std::fs::remove_dir_all(&base);
    }
}
