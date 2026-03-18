use airlock_daemon::commands::CommandRegistry;
use airlock_daemon::config::{self, Config};
use airlock_daemon::hooks::HookRunner;
use airlock_daemon::logging::AuditLogger;
use airlock_daemon::{run_daemon, ConcurrencyLocks, MountCache};
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

fn socket_path() -> PathBuf {
    if cfg!(target_os = "macos") {
        let home = env::var("HOME").expect("HOME not set");
        PathBuf::from(home)
            .join(".config")
            .join("airlock")
            .join("docker-airlock.sock")
    } else {
        PathBuf::from("/var/run/docker-airlock.sock")
    }
}

fn config_dir() -> PathBuf {
    let home = env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config").join("airlock")
}

fn user_commands_dir() -> PathBuf {
    config_dir().join("commands")
}

fn hooks_dir() -> PathBuf {
    let home = env::var("HOME").expect("HOME not set");
    PathBuf::from(home)
        .join(".config")
        .join("airlock")
        .join("hooks")
}

fn load_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.load_builtins();
    registry.load_user_overrides(&user_commands_dir());
    registry
}

fn show_command(args: &[String]) {
    let cmd = match args.first() {
        Some(c) => c,
        None => {
            eprintln!("usage: airlock-daemon show <command>");
            std::process::exit(1);
        }
    };

    let registry = load_registry();
    match registry.active_toml(cmd) {
        Some(toml) => print!("{toml}"),
        None => {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
    }
}

fn diff_command(args: &[String]) {
    let cmd = match args.first() {
        Some(c) => c,
        None => {
            eprintln!("usage: airlock-daemon diff <command>");
            std::process::exit(1);
        }
    };

    let registry = load_registry();

    if !registry.has_user_override(cmd) {
        if registry.has_builtin(cmd) {
            println!("No user override for '{cmd}'. Built-in is active.");
        } else {
            eprintln!("unknown command: {cmd}");
            std::process::exit(1);
        }
        return;
    }

    if !registry.has_builtin(cmd) {
        println!("'{cmd}' is user-defined. No built-in to compare.");
        return;
    }

    let builtin = registry.builtin_toml(cmd).unwrap();
    let user = registry.user_toml(cmd).unwrap();

    let tmp_dir = std::env::temp_dir();
    let builtin_path = tmp_dir.join(format!("airlock-builtin-{cmd}.toml"));
    let user_path = tmp_dir.join(format!("airlock-user-{cmd}.toml"));

    std::fs::write(&builtin_path, builtin).expect("failed to write temp file");
    std::fs::write(&user_path, user).expect("failed to write temp file");

    let output = std::process::Command::new("diff")
        .arg("-u")
        .arg("--label")
        .arg(format!("built-in/{cmd}.toml"))
        .arg("--label")
        .arg(format!("user/{cmd}.toml"))
        .arg(&builtin_path)
        .arg(&user_path)
        .output()
        .expect("failed to run diff");

    let _ = std::fs::remove_file(&builtin_path);
    let _ = std::fs::remove_file(&user_path);

    print!("{}", String::from_utf8_lossy(&output.stdout));
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }
}

fn eject_command(args: &[String]) {
    let cmd = match args.first() {
        Some(c) => c,
        None => {
            eprintln!("usage: airlock-daemon eject <command>");
            std::process::exit(1);
        }
    };

    let mut registry = CommandRegistry::new();
    registry.load_builtins();

    let builtin = match registry.builtin_toml(cmd) {
        Some(t) => t.to_string(),
        None => {
            eprintln!("no built-in module for '{cmd}'");
            std::process::exit(1);
        }
    };

    let dir = user_commands_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("failed to create {}: {e}", dir.display());
        std::process::exit(1);
    }

    let path = dir.join(format!("{cmd}.toml"));
    if path.exists() {
        eprintln!(
            "user override already exists at {}. Delete it first to re-eject.",
            path.display()
        );
        std::process::exit(1);
    }

    std::fs::write(&path, builtin).expect("failed to write file");
    println!("ejected built-in '{cmd}' to {}", path.display());
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let subcommand = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match subcommand {
        "start" => {}
        "version" => {
            println!("airlock-daemon {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        "show" => {
            show_command(&args[2..]);
            return;
        }
        "diff" => {
            diff_command(&args[2..]);
            return;
        }
        "eject" => {
            eject_command(&args[2..]);
            return;
        }
        "init" => {
            let config = airlock_daemon::init::InitConfig::detect();
            let uninstall = args.iter().any(|a| a == "--uninstall");
            if uninstall {
                airlock_daemon::init::run_uninstall(&config).unwrap_or_else(|e| {
                    eprintln!("airlock: {e}");
                    std::process::exit(1);
                });
            } else {
                airlock_daemon::init::run_init(&config).unwrap_or_else(|e| {
                    eprintln!("airlock: {e}");
                    std::process::exit(1);
                });
            }
            return;
        }
        "check" => {
            let mut registry = CommandRegistry::new();
            registry.load_builtins();

            let user_dir = user_commands_dir();
            let mut has_errors = false;

            if user_dir.exists() {
                if let Ok(entries) = std::fs::read_dir(&user_dir) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                            continue;
                        }
                        let name = path.file_stem().unwrap().to_string_lossy();
                        let content = match std::fs::read_to_string(&path) {
                            Ok(c) => c,
                            Err(e) => {
                                eprintln!("  error: {name} — {e}");
                                has_errors = true;
                                continue;
                            }
                        };
                        match airlock_daemon::commands::CommandModule::parse(&content) {
                            Ok(_) => eprintln!("  ok: {name}"),
                            Err(e) => {
                                eprintln!("  error: {name} — {e}");
                                has_errors = true;
                            }
                        }
                    }
                }
            }

            let commands = registry.command_names();
            eprintln!("airlock: {} built-in commands", commands.len());

            if has_errors {
                eprintln!("airlock: validation failed");
                std::process::exit(1);
            } else {
                eprintln!("airlock: all modules valid");
            }
            return;
        }
        _ => {
            eprintln!("usage: airlock-daemon <start|version|init|check|show|diff|eject>");
            std::process::exit(1);
        }
    }

    let path = socket_path();

    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("failed to create socket directory: {e}");
            std::process::exit(1);
        }
    }

    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("failed to bind socket at {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    println!("airlock-daemon listening on {}", path.display());

    let app_config = Config::load(&config_dir());
    let log_path = config::expand_tilde(&app_config.log.path);
    if let Some(dir) = std::path::Path::new(&log_path).parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let logger = Arc::new(AuditLogger::new(
        PathBuf::from(log_path),
        app_config.log.max_size_mb,
        app_config.log.max_files,
    ));

    let mount_cache: MountCache = Arc::new(RwLock::new(HashMap::new()));
    let registry = load_registry();
    eprintln!(
        "airlock: loaded commands: {}",
        registry.command_names().join(", ")
    );
    let overrides = registry.user_override_names();
    if !overrides.is_empty() {
        eprintln!("airlock: user overrides: {}", overrides.join(", "));
    }
    let registry = Arc::new(registry);
    let cmd_locks: ConcurrencyLocks = Arc::new(RwLock::new(HashMap::new()));
    let hook_runner = Arc::new(HookRunner::new(hooks_dir()));

    run_daemon(
        listener,
        mount_cache,
        registry,
        cmd_locks,
        hook_runner,
        logger,
    )
    .await;
}
