use airlock_daemon::commands::CommandRegistry;
use airlock_daemon::config::{self, Config};
use airlock_daemon::doctor;
use airlock_daemon::hooks::HookRunner;
use airlock_daemon::logging::AuditLogger;
use airlock_daemon::profile::Profile;
use airlock_daemon::test;
use airlock_daemon::{bind_profile_socket, run_daemon, ConcurrencyLocks, MountCache, ProfileMap};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

fn config_dir() -> PathBuf {
    let home = env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".config").join("airlock")
}

fn profiles_dir() -> PathBuf {
    config_dir().join("profiles")
}

fn sockets_dir() -> PathBuf {
    config_dir().join("sockets")
}

fn user_commands_dir() -> PathBuf {
    config_dir().join("commands")
}

fn hooks_dir() -> PathBuf {
    config_dir().join("hooks")
}

fn load_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.load_builtins();
    registry.load_user_overrides(&user_commands_dir());
    registry
}

fn require_enabled_commands() -> (Config, HashSet<String>) {
    let app_config = Config::load(&config_dir());
    let enabled: HashSet<String> = match &app_config.commands.enable {
        Some(list) if list.is_empty() => {
            eprintln!(
                "airlock: commands.enable is empty — enable at least one command in config.toml"
            );
            std::process::exit(1);
        }
        Some(list) => list.iter().cloned().collect(),
        None => {
            eprintln!("airlock: no commands enabled — add [commands] enable = [\"git\"] to ~/.config/airlock/config.toml");
            std::process::exit(1);
        }
    };
    (app_config, enabled)
}

fn load_filtered_registry(enabled: &HashSet<String>) -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.load_builtins_filtered(enabled);
    registry.load_user_overrides_filtered(&user_commands_dir(), enabled);
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
        "doctor" => {
            let (_, enabled) = require_enabled_commands();
            let registry = load_filtered_registry(&enabled);

            let cmd_results = doctor::check_commands(&registry);
            doctor::print_results("Commands", &cmd_results);

            let docker_results = doctor::check_docker();
            doctor::print_results("Docker", &docker_results);

            if doctor::has_failures(&cmd_results) || doctor::has_failures(&docker_results) {
                std::process::exit(1);
            }
            return;
        }
        "test" => {
            let profile_name = match args.get(2) {
                Some(p) => p,
                None => {
                    eprintln!("usage: airlock-daemon test <profile> <command> [args...]");
                    std::process::exit(1);
                }
            };
            let command = match args.get(3) {
                Some(c) => c,
                None => {
                    eprintln!("usage: airlock-daemon test <profile> <command> [args...]");
                    std::process::exit(1);
                }
            };
            let cmd_args: Vec<String> = args[4..].to_vec();

            let (_, enabled) = require_enabled_commands();
            let registry = load_filtered_registry(&enabled);

            let profile_path = profiles_dir().join(format!("{profile_name}.toml"));
            let profile_content = match std::fs::read_to_string(&profile_path) {
                Ok(c) => c,
                Err(_) => {
                    eprintln!(
                        "airlock: profile '{profile_name}' not found at {}",
                        profile_path.display()
                    );
                    std::process::exit(1);
                }
            };
            let profile = match Profile::parse(&profile_content) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("airlock: failed to parse profile '{profile_name}': {e}");
                    std::process::exit(1);
                }
            };

            let result = test::evaluate(
                profile_name,
                &profile,
                command,
                &cmd_args,
                &enabled,
                &registry,
                &hooks_dir(),
            );
            test::print_result(&result);

            let static_allowed = result.outcome == "ALLOWED";
            eprintln!();
            let live = test::check_live(
                profile_name,
                command,
                &cmd_args,
                &sockets_dir(),
                static_allowed,
            );
            test::print_live_result(&live);

            let exit_code = match (&live, static_allowed) {
                (test::LiveResult::Mismatch { .. }, _) => 1,
                (_, false) => 1,
                _ => 0,
            };
            std::process::exit(exit_code);
        }
        "profile" => {
            let sub = args.get(2).map(|s| s.as_str()).unwrap_or("help");
            match sub {
                "list" => {
                    let prof_dir = profiles_dir();
                    let sock_dir = sockets_dir();
                    if !prof_dir.exists() {
                        eprintln!("no profiles directory at {}", prof_dir.display());
                        std::process::exit(1);
                    }
                    let mut names: Vec<String> = Vec::new();
                    if let Ok(entries) = std::fs::read_dir(&prof_dir) {
                        for entry in entries.flatten() {
                            let path = entry.path();
                            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                                continue;
                            }
                            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                                names.push(name.to_string());
                            }
                        }
                    }
                    names.sort();
                    for name in &names {
                        let sock = sock_dir.join(format!("{name}.sock"));
                        println!("{name}\t{}", sock.display());
                    }
                    if names.is_empty() {
                        eprintln!("no profiles found in {}", prof_dir.display());
                    }
                }
                "show" => {
                    let name = match args.get(3) {
                        Some(n) => n,
                        None => {
                            eprintln!("usage: airlock-daemon profile show <name>");
                            std::process::exit(1);
                        }
                    };
                    let path = profiles_dir().join(format!("{name}.toml"));
                    match std::fs::read_to_string(&path) {
                        Ok(content) => print!("{content}"),
                        Err(e) => {
                            eprintln!("failed to read profile '{name}': {e}");
                            std::process::exit(1);
                        }
                    }
                }
                _ => {
                    eprintln!("usage: airlock-daemon profile <list|show>");
                    std::process::exit(1);
                }
            }
            return;
        }
        _ => {
            eprintln!(
                "usage: airlock-daemon <start|version|init|check|doctor|why|show|diff|eject|profile>"
            );
            std::process::exit(1);
        }
    }

    // Load profiles
    let prof_dir = profiles_dir();
    let mut profile_map: HashMap<String, Profile> = HashMap::new();

    if prof_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&prof_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                    continue;
                }
                let name = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("airlock: failed to read profile '{}': {e}", path.display());
                        std::process::exit(1);
                    }
                };
                match Profile::parse(&content) {
                    Ok(profile) => {
                        profile_map.insert(name, profile);
                    }
                    Err(e) => {
                        eprintln!("airlock: failed to parse profile '{}': {e}", path.display());
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    if profile_map.is_empty() {
        eprintln!(
            "airlock: no profiles found in {} — create at least one profile to start",
            prof_dir.display()
        );
        std::process::exit(1);
    }

    // Bind sockets
    let sock_dir = sockets_dir();
    if let Err(e) = std::fs::create_dir_all(&sock_dir) {
        eprintln!(
            "airlock: failed to create sockets directory {}: {e}",
            sock_dir.display()
        );
        std::process::exit(1);
    }

    let mut listeners: Vec<(String, UnixListener)> = Vec::new();
    let mut profile_names: Vec<&str> = profile_map.keys().map(|s| s.as_str()).collect();
    profile_names.sort();

    for name in &profile_names {
        let sock_path = sock_dir.join(format!("{name}.sock"));
        match bind_profile_socket(&sock_path) {
            Ok(l) => {
                eprintln!("airlock: bound socket {} (mode 0600)", sock_path.display());
                listeners.push((name.to_string(), l));
            }
            Err(e) => {
                eprintln!(
                    "airlock: failed to bind socket at {}: {e}",
                    sock_path.display()
                );
                std::process::exit(1);
            }
        }
    }

    eprintln!(
        "airlock: listening on {} profile socket(s): {}",
        listeners.len(),
        profile_names.join(", ")
    );

    let profiles: ProfileMap = Arc::new(profile_map);

    let (app_config, enabled_commands) = require_enabled_commands();
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
    let registry = load_filtered_registry(&enabled_commands);
    eprintln!(
        "airlock: enabled commands: {}",
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
        listeners,
        profiles,
        mount_cache,
        registry,
        cmd_locks,
        hook_runner,
        logger,
    )
    .await;
}
