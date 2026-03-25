use airlock_daemon::commands::CommandRegistry;
use airlock_daemon::config::{self, Config};
use airlock_daemon::doctor;
use airlock_daemon::hooks::HookResolver;
use airlock_daemon::logging::AuditLogger;
use airlock_daemon::paths::{AgentPaths, DaemonPaths};
use airlock_daemon::registration;
use airlock_daemon::test;
use airlock_daemon::{
    bind_profile_socket, run_daemon, ConcurrencyLocks, MountCache, ProfileEntry, ProfileMap,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::sync::RwLock;

fn load_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.load_builtins();
    registry
}

fn require_enabled_commands(paths: &DaemonPaths) -> (Config, HashSet<String>) {
    let app_config = Config::load(&paths.config_dir);
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
    registry
}

fn load_agents_or_exit(path: &std::path::Path) -> Vec<registration::AgentRegistration> {
    registration::load_registration(path).unwrap_or_else(|e| {
        eprintln!("airlock: {e}");
        std::process::exit(1);
    })
}

fn load_agent_overrides_from_registrations(
    registrations: &[registration::AgentRegistration],
    registry: &mut CommandRegistry,
    enabled: &HashSet<String>,
) {
    for reg in registrations {
        let agent = AgentPaths::new(reg.path.clone());
        let cmds_dir = agent.commands_dir();
        if cmds_dir.is_dir() {
            registry.load_agent_overrides(&reg.name, &cmds_dir, Some(enabled));
        }
    }
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

#[tokio::main]
async fn main() {
    let raw_args: Vec<String> = env::args().collect();

    let agents_path: Option<PathBuf> = raw_args
        .windows(2)
        .find(|w| w[0] == "--agents")
        .map(|w| PathBuf::from(&w[1]));

    let config_flag: Option<PathBuf> = raw_args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| PathBuf::from(&w[1]));

    let sockets_flag: Option<PathBuf> = raw_args
        .windows(2)
        .find(|w| w[0] == "--sockets")
        .map(|w| PathBuf::from(&w[1]));

    let paths = match (&config_flag, &sockets_flag) {
        (Some(config), Some(sockets)) => DaemonPaths {
            config_dir: config.clone(),
            sockets_dir: sockets.clone(),
        },
        (None, None) => DaemonPaths::detect(),
        _ => {
            eprintln!("airlock: --config and --sockets must both be provided, or neither");
            std::process::exit(1);
        }
    };

    let args: Vec<String> = {
        let mut filtered = Vec::new();
        let mut skip_next = false;
        for arg in &raw_args {
            if skip_next {
                skip_next = false;
                continue;
            }
            if arg == "--agents" || arg == "--config" || arg == "--sockets" {
                skip_next = true;
                continue;
            }
            filtered.push(arg.clone());
        }
        filtered
    };

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
            let registry = load_registry();
            let commands = registry.command_names();
            eprintln!("airlock: {} built-in commands", commands.len());

            let mut has_errors = false;

            if let Some(ref agents_file) = agents_path {
                let registrations = match registration::load_registration(agents_file) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("airlock: {e}");
                        std::process::exit(1);
                    }
                };
                for reg in &registrations {
                    let agent = AgentPaths::new(reg.path.clone());
                    match agent.load_profile() {
                        Ok(_) => eprintln!("  agent {}: profile ok", reg.name),
                        Err(e) => {
                            eprintln!("  agent {}: profile error — {e}", reg.name);
                            has_errors = true;
                        }
                    }
                    let cmds_dir = agent.commands_dir();
                    if cmds_dir.is_dir() {
                        if let Ok(entries) = std::fs::read_dir(&cmds_dir) {
                            for entry in entries.flatten() {
                                let path = entry.path();
                                if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                                    continue;
                                }
                                let name = path.file_stem().unwrap().to_string_lossy();
                                let content = match std::fs::read_to_string(&path) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        eprintln!("  agent {}: error: {name} — {e}", reg.name);
                                        has_errors = true;
                                        continue;
                                    }
                                };
                                match airlock_daemon::commands::CommandModule::parse(&content) {
                                    Ok(_) => eprintln!("  agent {}: ok: {name}", reg.name),
                                    Err(e) => {
                                        eprintln!("  agent {}: error: {name} — {e}", reg.name);
                                        has_errors = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if has_errors {
                eprintln!("airlock: validation failed");
                std::process::exit(1);
            } else {
                eprintln!("airlock: all modules valid");
            }
            return;
        }
        "doctor" => {
            let (_, enabled) = require_enabled_commands(&paths);
            let mut registry = load_filtered_registry(&enabled);

            if let Some(ref agents_file) = agents_path {
                if let Ok(registrations) = registration::load_registration(agents_file) {
                    load_agent_overrides_from_registrations(
                        &registrations,
                        &mut registry,
                        &enabled,
                    );
                }
            }

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
            let agent_name = match args.get(2) {
                Some(p) => p,
                None => {
                    eprintln!(
                        "usage: airlock-daemon test --agents <path> <agent> <command> [args...]"
                    );
                    std::process::exit(1);
                }
            };
            let command = match args.get(3) {
                Some(c) => c,
                None => {
                    eprintln!(
                        "usage: airlock-daemon test --agents <path> <agent> <command> [args...]"
                    );
                    std::process::exit(1);
                }
            };
            let cmd_args: Vec<String> = args[4..].to_vec();

            let agents_file = match &agents_path {
                Some(p) => p,
                None => {
                    eprintln!("airlock: --agents flag required for test subcommand");
                    std::process::exit(1);
                }
            };
            let registrations = load_agents_or_exit(agents_file);
            let reg = match registrations.iter().find(|r| r.name == *agent_name) {
                Some(r) => r,
                None => {
                    eprintln!(
                        "airlock: agent '{agent_name}' not found in {}",
                        agents_file.display()
                    );
                    std::process::exit(1);
                }
            };
            let agent = AgentPaths::new(reg.path.clone());
            let profile = agent.load_profile().unwrap_or_else(|e| {
                eprintln!("airlock: {e}");
                std::process::exit(1);
            });

            let (_, enabled) = require_enabled_commands(&paths);
            let mut registry = load_filtered_registry(&enabled);
            load_agent_overrides_from_registrations(
                std::slice::from_ref(reg),
                &mut registry,
                &enabled,
            );

            let result = test::evaluate(
                agent_name,
                &profile,
                command,
                &cmd_args,
                &enabled,
                &registry,
                &agent.hooks_dir(),
                Some(agent_name),
            );
            test::print_result(&result);

            let static_allowed = result.outcome == "ALLOWED";
            eprintln!();
            let live = test::check_live(
                agent_name,
                command,
                &cmd_args,
                &paths.sockets_dir,
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
                    let registrations = match &agents_path {
                        Some(p) => load_agents_or_exit(p),
                        None => {
                            eprintln!("no agents registered (use --agents flag)");
                            std::process::exit(0);
                        }
                    };
                    let sock_dir = &paths.sockets_dir;
                    for reg in &registrations {
                        let sock = sock_dir.join(format!("{}.sock", reg.name));
                        println!("{}\t{}", reg.name, sock.display());
                    }
                    if registrations.is_empty() {
                        eprintln!("no agents in registration file");
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
                    let registrations = match &agents_path {
                        Some(p) => load_agents_or_exit(p),
                        None => {
                            eprintln!("airlock: --agents flag required");
                            std::process::exit(1);
                        }
                    };
                    let reg = match registrations.iter().find(|r| r.name == *name) {
                        Some(r) => r,
                        None => {
                            eprintln!("airlock: agent '{name}' not found in registration file");
                            std::process::exit(1);
                        }
                    };
                    let agent = AgentPaths::new(reg.path.clone());
                    match std::fs::read_to_string(agent.profile_path()) {
                        Ok(content) => print!("{content}"),
                        Err(e) => {
                            eprintln!("failed to read profile for agent '{name}': {e}");
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
            eprintln!("usage: airlock-daemon <start|version|init|check|doctor|test|show|profile>");
            std::process::exit(1);
        }
    }

    // Load agents from registration file
    let registrations = match &agents_path {
        Some(p) => load_agents_or_exit(p),
        None => Vec::new(),
    };

    let mut profile_map: HashMap<String, ProfileEntry> = HashMap::new();
    for reg in &registrations {
        let agent = AgentPaths::new(reg.path.clone());
        let profile = agent.load_profile().unwrap_or_else(|e| {
            eprintln!("airlock: agent '{}': {e}", reg.name);
            std::process::exit(1);
        });
        profile_map.insert(
            reg.name.clone(),
            ProfileEntry {
                profile,
                agent_name: Some(reg.name.clone()),
            },
        );
    }

    if profile_map.is_empty() {
        eprintln!("airlock: no agents registered — daemon started with no active sockets");
    }

    // Bind sockets
    let sock_dir = &paths.sockets_dir;
    if let Err(e) = std::fs::create_dir_all(sock_dir) {
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

    let (app_config, enabled_commands) = require_enabled_commands(&paths);
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
    let mut registry = load_filtered_registry(&enabled_commands);
    let mut hook_resolver = HookResolver::new();

    load_agent_overrides_from_registrations(&registrations, &mut registry, &enabled_commands);
    for reg in &registrations {
        let agent = AgentPaths::new(reg.path.clone());
        hook_resolver.add_agent(reg.name.clone(), agent.hooks_dir());
    }

    eprintln!(
        "airlock: enabled commands: {}",
        registry.command_names().join(", ")
    );
    let registry = Arc::new(registry);
    let cmd_locks: ConcurrencyLocks = Arc::new(RwLock::new(HashMap::new()));
    let hook_resolver = Arc::new(hook_resolver);

    run_daemon(
        listeners,
        profiles,
        mount_cache,
        registry,
        cmd_locks,
        hook_resolver,
        logger,
    )
    .await;
}
