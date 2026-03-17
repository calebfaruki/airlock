use airlock_shim::{
    build_request, command_from_argv0, dispatch_output, parse_container_id, OutputTarget, Response,
};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process;

const DEFAULT_SOCKET_PATH: &str = "/run/docker-airlock.sock";

fn socket_path() -> String {
    env::var("AIRLOCK_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET_PATH.to_string())
}

fn detect_container_id() -> Option<String> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    parse_container_id(&content)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let command = match command_from_argv0(&args[0]) {
        Some(cmd) => cmd,
        None => {
            eprintln!("usage: create a symlink to airlock-shim named after the command to proxy");
            eprintln!("  ln -s airlock-shim /usr/local/airlock/bin/git");
            process::exit(1);
        }
    };

    let cmd_args: Vec<String> = args[1..].to_vec();

    let cwd = env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "/".to_string());

    let container_id = detect_container_id();

    let request = build_request(command, cmd_args, cwd, container_id);

    let sock = socket_path();
    let mut stream = match UnixStream::connect(&sock) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("airlock: cannot connect to daemon at {sock}: {e}");
            process::exit(1);
        }
    };

    let mut payload = serde_json::to_string(&request).expect("failed to serialize request");
    payload.push('\n');

    if let Err(e) = stream.write_all(payload.as_bytes()) {
        eprintln!("airlock: failed to send request: {e}");
        process::exit(1);
    }

    let reader = BufReader::new(stream);
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("airlock: daemon connection lost: {e}");
                process::exit(1);
            }
        };

        if line.is_empty() {
            continue;
        }

        let resp: Response = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.method.as_deref() == Some("output") {
            if let Some(params) = resp.params {
                match dispatch_output(&params.stream, &params.data) {
                    OutputTarget::Stdout(data) => {
                        let mut out = stdout.lock();
                        let _ = out.write_all(data.as_bytes());
                        let _ = out.flush();
                    }
                    OutputTarget::Stderr(data) => {
                        let mut out = stderr.lock();
                        let _ = out.write_all(data.as_bytes());
                        let _ = out.flush();
                    }
                    OutputTarget::Ignored => {}
                }
            }
            continue;
        }

        if let Some(result) = resp.result {
            process::exit(result.exit_code);
        }

        if let Some(error) = resp.error {
            eprintln!("airlock: error — {}", error.message);
            process::exit(1);
        }
    }

    eprintln!("airlock: daemon disconnected before sending response");
    process::exit(1);
}
