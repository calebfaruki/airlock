# Airlock

Credential isolation for CLI tools in Docker containers. Proxies git, aws, terraform, and other commands that need SSH keys, cloud configs, or local credentials  without mounting secrets into the container.

## How It Works

Three components:

1. **Container-side shim** — a single static binary inside the container. Reads `argv[0]` to determine which command is being proxied (busybox pattern). Installed via symlinks in the user's Dockerfile.

2. **Host-side daemon** — a long-running process on the host. Listens on a unix socket, receives JSON-RPC requests from the shim, executes commands with real credentials, and streams output back.

3. **Command directory** — TOML-based modules defining how each CLI tool is proxied. Built-in modules ship with conservative deny rules. Unknown commands are rejected.

The shim sends a request, the daemon looks it up in the command directory, applies deny rules and environment isolation, executes the command, and streams output back. The container never sees credentials — they live on the host.

## Why Airlock?

Network-level credential proxies (Docker Sandboxes, NemoClaw) protect HTTP API keys by intercepting outbound HTTPS requests and injecting auth headers. But many developer tools don't authenticate over HTTP — they use local files:

- **git** — SSH keys, credential helpers
- **aws / gcloud / az** — IAM credentials, service account keys
- **terraform** — inherits cloud CLI credentials
- **docker push/pull** — registry auth in `~/.docker/config.json`
- **kubectl / helm** — kubeconfig with cluster certificates
- **npm / pip / cargo** — registry tokens for private packages
- **ssh / scp** — SSH keys

These tools authenticate via files on the host filesystem. No network proxy can intercept that. Airlock solves this by proxying the CLI commands themselves — the container asks the host to run the command, and the host executes it with real credentials. The container never sees the keys.

Use network proxies for HTTP API keys. Use Airlock for everything else.

## Installation

### Quick Install (Linux/macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/calebfaruki/airlock/main/install.sh | sh
```

This downloads the daemon, installs it to `~/.local/bin/`, and runs `airlock init` to set up the system service.

### Container Setup

Download the shim from [releases](https://github.com/calebfaruki/airlock/releases) and add to your Dockerfile:

```dockerfile
ADD https://github.com/calebfaruki/airlock/releases/latest/download/airlock-shim-linux-amd64 \
    /usr/local/airlock/bin/airlock-shim
RUN chmod +x /usr/local/airlock/bin/airlock-shim
ENV PATH="/usr/local/airlock/bin:$PATH"
RUN ln -s airlock-shim /usr/local/airlock/bin/git \
    && ln -s airlock-shim /usr/local/airlock/bin/terraform \
    && ln -s airlock-shim /usr/local/airlock/bin/aws
```

### Docker Run

```sh
docker run \
    -v /var/run/docker-airlock.sock:/run/docker-airlock.sock \
    your-image
```

On macOS, use `~/.config/airlock/docker-airlock.sock` as the host path.

### macOS Note

The launchd service inherits a minimal PATH (`/usr/bin:/bin:/usr/sbin:/sbin`). Tools installed via Homebrew, nix, or cargo won't be found by default. Use absolute paths in command modules:

```toml
[command]
bin = "/opt/homebrew/bin/gh"
```

Run `airlock-daemon check` to validate all modules before restarting the daemon.

## Usage

### Daemon

```sh
airlock-daemon start             # Run daemon in foreground
airlock-daemon init              # Install as system service (systemd/launchd)
airlock-daemon init --uninstall  # Remove system service
airlock-daemon check             # Validate all command modules
airlock-daemon version           # Print version
```

### Command Directory

```sh
airlock-daemon show git     # Print active module (built-in or user override)
airlock-daemon diff git     # Compare user override vs built-in
airlock-daemon eject git    # Copy built-in to ~/.config/airlock/commands/ for editing
```

### Hooks

Place executable scripts in `~/.config/airlock/hooks/`:

- `pre-exec` — receives the JSON-RPC request on stdin. Exit 0 to allow, non-zero to deny. Write modified JSON to stdout to rewrite the request.
- `post-exec` — receives the JSON-RPC response on stdin. Exit 0 with modified JSON on stdout to alter output. Non-zero exit passes through the original response.

### Logging

Every request is logged to `~/.local/share/airlock/airlock.log` as NDJSON. Configure rotation in `~/.config/airlock/config.toml`:

```toml
[log]
path = "~/.local/share/airlock/airlock.log"
max_size_mb = 50
max_files = 5
```

## Built-in Commands

Airlock ships with modules for: `git`, `terraform`, `aws`, `ssh`, `docker`. Each has conservative deny rules. Run `airlock-daemon show <command>` to see the active configuration.

Unknown commands are rejected. To add a new command, create a TOML file in `~/.config/airlock/commands/`:

```toml
[command]
bin = "deploy-cli"
```

## Built-in Protections

Built-in command modules ship with security hardening based on known attack vectors. Each module has a [`SECURITY.md`](crates/airlock-daemon/src/commands/builtins/) documenting the threat model behind every deny rule and environment variable.

Run `airlock-daemon show <command>` to see the active configuration. Run `airlock-daemon eject <command>` to customize.

## Observability

On startup, the daemon prints loaded commands and any user overrides to stderr:

```
airlock: loaded commands: aws, docker, gh, git, ssh, terraform
airlock: user overrides: gh
```

If a command fails because the binary isn't found, the error message hints at using an absolute path — the most common issue on macOS where launchd has a minimal PATH.

Run `airlock-daemon check` before restarting to catch TOML syntax errors and missing binaries early.

## Security Model

- The daemon never passes arguments through a shell — always `execve` with an explicit arg array.
- Unknown commands are rejected. The command directory is an allowlist.
- The container never holds credentials.
- User overrides are full replace — no merging with built-ins.
- Built-in modules are compiled into the binary and upgrade with the daemon.
