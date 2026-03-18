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

### Create a Profile

Profiles scope credentials to individual containers. Each profile gets its own unix socket. Create at least one before starting the daemon:

```sh
# Minimal profile — all commands, no credential injection
touch ~/.config/airlock/profiles/default.toml

# Restricted profile — only git and gh, with a specific SSH key
cat > ~/.config/airlock/profiles/agent-a.toml << 'EOF'
commands = ["git", "gh"]

[env]
set = { GIT_SSH_COMMAND = "ssh -i ~/.ssh/project_a_key" }
EOF
```

### Docker Run

Mount the profile's socket into the container. The shim always connects to `/run/docker-airlock.sock` inside the container.

Linux:

```sh
docker run \
    -v /run/user/$(id -u)/airlock/sockets/agent-a.sock:/run/docker-airlock.sock \
    your-image
```

Docker Desktop (macOS) — requires `--group-add 0` for non-root container users (VirtioFS remaps socket permissions to `root:root 0660`):

```sh
docker run \
    --group-add 0 \
    -v ~/.config/airlock/sockets/agent-a.sock:/run/docker-airlock.sock \
    your-image
```

## Usage

### Daemon

```sh
airlock-daemon start             # Run daemon in foreground
airlock-daemon init              # Install as system service (systemd/launchd)
airlock-daemon init --uninstall  # Remove system service
airlock-daemon check             # Validate all command modules
airlock-daemon version           # Print version
airlock-daemon profile list      # List profiles and socket paths
airlock-daemon profile show <n>  # Print a profile's TOML
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

Run `airlock-daemon check` before restarting to catch TOML syntax errors and missing binaries early.

## Profiles

Profiles scope credentials to individual containers. Each profile is a TOML file in `~/.config/airlock/profiles/`. The daemon creates one unix socket per profile at startup.

### Schema

```toml
# Optional: whitelist of commands. Omit to allow all.
commands = ["git", "gh"]

# Optional: environment variables injected before command execution.
[env]
set = { GIT_SSH_COMMAND = "ssh -i ~/.ssh/project_a_key", AWS_PROFILE = "readonly" }
```

An empty file is a valid profile — it grants access to all commands with no additional env vars.

### Env Merge Order

Three sources, applied in order:

1. **Command module `[env] strip`** — removes dangerous vars. Always wins.
2. **Profile `[env] set`** — injects credential vars.
3. **Command module `[env] set`** — injects hardening vars. Overrides profile on conflict.

A profile cannot override security hardening set by a command module.

### Socket Paths

| Platform | Path |
|----------|------|
| macOS | `~/.config/airlock/sockets/<profile>.sock` |
| Linux | `$XDG_RUNTIME_DIR/airlock/sockets/<profile>.sock` |

### No Profiles = No Start

The daemon requires at least one profile. If `~/.config/airlock/profiles/` is empty or missing, the daemon refuses to start.

## Upgrading from v1

v1 used a single shared socket. v2 requires profiles:

1. Create at least one profile: `touch ~/.config/airlock/profiles/default.toml`
2. Re-run `airlock init` to create the new directories
3. Update `docker run` commands to mount the profile socket:
   - Linux: `-v /run/user/$(id -u)/airlock/sockets/default.sock:/run/docker-airlock.sock`
   - macOS: `-v ~/.config/airlock/sockets/default.sock:/run/docker-airlock.sock`

## Security Model

- The daemon never passes arguments through a shell — always `execve` with an explicit arg array.
- Unknown commands are rejected. The command directory is an allowlist.
- The container never holds credentials.
- User overrides are full replace — no merging with built-ins.
- Built-in modules are compiled into the binary and upgrade with the daemon.
