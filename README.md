# Airlock

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/calebfaruki/airlock/badge)](https://securityscorecards.dev/viewer/?uri=github.com/calebfaruki/airlock)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12214/badge)](https://www.bestpractices.dev/projects/12214)
[![made-with-rust](https://img.shields.io/badge/Made%20with-Rust-1f425f.svg)](https://www.rust-lang.org/)

Credential isolation for CLI tools in Docker containers. Proxies git, aws, terraform, and other commands that need SSH keys, cloud configs, or local credentials  without mounting secrets into the container.

## How It Works

Three components:

1. **Container-side shim** — a single static binary inside the container. Reads `argv[0]` to determine which command is being proxied (busybox pattern). Installed via symlinks in the user's Dockerfile.

2. **Daemon** — a long-running process on the host (local) or a shared container (remote compose/k8s). Listens on a unix socket, receives JSON-RPC requests from the shim, executes commands with real credentials, and streams output back.

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

### Local Install (Linux/macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/calebfaruki/airlock/main/install.sh | sh
```

This downloads the daemon, installs it to `~/.local/bin/`, and runs `airlock init` to set up the system service.

### Remote Deployment

For Docker Compose or Kubernetes deployments, use the daemon container image:

```sh
docker pull ghcr.io/calebfaruki/airlock-daemon:latest
```

### Container Setup

Copy the shim from the container image or download from [releases](https://github.com/calebfaruki/airlock/releases):

```dockerfile
COPY --from=ghcr.io/calebfaruki/airlock-shim:latest /airlock-shim /usr/local/airlock/bin/airlock-shim
RUN chmod +x /usr/local/airlock/bin/airlock-shim
ENV PATH="/usr/local/airlock/bin:$PATH"
RUN ln -s airlock-shim /usr/local/airlock/bin/git \
    && ln -s airlock-shim /usr/local/airlock/bin/terraform \
    && ln -s airlock-shim /usr/local/airlock/bin/aws
```

### Agent Configuration

Each agent has its own working directory containing an `airlock.toml` profile:

```
my-agent/
├── airlock.toml          # required — profile
├── commands/             # optional — per-agent command overrides
└── hooks/                # optional — per-agent hooks
```

```sh
mkdir -p my-agent
cat > my-agent/airlock.toml << 'EOF'
commands = ["git", "gh"]

[env]
set = { GIT_SSH_COMMAND = "ssh -i ~/.ssh/project_a_key" }
EOF
```

Register agents in a TOML file:

```toml
# agents.toml
[my-agent]
path = "/home/admin/agents/my-agent"
```

Start the daemon with: `airlock-daemon start --agents agents.toml`

### Docker Run (Local)

Mount the agent's socket into the container. The shim connects to `/run/docker-airlock.sock` inside the container.

```sh
docker run \
    -v ~/.config/airlock/sockets/my-agent.sock:/run/docker-airlock.sock \
    your-image
```

### Docker Compose (Remote)

The daemon and agent run as containers sharing a socket volume:

```yaml
services:
  airlock:
    image: ghcr.io/calebfaruki/airlock-daemon:latest
    command: ["start", "--config", "/etc/airlock", "--sockets", "/run/airlock/sockets", "--agents", "/etc/airlock/agents.toml"]
    volumes:
      - sockets:/run/airlock/sockets
      - ./agents.toml:/etc/airlock/agents.toml:ro
      - ./agents:/agents:ro

  my-agent:
    image: your-agent-image
    volumes:
      - sockets:/run/airlock/sockets

volumes:
  sockets:
```

## Usage

### Daemon

```sh
airlock-daemon start --agents agents.toml  # Local: start with registered agents
airlock-daemon start --config /etc/airlock --sockets /run/sockets --agents agents.toml  # Container
airlock-daemon start                       # Start with zero agents
airlock-daemon init                        # Install as system service (systemd/launchd)
airlock-daemon init --uninstall            # Remove system service
airlock-daemon check --agents agents.toml  # Validate builtins + agent configs
airlock-daemon doctor --agents agents.toml # Check host binaries and Docker
airlock-daemon test --agents agents.toml my-agent git push  # Dry-run evaluation
airlock-daemon version                     # Print version
airlock-daemon show git                    # Print built-in module
airlock-daemon profile list --agents agents.toml   # List agents and sockets
airlock-daemon profile show --agents agents.toml my-agent  # Print agent profile
```

### Hooks

Place executable scripts in the agent's `hooks/` directory:

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

## Enabling Commands

Command modules are opt-in. List the commands your agents need in `~/.config/airlock/config.toml`:

```toml
[commands]
enable = ["git", "terraform"]
```

The daemon exits on startup if `commands.enable` is missing or empty. Only enabled commands are loaded — requests for anything else return "unknown command".

Airlock ships with built-in modules for: `git`, `terraform`, `aws`, `ssh`, `docker`. Each has conservative deny rules. Run `airlock-daemon show <command>` to see the active configuration.

To add a custom command or override a built-in, create a TOML file in the agent's `commands/` directory and add the name to `commands.enable`:

```toml
# my-agent/commands/deploy-cli.toml
[command]
bin = "deploy-cli"

[deny]
args = []
```

### Three-Layer Security Model

Three independent layers restrict what an agent can do:

1. **Daemon module list** (`commands.enable`) — ceiling that no profile can exceed
2. **Profile `commands` list** — per-container restriction within the ceiling
3. **Deny rules** — per-module restriction on flags and arguments

Each layer is independent. A mistake in one layer doesn't compromise the others.

> **SSH requires extra caution.** SSH is remote code execution on external servers. See [`ssh/SECURITY.md`](crates/airlock-daemon/src/commands/builtins/ssh/SECURITY.md) before enabling it.

## Built-in Protections

Built-in command modules ship with security hardening based on known attack vectors. Each module has a [`SECURITY.md`](crates/airlock-daemon/src/commands/builtins/) documenting the threat model behind every deny rule and environment variable.

Run `airlock-daemon show <command>` to see the active configuration. To customize, add a `commands/<name>.toml` to the agent's directory.

## Observability

On startup, the daemon prints loaded commands to stderr:

```
airlock: enabled commands: git, terraform
```

Run `airlock-daemon check --agents agents.toml` before restarting to catch TOML syntax errors and missing binaries early.

## Agents

Each agent has its own working directory registered via a TOML file passed with `--agents`. The daemon creates one socket per agent at `~/.config/airlock/sockets/<agent>.sock`.

### Profile Schema (`airlock.toml`)

```toml
# Required: allowlist of commands. Use [] to allow all.
commands = ["git", "gh"]

# Optional: environment variables injected before command execution.
[env]
set = { GIT_SSH_COMMAND = "ssh -i ~/.ssh/project_a_key", AWS_PROFILE = "readonly" }
```

The `commands` field is required. Use `commands = []` to allow all commands. An empty file without `commands` is rejected at startup.

### Env Merge Order

Three sources, applied in order:

1. **Command module `[env] strip`** — removes dangerous vars. Always wins.
2. **Profile `[env] set`** — injects credential vars.
3. **Command module `[env] set`** — injects hardening vars. Overrides profile on conflict.

A profile cannot override security hardening set by a command module.

### Socket Paths

| Path |
|------|
| `~/.config/airlock/sockets/<agent>.sock` |

### Zero Agents

The daemon starts with zero agents and zero sockets if no `--agents` flag is provided.

## Upgrading

### From v0.3.x

v0.4.0 replaces `~/.config/airlock/profiles/` with the `--agents` registration file. Create agent directories with `airlock.toml`, write a registration file, and pass it via `--agents`. The `diff` and `eject` subcommands have been removed — agent overrides go in the agent's `commands/` directory.

### From v0.1.x

v0.2.0 requires explicit command enablement. Add `[commands] enable` to `~/.config/airlock/config.toml`.

## Security Model

- The daemon never passes arguments through a shell — always `execve` with an explicit arg array.
- Unknown commands are rejected. The command directory is an allowlist.
- The container never holds credentials.
- Agent overrides are full replace — no merging with built-ins.
- Built-in modules are compiled into the binary and upgrade with the daemon.
