# CLAUDE.md — Airlock Project Guide

This file is the source of truth for the airlock project. Every Claude Code session must read and follow this document. Do not deviate from the architecture, naming, file paths, or design decisions described here without explicit approval.

## What is Airlock?

Airlock is an open-source CLI proxy that isolates Docker container credentials by proxying commands over a unix socket. Containers never hold SSH keys, API tokens, or credential files. Instead, a lightweight shim intercepts CLI commands inside the container and delegates execution to a daemon where real credentials live. The daemon runs on the host (local) or as a shared container (remote compose/k8s).

Airlock is written in Rust. This choice is deliberate — the daemon sits on a security trust boundary, receives untrusted input from containers, and executes commands with real credentials. Rust's type system encodes validation state at compile time, making it structurally impossible to bypass security checks.

## Architecture

Three components:

1. **Container-side shim** (`airlock-shim`) — a single static binary inside the container
2. **Daemon** (`airlock-daemon`) — a long-running process on the host (local) or a shared container (remote compose/k8s)
3. **Command directory** — TOML-based modules defining how each CLI tool is proxied

## Design Principles

- **Unopinionated.** Airlock proxies commands and gets out of the way. Policy enforcement lives in user-defined hooks, not in airlock itself.
- **Pluggable.** Community-contributed command modules. Users can add their own without submitting a PR.
- **Secure by default.** Built-in command modules ship with conservative deny rules. Unknown commands are rejected. The command directory is an allowlist.
- **Zero config where possible.** CWD mapping is automatic via docker inspect. No env vars, no path maps.

## Protocol

JSON-RPC 2.0 over NDJSON (newline-delimited JSON) on a unix socket.

### Request (shim → daemon)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "exec",
  "params": {
    "command": "git",
    "args": ["push", "origin", "main"],
    "cwd": "/workspace",
    "container_id": "7a0144cee1256c539fab790199527b7051aff1b603ebcf7ed3fd436440ef3b3a"
  }
}
```

### Output streaming (daemon → shim)

Output is streamed in real time as JSON-RPC 2.0 notifications (no `id` field). This prevents agent framework timeouts on long-running commands.

```json
{"jsonrpc": "2.0", "method": "output", "params": {"stream": "stdout", "data": "Enumerating objects: 5, done.\n"}}
{"jsonrpc": "2.0", "method": "output", "params": {"stream": "stderr", "data": "remote: Counting objects: 100%\n"}}
```

### Final response (daemon → shim)

Success:
```json
{"jsonrpc": "2.0", "id": 1, "result": {"exit_code": 0}}
```

Denied by airlock:
```json
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32600, "message": "denied: --upload-pack not permitted"}}
```

Unknown command:
```json
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "unknown command: kubectl"}}
```

The shim reads lines from the socket. Notifications get printed immediately to the correct stream. The final response (matched by `id`) triggers exit with the returned exit code.

## Agents

Each agent has its own working directory containing an `airlock.toml` profile and optional `commands/` and `hooks/` subdirectories. The daemon learns about agents by reading a TOML registration file provided via the `--agents` CLI flag.

### Agent directory layout

```
my-agent/
├── airlock.toml          # required — profile for this agent
├── commands/             # optional — per-agent command overrides
│   └── git.toml
└── hooks/                # optional — per-agent hooks
    └── pre-exec
```

### Registration file

```toml
[my-agent]
path = "/home/admin/agents/my-agent"

[dev-agent]
path = "/home/admin/agents/dev-agent"
```

Each key is the agent name. `path` points to the agent's working directory. The daemon validates that every path exists and contains an `airlock.toml` at startup — it refuses to start if any is missing.

### Profile TOML (`airlock.toml`)

```toml
commands = ["git", "gh"]

[env]
set = { GIT_SSH_COMMAND = "ssh -i ~/.ssh/project_a_key" }
```

`commands` is required. Use `commands = []` to allow all commands. `env` is optional. An empty file without `commands` is rejected at startup.

### Env Merge Order

1. **Command module `[env] strip`** — removes dangerous vars (always wins)
2. **Profile `[env] set`** — injects credentials
3. **Command module `[env] set`** — injects hardening (wins over profile)

### Socket-per-agent

The daemon creates one socket per registered agent at startup. Mapping: agent name → `sockets/<name>.sock`. If no `--agents` flag is provided, the daemon starts with zero agents and zero sockets.

## Socket Paths

| Location | Path |
|----------|------|
| Inside container (hardcoded) | `/run/docker-airlock.sock` |
| Host (all platforms) | `~/.config/airlock/sockets/<agent>.sock` |

Docker volume mount (example agent `my-agent`):
```
-v ~/.config/airlock/sockets/my-agent.sock:/run/docker-airlock.sock
```

## Container-Side Shim

Single static Rust binary using the busybox pattern. Reads `argv[0]` to determine which command is being proxied. Installed via plain symlinks in the user's Dockerfile:

```dockerfile
COPY airlock-shim /usr/local/airlock/bin/airlock-shim
RUN chmod +x /usr/local/airlock/bin/airlock-shim
ENV PATH="/usr/local/airlock/bin:$PATH"
RUN ln -s airlock-shim /usr/local/airlock/bin/git \
    && ln -s airlock-shim /usr/local/airlock/bin/terraform \
    && ln -s airlock-shim /usr/local/airlock/bin/aws
```

Real tools should NOT be installed in the container. If they are, PATH ordering ensures the shim wins (`/usr/local/airlock/bin` is prepended to PATH).

The shim does NOT hide airlock's identity. Error messages clearly identify airlock so agents can interpret denials correctly (e.g., `airlock: denied — terraform destroy not permitted`).

### Container ID detection

The shim reads `/proc/self/mountinfo` and parses lines containing `/docker/containers/<64-char-hex>/` to extract its own container ID. This is sent in every request to enable automatic CWD mapping.

## Daemon

Long-running process on the host (managed by systemd/launchd) or a shared container (managed by compose/k8s).

### Responsibilities

1. Listen on the unix socket
2. Accept connections, spawn a tokio async task per connection
3. Parse JSON-RPC requests
4. Look up the command in the command directory (reject unknown commands)
5. Apply deny rules, env stripping/injection, and arg appending from the TOML module
6. Run pre-exec hook if present
7. Resolve host-side CWD via docker inspect (cached per container ID)
8. Execute the command via `execve` with an explicit arg array — **never through a shell**
9. Stream stdout/stderr as JSON-RPC notifications
10. Run post-exec hook if present (can modify output before it reaches the agent)
11. Send final response with exit code
12. Log the request to the audit log

### CWD Mapping

Zero configuration. The daemon receives `container_id` and `cwd` from the shim. It calls `docker inspect <container_id>` to get volume mount mappings, then translates the container path to the host path by prefix matching. Mount mappings are cached per container ID. This works identically on Linux and macOS Docker Desktop.

### Concurrency

Commands run concurrently by default (one tokio task per connection). Individual command modules can set `concurrent = false` in their TOML to serialize execution (e.g., terraform).

### Shutdown

No graceful shutdown logic. The process exits on SIGTERM. systemd/launchd handle restart.

## Command Directory

TOML file per command. Built-in modules are compiled into the binary and versioned with the daemon. Modules are opt-in — only commands listed in `commands.enable` in `config.toml` are loaded at startup. Each agent can optionally have a `commands/` directory with per-agent overrides that completely replace the built-in for that agent (full replace, no merging).

### TOML Schema

Deny mode — block these, allow everything else:
```toml
[command]
bin = "git"

[deny]
args = ["--upload-pack", "-u", "--config", "-c", "--exec-path"]

[env]
strip = ["GIT_SSH_COMMAND", "GIT_CONFIG", "GIT_CONFIG_GLOBAL"]
set = { GIT_CONFIG_NOSYSTEM = "1" }

[args]
append = ["--config", "core.hooksPath=/dev/null"]

[exec]
concurrent = true
```

Allow mode — permit these, block everything else:
```toml
[command]
bin = "aws"

[allow]
args = ["s3", "sts", "ecr", "ecs", "ssm", "logs"]
```

A module must have exactly one of `[allow]` or `[deny]`. Both present is an error. Neither present is an error. Both sections use the same `args` format — same parsing, same rule types (plain args, sequences with `&`, flag-value patterns with `=`).

### Schema reference

| Section | Field | Type | Description |
|---------|-------|------|-------------|
| `[command]` | `bin` | string | The executable name on the host |
| `[deny]` | `args` | string array | Patterns matched against the args array. If any arg matches, the request is denied. Mutually exclusive with `[allow]`. |
| `[allow]` | `args` | string array | Patterns matched against the args array. If any arg matches, the request is allowed. No match means denied. Mutually exclusive with `[deny]`. |
| `[env]` | `strip` | string array | Environment variable names to remove before execution |
| `[env]` | `set` | key-value map | Environment variables to inject before execution |
| `[args]` | `append` | string array | Args appended to every invocation of this command |
| `[exec]` | `concurrent` | bool (default: true) | If false, only one instance of this command runs at a time |

### Unknown commands

Rejected. The command directory is an allowlist. If a command has no module (built-in or agent override), the daemon returns a JSON-RPC error.

### Inspecting modules

- `airlock show <cmd>` — prints the built-in module for a command

## Hooks

Executable files in the agent's `hooks/` directory. Can be written in any language. Each agent has its own hooks — there are no global hooks.

### pre-exec

Receives the full JSON-RPC request on stdin. Decides whether to allow or reject.

| Exit code | Stdout | Behavior |
|-----------|--------|----------|
| 0 | empty | Proceed with original request |
| 0 | modified JSON | Proceed with modified request |
| non-zero | optional error JSON | Reject the request |

### post-exec

Receives the full JSON-RPC response on stdin. Can modify output before it reaches the agent.

| Exit code | Stdout | Behavior |
|-----------|--------|----------|
| 0 | empty | Pass through original response |
| 0 | modified JSON | Send modified response to agent |
| non-zero | ignored | Send original response |

Post-exec can be used for output redaction/sanitization, audit logging, or notifications. Airlock does not ship sanitization logic — that is the user's responsibility via hooks.

## Logging

NDJSON file at `~/.local/share/airlock/airlock.log` with size-based rotation.

Every request is logged (allowed and denied):
```json
{
  "ts": "2026-03-17T14:32:01Z",
  "id": 1,
  "profile": "agent-a",
  "event": "exec",
  "command": "git",
  "args": ["push", "origin", "main"],
  "cwd": "/workspace",
  "exit_code": 0,
  "duration_ms": 1200,
  "outcome": "allowed"
}
```

Denied request:
```json
{
  "ts": "2026-03-17T14:32:05Z",
  "id": 2,
  "profile": "readonly-agent",
  "event": "exec",
  "command": "terraform",
  "args": ["destroy"],
  "cwd": "/workspace",
  "exit_code": null,
  "duration_ms": 0,
  "outcome": "denied",
  "reason": "denied arg: destroy"
}
```

Structured for SIEM/Splunk ingestion. Airlock does not own export — it writes the file, users pipe it wherever they want.

## `airlock init`

Single command that sets up the host. Idempotent — safe to run multiple times.

1. Creates directory structure: `~/.config/airlock/`, `~/.config/airlock/sockets/`, `~/.local/share/airlock/`
2. Installs systemd user unit (Linux) or launchd plist (macOS), optionally with `--agents <path>`
3. Enables and starts the daemon
4. Prints the socket directory path

On version upgrade, `airlock init` updates the service definition but never touches config.toml.

## `airlock doctor`

Checks external state that airlock depends on but does not control. Two categories:

1. **Commands** — for each command in `commands.enable`, resolves the binary on PATH. Reports found (with full path) or not found.
2. **Docker** — checks if `docker` is on PATH, if the daemon is running, and warns about Docker Desktop on macOS (VirtioFS socket permission remapping).

Exit code 0 if no failures, 1 if any binary is missing.

## `airlock test`

Dry-runs a command through the evaluation pipeline without executing it. Two phases:

**Phase 1 (static):** Walks the four decision steps using config and profile files on disk:
1. **Command enabled?** — is the command in `commands.enable`?
2. **Module found?** — built-in or agent override? (informational, never denies independently)
3. **Policy rules?** — normalized args evaluated against deny or allow rules
4. **Profile allows?** — is the command in the profile's `commands` list?

**Phase 2 (live):** Connects to the daemon's socket and sends a `check` request. Confirms the daemon's decision matches the static analysis.

Usage: `airlock-daemon test --agents <path> <agent> <command> [args...]`

Exit code 0 if allowed (and live agrees or skipped), 1 if denied or mismatch.

## Configuration

File at `~/.config/airlock/config.toml`. The `[commands]` section is required — the daemon exits on startup if `commands.enable` is missing or empty.

```toml
[commands]
enable = ["git", "terraform"]

[daemon]
socket = "/var/run/docker-airlock.sock"
log_level = "info"

[log]
path = "~/.local/share/airlock/airlock.log"
max_size_mb = 50
max_files = 5
```

Only commands in `enable` are loaded. Requests for other commands return "unknown command" regardless of profile configuration. `airlock init` generates a starter config with a commented-out example.

## Directory Layout

### Daemon directories

```
~/.config/airlock/
├── config.toml              # required — commands.enable list
└── sockets/                 # one socket per agent, created by daemon
    ├── my-agent.sock
    └── dev-agent.sock

~/.local/share/airlock/
└── airlock.log              # NDJSON audit log with rotation
```

### Agent directory (one per agent, at any path)

```
/path/to/my-agent/
├── airlock.toml             # required — profile for this agent
├── commands/                # optional — per-agent command overrides
│   └── git.toml
└── hooks/                   # optional — per-agent hooks
    ├── pre-exec
    └── post-exec
```

### Registration file (passed via `--agents` flag)

```toml
[my-agent]
path = "/path/to/my-agent"

[dev-agent]
path = "/path/to/dev-agent"
```

## Distribution

Both binaries published as GitHub release artifacts per platform (linux-amd64, linux-arm64, darwin-amd64, darwin-arm64). Musl static builds also published for container images.

Host install (local deployment):
```
curl -fsSL https://raw.githubusercontent.com/<user>/airlock/main/install.sh | sh
```

Container images (remote deployment):
- `ghcr.io/<user>/airlock-daemon:latest` — daemon image (scratch + static musl binary)
- `ghcr.io/<user>/airlock-shim:latest` — shim image (scratch + static musl binary)

Start the daemon with agents: `airlock-daemon start --agents /path/to/agents.toml`

## Security Invariants

These must never be violated:

1. **The daemon never passes args through a shell.** Always `Command::new(bin).arg(x).arg(y)` — never `sh -c "..."`.
2. **Unknown commands are rejected.** The command directory is an allowlist.
3. **The container never holds credentials.** No SSH keys, no tokens, no credential files mounted in.
4. **The shim identifies itself in errors.** Agents must be able to distinguish airlock denials from command failures.
5. **Agent overrides are full replace.** No merging of TOML modules. The active config is always exactly one source.
6. **Built-in modules are compiled into the binary.** They upgrade with the daemon. No stale files on disk.

## What Airlock Is NOT

- **Not a workflow engine.** It denies or allows. Approval flows (human-in-the-loop) belong to the agent framework.
- **Not a sanitizer.** Post-exec hooks can redact output, but airlock ships no redaction logic.
- **Not a framework.** It is a single-purpose proxy. No opinions on agent architecture.
- **Not a timeout manager.** Commands run until they finish. No artificial timeouts or output size limits.

## Lints

Workspace-wide lint configuration lives in the root `Cargo.toml` under `[workspace.lints]`. Individual crates inherit via `[lints] workspace = true`. Do not add lint attributes (`#![deny(...)]`, `#![warn(...)]`) in source files.

After any refactor, run `cargo clippy --workspace` and fix all warnings before committing. Dead code, unused imports, and unused variables are denied (compile errors, not warnings).

## Implementation Phases

1. **Core IPC** — shim + daemon + git hardcoded. Prove the socket works end-to-end with streaming.
2. **Command directory** — TOML parsing, built-in modules, deny/env/args/exec rules, per-agent overrides.
3. **Hooks** — pre-exec and post-exec executable hooks with stdin/stdout interface.
4. **`airlock init`** — directory setup, systemd/launchd service installation, idempotent upgrades.
5. **Logging** — NDJSON audit log with rotation.
6. **Distribution** — GitHub Actions CI, release artifacts, install script.

Build each phase completely before moving to the next. Do not mix phases. Each phase should compile, run, and be testable independently.