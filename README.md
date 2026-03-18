# Airlock

An open-source CLI proxy that isolates Docker container credentials by proxying commands over a unix socket to the host machine. Containers never hold SSH keys, API tokens, or credential files.

## How It Works

Three components:

1. **Container-side shim** — a single static binary inside the container. Reads `argv[0]` to determine which command is being proxied (busybox pattern). Installed via symlinks in the user's Dockerfile.

2. **Host-side daemon** — a long-running process on the host. Listens on a unix socket, receives JSON-RPC requests from the shim, executes commands with real credentials, and streams output back.

3. **Command directory** — TOML-based modules defining how each CLI tool is proxied. Built-in modules ship with conservative deny rules. Unknown commands are rejected.

The shim sends a request, the daemon looks it up in the command directory, applies deny rules and environment isolation, executes the command, and streams output back. The container never sees credentials — they live on the host.

## Installation

### Quick Install (Linux/macOS)

```sh
curl -fsSL https://raw.githubusercontent.com/calebfaruki/airlock/main/install.sh | sh
```

This downloads the daemon, installs it to `~/.local/bin/`, and runs `airlock init` to set up the system service.

### macOS: Homebrew PATH

On macOS, `launchd` runs the daemon with a minimal PATH (`/usr/bin:/bin:/usr/sbin:/sbin`) that does not include Homebrew's `/opt/homebrew/bin`. If your CLI tools are installed via Homebrew, the daemon won't find them.

Two options:

**Option A: Absolute paths in command modules** (recommended — explicit and auditable)

Eject the built-in and set `bin` to the full path:

```sh
airlock-daemon eject git
# Edit ~/.config/airlock/commands/git.toml
# Change: bin = "git"
# To:     bin = "/opt/homebrew/bin/git"
```

Run `which <command>` to find the path. Repeat for each Homebrew-installed tool.

**Option B: Add Homebrew to the launchd PATH**

Edit `~/Library/LaunchAgents/dev.airlock.daemon.plist` and add an `EnvironmentVariables` key:

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
</dict>
```

Then reload: `launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/dev.airlock.daemon.plist && launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.airlock.daemon.plist`

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

## Usage

### Daemon

```sh
airlock-daemon start             # Run daemon in foreground
airlock-daemon init              # Install as system service (systemd/launchd)
airlock-daemon init --uninstall  # Remove system service
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

## Security Model

- The daemon never passes arguments through a shell — always `execve` with an explicit arg array.
- Unknown commands are rejected. The command directory is an allowlist.
- The container never holds credentials.
- User overrides are full replace — no merging with built-ins.
- Built-in modules are compiled into the binary and upgrade with the daemon.
