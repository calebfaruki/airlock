# ssh — Security Model

**Threat:** SSH is remote code execution on external servers. No other agentic framework (Claude Code, Codex, Docker Sandboxes) provides this capability. They deliberately keep SSH keys outside the sandbox. Airlock is the only way an agent gets authenticated SSH access.

## What the Deny Rules Guarantee

**SSH stays one-hop, one-command.** No forwarding, tunneling, or chaining.

| Arg | Threat |
|-----|--------|
| `-A` | Agent forwarding — exposes host SSH keys to remote server (CVE-2023-38408) |
| `-L` | Local port forwarding — tunnels into internal networks through the host |
| `-R` | Remote port forwarding — exposes host ports to the remote server |
| `-D` | Dynamic SOCKS proxy — full network tunnel through host |
| `-w` | TUN/TAP tunneling — creates VPN between host and remote server |
| `-J` | ProxyJump — chains through intermediate hosts |
| `-W` | Stdio forwarding — raw TCP tunnel via stdin/stdout |

**SSH cannot escalate into local code execution.** ProxyCommand, config overrides, and custom config files are denied.

| Arg | Threat |
|-----|--------|
| `-o` | Config override — bypasses all other deny rules (e.g., `ProxyCommand=/bin/sh`) |
| `-F` | Custom config file — can contain ProxyCommand (local code execution via /bin/sh) |

**SSH cannot modify the host or expose its display server.**

| Arg | Threat |
|-----|--------|
| `-E` | Log file — writes to arbitrary path on host |
| `-X` | X11 forwarding — exposes host display server to remote |
| `-Y` | Trusted X11 forwarding — same as `-X` without security extensions |

**Credentials stay on the host.** Agent forwarding is denied, so the remote server cannot reuse the host's SSH keys.

**Existing connections cannot be hijacked.**

| Arg | Threat |
|-----|--------|
| `-O` | Control master commands — can hijack existing multiplexed connections |

## Stripped Env Vars

| Var | Why |
|-----|-----|
| `SSH_AUTH_SOCK` | Prevents container from directing ssh to a rogue agent socket |

## What the Deny Rules Do NOT Guarantee

- **What the agent runs on the remote server.** The command is a positional argument and cannot be filtered by deny rules.
- **Which server the agent connects to.** Any host the daemon's SSH keys can reach is accessible.

## Not Covered

- **Arbitrary host connection** — agent can SSH to any host reachable with the daemon's keys
- **Arbitrary remote command execution** (`ssh host 'rm -rf /'`) — the command argument is the purpose of SSH
- **`-i` (identity file selection)** — not denied; profiles should control which key is used via env
- **`-p` (non-standard port)** — not denied; restricting ports requires a pre-exec hook

If the agent doesn't need SSH, remove it from `commands.enable`.
