# Changelog

## [0.2.0] - 2026-03-20

### Changed
- **Breaking:** Command modules are now opt-in. Add `[commands] enable = [...]` to `config.toml`. The daemon exits on startup if this field is missing or empty.
- `airlock init` generates a starter `config.toml` with a commented-out `[commands]` example. On upgrade, it detects a missing `[commands]` section and prints a migration hint.
- Startup log changed from "loaded commands" to "enabled commands".

### Security
- SSH module: added deny rules for agent forwarding (`-A`), port forwarding (`-L`/`-R`/`-D`), config overrides (`-o`/`-F`), ProxyJump (`-J`), stdio forwarding (`-W`), X11 forwarding (`-X`/`-Y`), log file writing (`-E`), TUN/TAP tunneling (`-w`), and control master commands (`-O`).
- SSH module: stripped `SSH_AUTH_SOCK` from environment.
- SSH `SECURITY.md` rewritten with full threat model documenting what deny rules guarantee and what they do not.

### Migration
Add `[commands] enable` to `~/.config/airlock/config.toml`:
```toml
[commands]
enable = ["git", "terraform"]
```
Or re-run `airlock init` to get a migration hint.

## [0.1.0] - 2026-03-18

### Added
- Core IPC: shim + daemon over unix socket (JSON-RPC 2.0, NDJSON streaming)
- Command directory with built-in modules (git, terraform, aws, ssh, docker)
- TOML-based deny rules, env stripping/injection, arg appending, concurrency control
- Per-command SECURITY.md documenting threat model and rationale
- Pre-exec and post-exec hooks with 30s timeout and env isolation
- `airlock init` for systemd/launchd service installation (idempotent)
- `airlock init --uninstall` to remove service
- NDJSON audit logging with size-based rotation
- Optional config via `~/.config/airlock/config.toml`
- CLI: show, diff, eject, check subcommands
- Startup inventory: loaded commands printed on daemon start
- PATH hint on spawn failure for non-absolute binary paths
- CI: lint/test pipeline, Rust build caching, pinned toolchain
- Install script for Linux/macOS

### Security
- Commands execute via execve, never through a shell
- Unknown commands rejected (allowlist model)
- Git hooks disabled via GIT_CONFIG_COUNT (core.hooksPath=/dev/null)
- Git --template denied to prevent template hook injection
- GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT stripped from env
- CWD translation fails explicitly when docker inspect fails
- Hook-modified requests re-validated through full deny pipeline
- Hook processes run with isolated env (PATH/HOME/USER only)
