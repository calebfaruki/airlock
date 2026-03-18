# Changelog

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
