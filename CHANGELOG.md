# Changelog

## [0.3.0] - 2026-03-20

### Changed
- **Breaking:** Command modules are now opt-in. Add `[commands] enable = [...]` to `config.toml`. The daemon exits on startup if this field is missing or empty.
- **Breaking:** Profile `commands` field is now required. Use `commands = []` to explicitly allow all commands. Empty profile files are rejected at startup.
- `airlock init` generates a starter `config.toml` with a commented-out `[commands]` example. On upgrade, it detects a missing `[commands]` section and prints a migration hint.
- Startup log changed from "loaded commands" to "enabled commands".
- Extracted shared helpers (`deny_request()`, `spawn_stream_forwarder()`) to reduce duplication in lib.rs and tests.

### Security
- Arg normalization: deny rules now operate on normalized (flag, value) pairs instead of raw strings, closing flag-splitting bypasses like `--pid=host` vs `--pid host` (#22)
- Three deny rule types: plain args, flag-value patterns with glob support (`-v=/*:*`), and order-independent sequences (`apply & -auto-approve`)
- Glob patterns in deny entries validated and compiled at module load, not per request
- FlagValue lookahead no longer consumes `--` as a value
- Docker module: added flag-value deny rules for volume mounts, namespace escapes (`--pid=host`, `--net=host`, `--ipc=host`), and capability grants (`--cap-add=ALL`)
- Terraform module: `apply & -auto-approve` sequence deny rule replaces plain `destroy`
- SSH module: added 13 deny rules (`-A`, `-L`, `-R`, `-D`, `-o`, `-F`, `-J`, `-W`, `-X`, `-Y`, `-E`, `-w`, `-O`) and stripped `SSH_AUTH_SOCK` from environment
- SSH `SECURITY.md` rewritten with full threat model documenting what deny rules guarantee and what they do not
- Docker and Terraform `SECURITY.md` updated to reflect new deny coverage

### Added
- Fuzz testing: three targets (JSON-RPC parsing, profile parsing, deny rule matching) via cargo-fuzz/libfuzzer
- ClusterFuzzLite: PR fuzzing in CI pipeline (gated behind test and audit), daily batch fuzzing with corpus pruning

### Dependencies
- Bump `sigstore/cosign-installer` 3.10.1 → 4.1.0
- Bump `github/codeql-action` 3.33.0 → 4.33.0

## [0.2.0] - 2026-03-19

### Added
- Credential profiles: socket-per-profile isolation. Each profile gets its own unix socket. The volume mount is the capability.
- Profile TOML with command whitelist and env var injection for credential routing
- Env merge order: strip → profile → command module (command hardening always wins)
- Profile field in audit log entries
- `profile list` and `profile show` CLI commands
- `SECURITY.md` with vulnerability reporting policy (private reporting via GitHub advisories)
- Cosign keyless signing of release artifacts via GitHub Actions OIDC
- CodeQL scanning for GitHub Actions workflow definitions
- OpenSSF Scorecard workflow (weekly + push to main) with badge
- Dependabot for cargo and github-actions ecosystems (weekly)
- `cargo-audit` job in CI pipeline

### Changed
- Socket paths unified to `~/.config/airlock/sockets/` on all platforms (removed XDG_RUNTIME_DIR branching)
- All CI actions pinned by commit SHA instead of floating tags
- Hardened macOS launchd plist with explicit PATH for daemon
- Expanded git deny list with dangerous subcommands (`credential`, `daemon`, `shell`, `upload-pack`, `receive-pack`, `upload-archive`) and flags (`--config-env`, `--receive-pack`)
- Improved Docker Desktop documentation (VirtioFS socket permission workaround)

### Security
- Profile sockets enforce 0600 permissions at bind time
- Git deny list expanded to cover remote code execution subcommands

### Dependencies
- Bump `toml` 0.8.23 → 1.0.7
- Bump `actions/upload-artifact` 4.6.2 → 7.0.0
- Bump `actions/checkout` 4.3.1 → 6.0.2
- Bump `actions/download-artifact` 4.3.0 → 8.0.1
- Bump `github/codeql-action` 3.33.0 → 4.33.0
- Update `dtolnay/rust-toolchain` to latest SHA

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
