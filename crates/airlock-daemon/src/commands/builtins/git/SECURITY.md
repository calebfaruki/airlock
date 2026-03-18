# git — Security Model

**Threat:** Git has extensive code execution surfaces through flags, env vars, and hooks. An agent with unrestricted git access can execute arbitrary commands on the host, exfiltrate credentials, or read any file.

## Denied Args

| Arg | Why |
|-----|-----|
| `--upload-pack` | Executes arbitrary command instead of git-upload-pack (CVE-2022-25648) |
| `-u` | Short form of `--upload-pack` |
| `--config` | Overrides any git config at runtime — enables `core.sshCommand`, `credential.helper` |
| `-c` | Short form of `--config` |
| `--exec-path` | Redirects git to load sub-programs from attacker-controlled directory |
| `--template` | Copies hooks from a local directory into cloned repo — hooks execute on clone |
| `--config-env` | Injects git config from environment variables — bypasses `-c` deny |
| `--receive-pack` | Overrides receive-pack binary path — arbitrary command execution on push |
| `credential` | Subcommand that extracts host credentials via `credential fill/approve/reject` |
| `daemon` | Starts a git daemon — arbitrary network access from the host |
| `shell` | Restricted login shell — not needed in proxy context, potential escape vector |
| `upload-pack` | Transport plumbing — direct pack access bypassing normal fetch flow |
| `receive-pack` | Transport plumbing — direct pack access bypassing normal push flow |
| `upload-archive` | Transport plumbing — archive generation over transport protocol |

## Stripped Env Vars

| Var | Why |
|-----|-----|
| `GIT_SSH_COMMAND` | Shell-interpreted — arbitrary code execution with host SSH keys |
| `GIT_CONFIG` | Points git at attacker-controlled config file |
| `GIT_CONFIG_GLOBAL` | Overrides `~/.gitconfig` — same as above |
| `GIT_CONFIG_PARAMETERS` | Injects config key-value pairs, bypasses `-c` deny |
| `GIT_ATTR_SOURCE` | Controls attribute lookups — can trigger malicious filters |
| `GIT_CONFIG_COUNT` | Stripped then re-set with hardened values (see below) |

## Injected Env Vars

| Var | Value | Why |
|-----|-------|-----|
| `GIT_CONFIG_NOSYSTEM` | `1` | Ignore system-wide `/etc/gitconfig` |
| `GIT_CONFIG_COUNT` | `1` | Enable programmatic config injection (used with KEY_0/VALUE_0) |
| `GIT_CONFIG_KEY_0` | `core.hooksPath` | Target config key |
| `GIT_CONFIG_VALUE_0` | `/dev/null` | Disable all git hooks — prevents post-checkout, post-merge, fsmonitor execution |

## Known CVEs

- **CVE-2022-25648:** Argument injection via unsanitized input to git commands
- **CVE-2024-32002:** Code execution via crafted submodule symlinks on `clone --recurse-submodules`
- **CVE-2023-22490:** Local clone data exfiltration via symlinks in `$GIT_DIR`
- **CVE-2023-25652:** Arbitrary file write via `git apply --reject`

## Not Covered

- **Remote exfiltration** (`git remote add` + `git push` to attacker server) — use pre-exec hook to restrict remotes
- **Directory traversal** (`--work-tree`, `--git-dir`, `-C`) — not denied; CWD mapping provides partial protection
- **Submodule trojans** (`--recurse-submodules` with malicious `.gitmodules`) — not denied; use pre-exec hook
- **Env vars not stripped:** `GIT_SSH`, `GIT_PROXY_COMMAND`, `GIT_EXTERNAL_DIFF`, `GIT_ASKPASS`, `GIT_PAGER`, `GIT_EXEC_PATH`, `GIT_TEMPLATE_DIR` — the daemon does not forward container env to commands, so these only matter if set in the daemon's own environment
