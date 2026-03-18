# ssh — Security Model

**Threat:** SSH is a general-purpose remote execution tool. Every invocation is inherently code execution on a remote host using the daemon's SSH keys. There is no safe subset of SSH to allowlist.

## No Deny List

SSH has no concept of "safe subcommands." The dangerous part isn't a flag — it's the entire purpose of the tool. Restricting destinations or operations belongs in pre-exec hooks, not in a static deny list.

## Not Covered

- **Arbitrary host connection** — agent can SSH to any host the daemon's keys can reach
- **Port forwarding** (`-L`, `-R`, `-D`) — creates tunnels through the host into internal networks
- **Command execution** (`ssh host 'rm -rf /'`) — runs anything on any reachable host
- **Agent forwarding** (`-A`) — exposes the host's SSH agent to the remote server
- **ProxyCommand/ProxyJump** — chains through hosts, escalates network access
- **`-o` flag injection** — overrides SSH config (e.g., `StrictHostKeyChecking=no`)

All of these should be handled by a pre-exec hook that restricts allowed destination hosts and flags. If the agent doesn't need SSH, remove this module.
