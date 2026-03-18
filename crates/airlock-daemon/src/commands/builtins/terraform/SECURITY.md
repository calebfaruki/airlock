# terraform — Security Model

**Threat:** Terraform manages infrastructure as code. An agent with unrestricted access can destroy production resources, corrupt state, or escalate cloud privileges.

## Denied Args

| Arg | Why |
|-----|-----|
| `destroy` | Deletes all managed infrastructure — irreversible production wipe |
| `force-unlock` | Removes state lock, enabling concurrent mutations that corrupt state |

## Concurrency

`concurrent = false` — Terraform's state lock prevents concurrent operations. Parallel execution risks state corruption or race conditions between plan and apply.

## Not Covered

- **`apply -auto-approve`** — not denied; use pre-exec hook to require approval
- **`state rm/push/mv`** — state manipulation subcommands; consider adding to deny list
- **`-plugin-dir`** — loads providers from attacker-controlled directory; consider denying
- **`-chdir`** — escapes CWD mapping; consider denying
- **`TF_CLI_ARGS`** — env var that injects arbitrary flags, bypassing arg deny; should be stripped if terraform env is forwarded
- **Provider supply chain** — malicious `required_providers` in `.tf` files can load arbitrary provider binaries
