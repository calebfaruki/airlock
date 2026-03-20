# docker — Security Model

**Threat:** Docker CLI access is functionally root on the host. The daemon's Docker socket lets an agent create privileged containers, mount the host filesystem, or escape isolation entirely.

## Denied Args

| Entry | Why |
|-------|-----|
| `--privileged` | Disables all Linux security boundaries — trivial container escape via `nsenter`, host filesystem mount, kernel module loading |
| `-v=/*:*` | Blocks host root filesystem mounts (`-v /:/host`, `-v /etc:/mnt`) |
| `--volume=/*:*` | Same as above, long form |
| `-v=*docker.sock*` | Blocks Docker socket mount — Docker-in-Docker escape |
| `--volume=*docker.sock*` | Same as above, long form |
| `--pid=host` | Breaks process isolation — container can see/signal host processes |
| `--net=host` | Breaks network isolation — container shares host network stack |
| `--network=host` | Same as above, long form |
| `--ipc=host` | Breaks IPC isolation — shared memory access to host processes |
| `--cap-add=ALL` | Grants all Linux capabilities — equivalent to `--privileged` |
| `--security-opt=apparmor:unconfined` | Disables AppArmor mandatory access control |

## Stripped Env Vars

| Var | Why |
|-----|-----|
| `DOCKER_HOST` | Prevents redirecting commands to a remote/attacker-controlled Docker daemon |
| `DOCKER_TLS_VERIFY` | Prevents disabling TLS verification for MITM |
| `DOCKER_CERT_PATH` | Prevents substituting attacker certificates |

## Not Covered

- **Lateral movement** (`docker exec` on other containers) — not restricted
- **Relative path mounts** (`-v ./data:/data`) — only absolute root paths are denied
- **`--device`** — host device access (e.g., GPU, disk) not restricted

Docker is the most dangerous command to proxy. A pre-exec hook should restrict allowed Docker operations to a narrow set (e.g., `docker build`, `docker push` only).
