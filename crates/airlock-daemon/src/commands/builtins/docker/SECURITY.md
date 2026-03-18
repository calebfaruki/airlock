# docker — Security Model

**Threat:** Docker CLI access is functionally root on the host. The daemon's Docker socket lets an agent create privileged containers, mount the host filesystem, or escape isolation entirely.

## Denied Args

| Arg | Why |
|-----|-----|
| `--privileged` | Disables all Linux security boundaries — trivial container escape via `nsenter`, host filesystem mount, kernel module loading |

## Stripped Env Vars

| Var | Why |
|-----|-----|
| `DOCKER_HOST` | Prevents redirecting commands to a remote/attacker-controlled Docker daemon |
| `DOCKER_TLS_VERIFY` | Prevents disabling TLS verification for MITM |
| `DOCKER_CERT_PATH` | Prevents substituting attacker certificates |

## Not Covered

- **Host filesystem mount** (`docker run -v /:/host`) — reads/writes everything on the host
- **Host namespace escape** (`--pid=host`, `--net=host`, `--ipc=host`) — breaks process and network isolation
- **Capability escalation** (`--cap-add=ALL`) — equivalent to `--privileged`
- **Security opt bypass** (`--security-opt=apparmor:unconfined`) — disables AppArmor
- **Lateral movement** (`docker exec` on other containers) — not restricted
- **Socket recursion** (`-v /var/run/docker.sock:/var/run/docker.sock`) — Docker-in-Docker escape

Docker is the most dangerous command to proxy. The deny list covers only `--privileged`. A pre-exec hook should restrict allowed Docker operations to a narrow set (e.g., `docker build`, `docker push` only).
