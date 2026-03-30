# CLAUDE.md — Airlock Project Guide

This file is the source of truth for the airlock project. Every Claude Code session must read and follow this document. Do not deviate from the architecture, naming, file paths, or design decisions described here without explicit approval.

## What is Airlock?

Airlock is a Kubernetes CLI passthrough controller. It watches AirlockTool CRDs, serves gRPC to transponder, and creates ephemeral chamber Jobs for each tool call. The agent sends a command string. Airlock executes it in a chamber with credential injection, scoped egress, and output scrubbing. No MCP support — every tool is CLI-only.

The controller never reads Secrets — kubelet mounts credentials into Jobs. Containers never hold credentials beyond the lifetime of a single Job. Chamber Jobs use `execve` (no shell) — command strings are parsed into argv arrays via shlex-style splitting.

## Architecture

Three components:

1. **airlock-controller** — k8s controller binary. Watches AirlockTool CRDs. Serves gRPC (ListTools, CallTool, GetToolCall, SendToolResult). Creates ephemeral Jobs per tool call. One per namespace.
2. **airlock-runtime** — chamber runtime binary included in every tool Job image. Connects back to the controller via gRPC. Receives tool call parameters. Executes the configured command. Returns stdout/stderr/exit code.
3. **airlock-proto** — gRPC service and message definitions. Package namespace: `airlock.v1`.

### Controller-as-Server Pattern

The controller is the only gRPC server. Tool Jobs connect back to the controller as clients. The controller creates a Job with its own address as an env var (`AIRLOCK_CONTROLLER_ADDR`). The Job starts, connects, pulls work, executes, returns results. This eliminates Job endpoint discovery.

## Protocol

gRPC over HTTP/2. Service: `airlock.v1.AirlockController`.

| RPC | Direction | Purpose |
|-----|-----------|---------|
| `ListTools` | transponder → controller | List available tools from CRDs |
| `CallTool` | transponder → controller | Execute a tool (blocks until Job completes) |
| `GetToolCall` | runtime → controller | Pull work assignment (long-poll) |
| `SendToolResult` | runtime → controller | Return execution result |

Proto definition: `crates/airlock-proto/proto/airlock/v1/airlock.proto`

## AirlockTool CRD

```yaml
apiVersion: airlock.dev/v1
kind: AirlockTool
metadata:
  name: git-push
spec:
  chamber: git-ops
  description: "Push commits to a remote repository"
  image: ghcr.io/calebfaruki/airlock-git:latest
  command: "git push"
  maxCalls: 10
```

### CRD Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `chamber` | string | required | Name of the AirlockChamber in the same namespace |
| `description` | string | required | Tool description exposed to LLM via ListTools |
| `image` | string | required | Container image with airlock-runtime binary |
| `command` | string | required | Command string executed via execve in the chamber Job |
| `maxCalls` | u32 | `0` | Max invocations. 0 = unlimited |

## Command Execution

Chamber Jobs use `execve` (no shell). The command string from the CRD is parsed into an argv array using shlex-style splitting (`shell-words` crate). Shell metacharacters (`;`, `|`, `&&`, `>`, `` ` ``, `$()`) become literal arguments, not operators.

### Security Boundary

- **Command strings are admin-defined** — written in the CRD by a cluster admin, not LLM-provided
- **execve prevents command chaining** — no shell means no pipes, redirects, or subshells
- **Output scrubbing** — secret values (raw, base64, URL-encoded) are redacted from stdout/stderr before crossing the gRPC boundary
- **Defense in depth**: the Job has no credentials beyond what's explicitly mounted via the chamber's credential spec

## Job Lifecycle

- **Fire-and-forget** (keepalive=false): new Job per CallTool. Runtime runs one command, exits. TTL cleanup (30s).
- **Keepalive** (keepalive=true): one Job persists, runtime loops on GetToolCall. Controller tracks idle time. Job deleted after idle timeout.
- **maxCalls**: infrastructure-level invocation limit. RESOURCE_EXHAUSTED when exceeded.

## RBAC

The controller ServiceAccount has zero Secret read access:

```yaml
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: ["airlock.dev"]
    resources: ["airlocktools"]
    verbs: ["get", "list", "watch"]
```

Credentials are referenced by name in Job specs. Kubelet mounts them. The controller never touches credential bytes.

## Directory Layout

```
crates/
  airlock-proto/              # gRPC proto definitions
    proto/airlock/v1/airlock.proto
    build.rs
    src/lib.rs
  airlock-controller/         # k8s controller binary
    src/main.rs               # CLI + tokio runtime
    src/crd.rs                # AirlockTool CRD struct
    src/state.rs              # shared controller state
    src/watcher.rs            # kube-rs CRD watcher
    src/grpc.rs               # gRPC service implementation
    src/job.rs                # k8s Job builder
    src/keepalive.rs          # background cleanup task
  airlock-runtime/            # chamber runtime binary
    src/main.rs               # gRPC client loop
    src/execute.rs            # interpolation + validation + sh/execve execution
    src/scrub.rs              # output scrubbing (secret redaction)
images/
  git/Dockerfile              # built-in git tool image
examples/
  tools/                      # example AirlockTool CRDs
deploy/
  crds/airlockchamber.yaml    # generated AirlockChamber CRD
  crds/airlocktool.yaml       # generated AirlockTool CRD
  rbac.yaml                   # controller RBAC
```

## Distribution

Container images published to GHCR:
- `ghcr.io/calebfaruki/airlock-controller:latest` — distroless/cc base (glibc for kube-rs TLS)
- `ghcr.io/calebfaruki/airlock-runtime:latest` — scratch base (static musl)
- `ghcr.io/calebfaruki/airlock-git:latest` — alpine + git + airlock-runtime

Release artifacts: `airlock-controller-linux-{amd64,arm64}`, `airlock-runtime-linux-{amd64,arm64}`

All artifacts signed with cosign. Build provenance attestations via SLSA.

## Security Invariants

These must never be violated:

1. **Credentials never appear in gRPC messages.** No tokens, no keys, no secret bytes in transit.
2. **Credentials never appear in controller memory.** The controller references Secrets by name only.
3. **Controller RBAC has zero Secret read access.** Kubelet mounts credentials into Jobs.
4. **Chamber Jobs use execve (no shell).** Command strings are parsed into argv arrays. Shell metacharacters become literal arguments.
5. **Command strings are admin-defined.** CRDs are written by cluster admins, not LLM agents.
6. **shareProcessNamespace is false on all Job pods.** Prevents cross-container `/proc` access.
7. **maxCalls enforcement is infrastructure-level.** Not prompt-level, not bypassable by the LLM.
8. **Job TTL ensures cleanup.** Completed Jobs are garbage-collected (30s default).
9. **Secret values are scrubbed from command output before crossing the gRPC boundary.** The runtime redacts raw, base64-encoded, and URL-encoded secret values from stdout/stderr before sending results to the controller.
10. **All images are signed with cosign.** Keyless, sigstore-backed.

## What Airlock Is NOT

- **Not a workflow engine.** It executes tool calls. Approval flows belong to the agent framework.
- **Not an MCP server.** CLI passthrough only. No protocol translation.
- **Not a framework.** It is a single-purpose controller. No opinions on agent architecture.
- **Not a timeout manager.** Commands run until they finish.

## Lints

Workspace-wide lint configuration lives in the root `Cargo.toml` under `[workspace.lints]`. Individual crates inherit via `[lints] workspace = true`. Do not add lint attributes (`#![deny(...)]`, `#![warn(...)]`) in source files.

After any refactor, run `cargo clippy --workspace` and fix all warnings before committing. Dead code, unused imports, and unused variables are denied (compile errors, not warnings).

Proto-generated code is output to `OUT_DIR` and wrapped with `#[allow(clippy::all, unreachable_pub)]` in `airlock-proto/src/lib.rs`.

## Build Requirements

- Rust 1.94.0+ (stable)
- `protoc` (protobuf compiler) for proto code generation
- On macOS: `brew install protobuf`
- In CI: `arduino/setup-protoc` action

## External Systems

- **transponder**: calls ListTools/CallTool on the controller. No transponder code in this repo.
- **tightbeam**: referenced architecture pattern (controller-as-server). No code dependency.
- **sycophant**: Job label `app.kubernetes.io/part-of=sycophant`. Organizational label only.
