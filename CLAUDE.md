# CLAUDE.md — Airlock Project Guide

This file is the source of truth for the airlock project. Every Claude Code session must read and follow this document. Do not deviate from the architecture, naming, file paths, or design decisions described here without explicit approval.

## What is Airlock?

Airlock is a Kubernetes tool execution controller. It watches AirlockTool CRDs, serves gRPC to transponder, and creates ephemeral Jobs for each tool call. The controller never reads Secrets — kubelet mounts credentials into Jobs. Containers never hold credentials beyond the lifetime of a single Job.

Airlock is written in Rust. The controller sits on a security trust boundary, receives untrusted parameter values from LLM agents, and orchestrates command execution with real credentials. Rust's type system and the parameter validation boundary make it structurally difficult to bypass security checks.

## Architecture

Three components:

1. **airlock-controller** — k8s controller binary. Watches AirlockTool CRDs. Serves gRPC (ListTools, CallTool, GetToolCall, SendToolResult). Creates ephemeral Jobs per tool call. One per namespace.
2. **airlock-agent** — tiny binary included in every tool Job image. Connects back to the controller via gRPC. Receives tool call parameters. Executes the configured command. Returns stdout/stderr/exit code.
3. **airlock-proto** — gRPC service and message definitions. Package namespace: `airlock.v1`.

### Controller-as-Server Pattern

The controller is the only gRPC server. Tool Jobs connect back to the controller as clients. The controller creates a Job with its own address as an env var (`AIRLOCK_CONTROLLER_ADDR`). The Job starts, connects, pulls work, executes, returns results. This eliminates Job endpoint discovery.

## Protocol

gRPC over HTTP/2. Service: `airlock.v1.AirlockController`.

| RPC | Direction | Purpose |
|-----|-----------|---------|
| `ListTools` | transponder → controller | List available tools from CRDs |
| `CallTool` | transponder → controller | Execute a tool (blocks until Job completes) |
| `GetToolCall` | agent → controller | Pull work assignment (long-poll) |
| `SendToolResult` | agent → controller | Return execution result |

Proto definition: `crates/airlock-proto/proto/airlock/v1/airlock.proto`

## AirlockTool CRD

```yaml
apiVersion: airlock.dev/v1
kind: AirlockTool
metadata:
  name: git-push
spec:
  description: "Push commits to a remote branch"
  parameters:
    type: object
    properties:
      remote: { type: string, default: origin }
      branch: { type: string }
    required: [branch]
  image: ghcr.io/calebfaruki/airlock-git:latest
  command: "git push {remote} {branch}"
  workingDir: /workspace
  workspacePVC: true
  credential:
    secretName: git-ssh-key
    mountPath: /run/secrets/airlock/git
  keepalive: 0
  maxCalls: 0
```

### CRD Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `description` | string | required | Tool description exposed to LLM via ListTools |
| `parameters` | JSON Schema | required | Parameter schema (passed through, not validated by controller) |
| `image` | string | required | Container image with airlock-agent binary |
| `command` | string | required | Command template with `{param}` placeholders |
| `workingDir` | string | `/workspace` | Working directory inside the Job |
| `workspacePVC` | bool | `true` | Mount workspace-data PVC |
| `credential` | object | optional | Secret to mount (secretName + mountPath) |
| `keepalive` | u64 | `0` | Seconds to keep Job alive after last call. 0 = fire-and-forget |
| `maxCalls` | u32 | `0` | Max invocations. 0 = unlimited |

## Command Execution

The agent binary interpolates parameter values into the command template and executes via `sh -c`. Parameter values pass through metacharacter validation before interpolation.

### Security Boundary

- **Command templates are trusted** — defined in the CRD by a cluster admin, not LLM-provided
- **Parameter values are untrusted** — provided by the LLM, validated before interpolation
- **Forbidden characters**: `;`, `|`, `&`, `` ` ``, `$`, `(`, `)`, `>`, `<`
- **Defense in depth**: even if validation were bypassed, the Job has no credentials beyond what's explicitly mounted via the CRD's credential spec

## Job Lifecycle

- **Fire-and-forget** (keepalive=0): new Job per CallTool. Agent runs one command, exits. TTL cleanup (30s).
- **Keepalive** (keepalive>0): one Job persists, agent loops on GetToolCall. Controller tracks idle time. Job deleted after keepalive seconds of inactivity.
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
  airlock-agent/              # tool Job agent binary
    src/main.rs               # gRPC client loop
    src/execute.rs            # interpolation + validation + execution
images/
  git/Dockerfile              # built-in git tool image
examples/
  tools/                      # example AirlockTool CRDs
deploy/
  crds/airlocktool.yaml       # generated CRD manifest
  rbac.yaml                   # controller RBAC
```

## Distribution

Container images published to GHCR:
- `ghcr.io/calebfaruki/airlock-controller:latest` — distroless/cc base (glibc for kube-rs TLS)
- `ghcr.io/calebfaruki/airlock-agent:latest` — scratch base (static musl)
- `ghcr.io/calebfaruki/airlock-git:latest` — alpine + git + airlock-agent

Release artifacts: `airlock-controller-linux-{amd64,arm64}`, `airlock-agent-linux-{amd64,arm64}`

All artifacts signed with cosign. Build provenance attestations via SLSA.

## Security Invariants

These must never be violated:

1. **Credentials never appear in gRPC messages.** No tokens, no keys, no secret bytes in transit.
2. **Credentials never appear in controller memory.** The controller references Secrets by name only.
3. **Controller RBAC has zero Secret read access.** Kubelet mounts credentials into Jobs.
4. **Parameter values are validated before interpolation.** Shell metacharacters rejected at the boundary.
5. **Command templates are admin-defined.** CRDs are written by cluster admins, not LLM agents.
6. **maxCalls enforcement is infrastructure-level.** Not prompt-level, not bypassable by the LLM.
7. **Job TTL ensures cleanup.** Completed Jobs are garbage-collected (30s default).
8. **All images are signed with cosign.** Keyless, sigstore-backed.

## What Airlock Is NOT

- **Not a workflow engine.** It executes tool calls. Approval flows belong to the agent framework.
- **Not a sanitizer.** Output passes through unmodified. Redaction is the user's responsibility.
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
