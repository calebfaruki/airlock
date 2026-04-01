# CLAUDE.md — Airlock Project Guide

This file is the source of truth for the airlock project. Every Claude Code session must read and follow this document. Do not deviate from the architecture, naming, file paths, or design decisions described here without explicit approval.

## What is Airlock?

Airlock is a Kubernetes tool execution controller. It watches AirlockChamber CRDs, discovers tools from OCI image labels, serves gRPC to transponder, and creates ephemeral Jobs for each tool call. The LLM sends a full command string. Airlock executes it in a chamber with credential injection, scoped egress, and output scrubbing. No MCP support — every tool is CLI-only.

The controller never reads Secrets — kubelet mounts credentials into Jobs. Containers never hold credentials beyond the lifetime of a single Job. Chamber Jobs use `execve` (no shell) — command strings are parsed into argv arrays via shlex-style splitting.

## Architecture

Three components:

1. **airlock-controller** — k8s controller binary. Watches AirlockChamber CRDs. Discovers tools from OCI image labels (`dev.airlock.tools`). Serves gRPC (ListTools, CallTool, GetToolCall, SendToolResult). Creates ephemeral Jobs per tool call. One per namespace.
2. **airlock-runtime** — chamber runtime binary included in every tool Job image. Connects back to the controller via gRPC. Receives the command string from the LLM. Executes it via execve. Returns stdout/stderr/exit code.
3. **airlock-proto** — gRPC service and message definitions. Package namespace: `airlock.v1`.

### Controller-as-Server Pattern

The controller is the only gRPC server. Tool Jobs connect back to the controller as clients. The controller creates a Job with its own address as an env var (`AIRLOCK_CONTROLLER_ADDR`). The Job starts, connects, pulls work, executes, returns results. This eliminates Job endpoint discovery.

## Protocol

gRPC over HTTP/2. Service: `airlock.v1.AirlockController`.

| RPC | Direction | Purpose |
|-----|-----------|---------|
| `ListTools` | transponder → controller | List available tools discovered from chamber images |
| `CallTool` | transponder → controller | Execute a tool (blocks until Job completes) |
| `GetToolCall` | runtime → controller | Pull work assignment (long-poll) |
| `SendToolResult` | runtime → controller | Return execution result |

Proto definition: `crates/airlock-proto/proto/airlock/v1/airlock.proto`

## Tool Discovery

Tools are discovered from OCI image labels. When an AirlockChamber has an `image` field, the controller fetches the image config from the registry and reads the `dev.airlock.tools` label.

### Label Format

```json
["git", "gh", {"name": "deploy-cli", "description": "Deploy to production"}]
```

- Bare strings become tools with auto-generated descriptions: "Execute a {name} command. Pass the full command as a string."
- Objects with `name` and optional `description` fields allow custom descriptions.
- Missing label = no tools (not an error). Malformed entries are skipped with a warning.

### Duplicate Tool Names

If two chambers declare the same tool name, the first chamber wins. The second is rejected with a warning log. No silent override.

## AirlockChamber CRD

```yaml
apiVersion: airlock.dev/v1
kind: AirlockChamber
metadata:
  name: git-ops
spec:
  image: ghcr.io/calebfaruki/airlock-git:latest
  workspace: workspace-data
  workspaceMode: readWrite
  credentials:
    - secret: git-ssh-key
      key: id_ed25519
      file: /run/secrets/airlock/git/id_ed25519
  egress:
    - host: github.com
      port: 22
  keepalive: false
```

### CRD Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `image` | string | optional | OCI image with `dev.airlock.tools` label. Tools discovered from this image. |
| `workspace` | string | required | PVC name for the workspace volume |
| `workspaceMode` | string | required | `readWrite` or `readOnly` |
| `workspaceMountPath` | string | `/workspace` | Mount path for the workspace in the Job container |
| `credentials` | array | `[]` | Credential mappings (env or file mode) |
| `egress` | array | `[]` | Allowed egress rules (host + port) |
| `keepalive` | bool | `false` | Keep the Job alive for multiple calls |

## Command Execution

The LLM sends a full command string via `{"command": "git push origin main"}`. The runtime extracts the `command` field and executes it via `execve` (no shell). The command is parsed into an argv array using shlex-style splitting (`shell-words` crate). Shell metacharacters (`;`, `|`, `&&`, `>`, `` ` ``, `$()`) become literal arguments, not operators.

### Tool Parameter Schema

All tools use a uniform parameter schema:
```json
{"type":"object","properties":{"command":{"type":"string","description":"The full command to execute"}},"required":["command"]}
```

### Security Boundary

- **Command strings come from the LLM** — the LLM sends the full command, the runtime executes it as-is
- **execve prevents command chaining** — no shell means no pipes, redirects, or subshells
- **Output scrubbing** — secret values (raw, base64, URL-encoded) are redacted from stdout/stderr before crossing the gRPC boundary
- **Defense in depth**: the Job has no credentials beyond what's explicitly mounted via the chamber's credential spec

## Job Lifecycle

- **Fire-and-forget** (keepalive=false): new Job per CallTool. Runtime runs one command, exits. TTL cleanup (30s).
- **Keepalive** (keepalive=true): one Job persists, runtime loops on GetToolCall. Controller tracks idle time. Job deleted after idle timeout.

## RBAC

The controller ServiceAccount has zero Secret read access:

```yaml
rules:
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: ["airlock.dev"]
    resources: ["airlockchambers"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["airlock.dev"]
    resources: ["airlockchambers/status"]
    verbs: ["patch"]
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
    src/crd.rs                # AirlockChamber CRD struct
    src/state.rs              # shared controller state (RegisteredTool, chambers, call queue)
    src/registry.rs           # OCI registry client for reading image labels
    src/watcher.rs            # kube-rs CRD watcher with tool discovery
    src/grpc.rs               # gRPC service implementation
    src/job.rs                # k8s Job builder
    src/keepalive.rs          # background cleanup task
  airlock-runtime/            # chamber runtime binary
    src/main.rs               # gRPC client loop
    src/execute.rs            # sh/execve execution
    src/scrub.rs              # output scrubbing (secret redaction)
images/
  git/Dockerfile              # built-in git tool image (LABEL dev.airlock.tools='["git"]')
examples/
  chambers/                   # example AirlockChamber CRDs
deploy/
  crds/airlockchamber.yaml    # generated AirlockChamber CRD
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
5. **shareProcessNamespace is false on all Job pods.** Prevents cross-container `/proc` access.
6. **Job TTL ensures cleanup.** Completed Jobs are garbage-collected (30s default).
7. **Secret values are scrubbed from command output before crossing the gRPC boundary.** The runtime redacts raw, base64-encoded, and URL-encoded secret values from stdout/stderr before sending results to the controller.
8. **All images are signed with cosign.** Keyless, sigstore-backed.

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
