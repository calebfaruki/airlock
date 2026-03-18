# aws — Security Model

**Threat:** The AWS CLI operates with the host's cloud credentials. An agent can destroy infrastructure, escalate IAM privileges, or exfiltrate data.

## Denied Args

| Arg | Why |
|-----|-----|
| `terminate-instances` | Kill EC2 instances — production outage |
| `delete-db-instance` | Destroy RDS databases — permanent data loss without snapshots |
| `delete-user` | Remove IAM users — lock out legitimate access |
| `delete-role` | Remove IAM roles — break service dependencies |
| `delete-bucket` | Destroy S3 buckets and all contents |

## Stripped Env Vars

| Var | Why |
|-----|-----|
| `AWS_ACCESS_KEY_ID` | Prevents container from overriding which AWS account commands target |
| `AWS_SECRET_ACCESS_KEY` | Same — forces use of daemon's credential chain |
| `AWS_SESSION_TOKEN` | Same — prevents session token injection |

## Not Covered

- **IAM escalation** (`create-role`, `attach-role-policy`, `create-access-key`) — an agent can mint new credentials or grant itself admin; use pre-exec hook to restrict IAM operations
- **Cost attacks** (`run-instances` with expensive instance types) — not denied
- **Data exfiltration** (`s3 cp`, `s3 sync` to external buckets) — not denied
- **Network changes** (`authorize-security-group-ingress 0.0.0.0/0`) — not denied
- **KMS** (`schedule-key-deletion`) — makes encrypted data unrecoverable; not denied
