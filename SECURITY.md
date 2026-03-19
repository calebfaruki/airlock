# Security Policy

## Reporting a Vulnerability

**Do not open a public issue.** Instead, use [GitHub private vulnerability reporting](https://github.com/calebfaruki/airlock/security/advisories/new) to submit your report.

Include: what you found, steps to reproduce, and which version you tested against.

## Response

You should receive an acknowledgment within 48 hours. Security fixes are prioritized over all other work. We aim to release a fix within 90 days of a confirmed report, coordinating public disclosure timing with the reporter.

## Supported Versions

Only the latest release receives security patches.

## Scope

Security issues include: socket permission bypass, command allowlist bypass, environment isolation escape, shell injection, credential leakage across profiles, and audit log tampering.

Out of scope: denial of service via slow commands, feature requests, and issues in user-authored hooks or command overrides.
