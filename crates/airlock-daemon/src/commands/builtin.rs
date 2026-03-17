const GIT_TOML: &str = r#"[command]
bin = "git"

[deny]
# --upload-pack / -u: CVE-2022-25648, arbitrary code execution via argument injection
# --config / -c: overrides any git config including core.sshCommand, credential.helper
# --exec-path: redirects git to load sub-programs from attacker-controlled directory
# --template: copies hooks from a local directory into cloned repo — hooks execute on clone
args = ["--upload-pack", "-u", "--config", "-c", "--exec-path", "--template"]

[env]
# GIT_SSH_COMMAND: shell-interpreted, arbitrary code execution
# GIT_CONFIG / GIT_CONFIG_GLOBAL: points git at attacker-controlled config files
# GIT_CONFIG_PARAMETERS: legacy config injection
# GIT_CONFIG_COUNT: stripped then re-set below with hardened values
# GIT_ATTR_SOURCE: controls attribute lookups
strip = ["GIT_SSH_COMMAND", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_PARAMETERS", "GIT_ATTR_SOURCE", "GIT_CONFIG_COUNT"]
# GIT_CONFIG_NOSYSTEM: ignore system-wide gitconfig
# GIT_CONFIG_COUNT/KEY_0/VALUE_0: set core.hooksPath=/dev/null to disable all git hooks
set = { GIT_CONFIG_NOSYSTEM = "1", GIT_CONFIG_COUNT = "1", GIT_CONFIG_KEY_0 = "core.hooksPath", GIT_CONFIG_VALUE_0 = "/dev/null" }

[exec]
concurrent = true
"#;

const TERRAFORM_TOML: &str = r#"[command]
bin = "terraform"

[deny]
args = ["destroy", "force-unlock"]

[exec]
concurrent = false
"#;

const AWS_TOML: &str = r#"[command]
bin = "aws"

[deny]
args = ["terminate-instances", "delete-db-instance", "delete-user", "delete-role", "delete-bucket"]

[env]
strip = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"]

[exec]
concurrent = true
"#;

const SSH_TOML: &str = r#"[command]
bin = "ssh"

[exec]
concurrent = true
"#;

const DOCKER_TOML: &str = r#"[command]
bin = "docker"

[deny]
args = ["--privileged"]

[env]
strip = ["DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"]

[exec]
concurrent = true
"#;

pub fn builtins() -> Vec<(&'static str, &'static str)> {
    vec![
        ("git", GIT_TOML),
        ("terraform", TERRAFORM_TOML),
        ("aws", AWS_TOML),
        ("ssh", SSH_TOML),
        ("docker", DOCKER_TOML),
    ]
}
