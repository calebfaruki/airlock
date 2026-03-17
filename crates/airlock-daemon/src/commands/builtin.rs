const GIT_TOML: &str = r#"[command]
bin = "git"

[deny]
args = ["--upload-pack", "-u", "--config", "-c", "--exec-path"]

[env]
strip = ["GIT_SSH_COMMAND", "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_ATTR_SOURCE"]
set = { GIT_CONFIG_NOSYSTEM = "1" }

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
