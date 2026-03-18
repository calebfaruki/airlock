pub fn builtins() -> Vec<(&'static str, &'static str)> {
    vec![
        ("git", include_str!("builtins/git/module.toml")),
        ("terraform", include_str!("builtins/terraform/module.toml")),
        ("aws", include_str!("builtins/aws/module.toml")),
        ("ssh", include_str!("builtins/ssh/module.toml")),
        ("docker", include_str!("builtins/docker/module.toml")),
    ]
}
