use tracing::warn;

#[derive(Debug, Clone)]
pub struct DiscoveredTool {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("failed to parse image reference: {0}")]
    InvalidImageRef(String),
    #[error("registry request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),
    #[error("invalid label JSON: {0}")]
    InvalidLabel(String),
    #[error("unexpected registry response: {0}")]
    UnexpectedResponse(String),
}

struct ImageRef {
    registry: String,
    repository: String,
    reference: String,
}

fn parse_image_ref(image: &str) -> ImageRef {
    let (image_part, reference) = if let Some((img, digest)) = image.split_once('@') {
        (img, digest.to_string())
    } else if let Some((img, tag)) = image.rsplit_once(':') {
        (img, tag.to_string())
    } else {
        (image, "latest".to_string())
    };

    let parts: Vec<&str> = image_part.splitn(3, '/').collect();
    let (registry, repository) = match parts.len() {
        1 => (
            "registry-1.docker.io".to_string(),
            format!("library/{}", parts[0]),
        ),
        2 => {
            if parts[0].contains('.') || parts[0].contains(':') {
                (parts[0].to_string(), parts[1].to_string())
            } else {
                (
                    "registry-1.docker.io".to_string(),
                    format!("{}/{}", parts[0], parts[1]),
                )
            }
        }
        _ => (parts[0].to_string(), format!("{}/{}", parts[1], parts[2])),
    };

    ImageRef {
        registry,
        repository,
        reference,
    }
}

pub fn parse_tools_label(label_value: &str) -> Result<Vec<DiscoveredTool>, RegistryError> {
    let parsed: serde_json::Value = serde_json::from_str(label_value)
        .map_err(|e| RegistryError::InvalidLabel(format!("not valid JSON: {e}")))?;

    let array = parsed
        .as_array()
        .ok_or_else(|| RegistryError::InvalidLabel("label must be a JSON array".into()))?;

    let mut tools = Vec::new();
    for (i, entry) in array.iter().enumerate() {
        match entry {
            serde_json::Value::String(name) => {
                tools.push(DiscoveredTool {
                    name: name.clone(),
                    description: None,
                });
            }
            serde_json::Value::Object(obj) => {
                if let Some(name) = obj.get("name").and_then(|n| n.as_str()) {
                    let description = obj
                        .get("description")
                        .and_then(|d| d.as_str())
                        .map(String::from);
                    tools.push(DiscoveredTool {
                        name: name.to_string(),
                        description,
                    });
                } else {
                    warn!(
                        index = i,
                        "skipping tool entry: object missing 'name' field"
                    );
                }
            }
            _ => {
                warn!(index = i, "skipping tool entry: expected string or object");
            }
        }
    }

    Ok(tools)
}

pub async fn discover_tools(image_ref: &str) -> Result<Vec<DiscoveredTool>, RegistryError> {
    let parsed = parse_image_ref(image_ref);
    let client = reqwest::Client::new();

    // Get auth token for public registries
    let token = if parsed.registry == "registry-1.docker.io" {
        let token_url = format!(
            "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
            parsed.repository
        );
        let resp: serde_json::Value = client.get(&token_url).send().await?.json().await?;
        resp.get("token").and_then(|t| t.as_str()).map(String::from)
    } else if parsed.registry == "ghcr.io" {
        let token_url = format!(
            "https://ghcr.io/token?scope=repository:{}:pull&service=ghcr.io",
            parsed.repository
        );
        let resp: serde_json::Value = client.get(&token_url).send().await?.json().await?;
        resp.get("token").and_then(|t| t.as_str()).map(String::from)
    } else {
        None
    };

    // Fetch manifest
    let manifest_url = format!(
        "https://{}/v2/{}/manifests/{}",
        parsed.registry, parsed.repository, parsed.reference
    );
    let mut req = client.get(&manifest_url).header(
        "Accept",
        "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
    );
    if let Some(ref token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let manifest: serde_json::Value = req.send().await?.json().await?;

    // If it's an index/manifest list, get the first manifest
    let manifest = if manifest.get("manifests").is_some() {
        let first = manifest["manifests"]
            .as_array()
            .and_then(|m| m.first())
            .ok_or_else(|| RegistryError::UnexpectedResponse("empty manifest list".into()))?;
        let digest = first["digest"]
            .as_str()
            .ok_or_else(|| RegistryError::UnexpectedResponse("manifest missing digest".into()))?;
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            parsed.registry, parsed.repository, digest
        );
        let mut req = client.get(&url).header(
            "Accept",
            "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
        );
        if let Some(ref token) = token {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req.send().await?.json().await?
    } else {
        manifest
    };

    // Get config digest
    let config_digest = manifest["config"]["digest"].as_str().ok_or_else(|| {
        RegistryError::UnexpectedResponse("manifest missing config digest".into())
    })?;

    // Fetch config blob
    let config_url = format!(
        "https://{}/v2/{}/blobs/{}",
        parsed.registry, parsed.repository, config_digest
    );
    let mut req = client.get(&config_url);
    if let Some(ref token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    let config: serde_json::Value = req.send().await?.json().await?;

    // Read label
    let label = config
        .get("config")
        .and_then(|c| c.get("Labels"))
        .and_then(|l| l.get("dev.airlock.tools"))
        .and_then(|v| v.as_str());

    match label {
        Some(value) => parse_tools_label(value),
        None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_label_bare_strings() {
        let tools = parse_tools_label(r#"["git","gh"]"#).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "git");
        assert_eq!(tools[1].name, "gh");
        assert!(tools[0].description.is_none());
    }

    #[test]
    fn parse_label_objects() {
        let tools =
            parse_tools_label(r#"[{"name":"deploy","description":"Deploy tool"}]"#).unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "deploy");
        assert_eq!(tools[0].description.as_deref(), Some("Deploy tool"));
    }

    #[test]
    fn parse_label_mixed() {
        let tools =
            parse_tools_label(r#"["git",{"name":"deploy","description":"Deploy"},"gh"]"#).unwrap();
        assert_eq!(tools.len(), 3);
        assert_eq!(tools[0].name, "git");
        assert!(tools[0].description.is_none());
        assert_eq!(tools[1].name, "deploy");
        assert_eq!(tools[1].description.as_deref(), Some("Deploy"));
        assert_eq!(tools[2].name, "gh");
    }

    #[test]
    fn parse_label_malformed_entry_skipped() {
        let tools = parse_tools_label(r#"["git",{"bad":true},"gh"]"#).unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "git");
        assert_eq!(tools[1].name, "gh");
    }

    #[test]
    fn parse_label_empty_array() {
        let tools = parse_tools_label("[]").unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn parse_label_not_json() {
        assert!(parse_tools_label("not json").is_err());
    }

    #[test]
    fn parse_label_string_missing_name() {
        let tools = parse_tools_label(r#"[{"description":"no name"}]"#).unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn parse_image_ref_full() {
        let r = parse_image_ref("ghcr.io/org/image:v1");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/image");
        assert_eq!(r.reference, "v1");
    }

    #[test]
    fn parse_image_ref_with_digest() {
        let r = parse_image_ref("ghcr.io/org/image@sha256:abc123");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/image");
        assert_eq!(r.reference, "sha256:abc123");
    }

    #[test]
    fn parse_image_ref_docker_hub() {
        let r = parse_image_ref("alpine/git:latest");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "alpine/git");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_image_ref_docker_hub_official() {
        let r = parse_image_ref("alpine:3.21");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "3.21");
    }

    #[test]
    fn parse_image_ref_no_tag() {
        let r = parse_image_ref("ghcr.io/org/image");
        assert_eq!(r.reference, "latest");
    }
}
