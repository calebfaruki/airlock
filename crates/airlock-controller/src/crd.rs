use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "airlock.dev",
    version = "v1",
    kind = "AirlockTool",
    namespaced,
    printcolumn = r#"{"name":"Image","type":"string","jsonPath":".spec.image"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct AirlockToolSpec {
    pub description: String,

    /// JSON Schema describing tool parameters (passed through to ListTools).
    #[schemars(schema_with = "parameters_schema")]
    pub parameters: serde_json::Value,

    /// Container image that includes the airlock-agent binary.
    pub image: String,

    /// Command template with `{param_name}` placeholders.
    pub command: String,

    /// Working directory inside the Job container.
    #[serde(default = "default_working_dir")]
    pub working_dir: String,

    /// Mount the workspace-data PVC into the Job.
    #[serde(default = "default_true", rename = "workspacePVC")]
    pub workspace_pvc: bool,

    /// Optional credential Secret to mount into the Job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CredentialSpec>,

    /// Seconds to keep the Job alive after the last call. 0 = fire-and-forget.
    #[serde(default)]
    pub keepalive: u64,

    /// Maximum number of invocations. 0 = unlimited.
    #[serde(default)]
    pub max_calls: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSpec {
    pub secret_name: String,
    pub mount_path: String,
}

fn default_working_dir() -> String {
    "/workspace".to_string()
}

fn default_true() -> bool {
    true
}

fn parameters_schema(_: &mut schemars::generate::SchemaGenerator) -> schemars::Schema {
    serde_json::from_value(serde_json::json!({
        "type": "object",
        "description": "JSON Schema describing tool parameters (passed through to ListTools).",
        "x-kubernetes-preserve-unknown-fields": true
    }))
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_full_spec() {
        let json = serde_json::json!({
            "description": "Push commits to a remote branch",
            "parameters": {
                "type": "object",
                "properties": {
                    "remote": { "type": "string", "default": "origin" },
                    "branch": { "type": "string" }
                },
                "required": ["branch"]
            },
            "image": "ghcr.io/calebfaruki/airlock-git:latest",
            "command": "git push {remote} {branch}",
            "workingDir": "/workspace",
            "workspacePVC": true,
            "credential": {
                "secretName": "git-ssh-key",
                "mountPath": "/run/secrets/airlock/git"
            },
            "keepalive": 0,
            "maxCalls": 0
        });

        let spec: AirlockToolSpec = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(spec.description, "Push commits to a remote branch");
        assert_eq!(spec.image, "ghcr.io/calebfaruki/airlock-git:latest");
        assert_eq!(spec.command, "git push {remote} {branch}");
        assert_eq!(spec.working_dir, "/workspace");
        assert!(spec.workspace_pvc);
        assert_eq!(spec.keepalive, 0);
        assert_eq!(spec.max_calls, 0);

        let cred = spec.credential.as_ref().unwrap();
        assert_eq!(cred.secret_name, "git-ssh-key");
        assert_eq!(cred.mount_path, "/run/secrets/airlock/git");

        let re_serialized = serde_json::to_value(&spec).unwrap();
        assert_eq!(re_serialized, json);
    }

    #[test]
    fn defaults_applied() {
        let json = serde_json::json!({
            "description": "Minimal tool",
            "parameters": { "type": "object" },
            "image": "alpine:latest",
            "command": "echo hello"
        });

        let spec: AirlockToolSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.working_dir, "/workspace");
        assert!(spec.workspace_pvc);
        assert!(spec.credential.is_none());
        assert_eq!(spec.keepalive, 0);
        assert_eq!(spec.max_calls, 0);
    }

    #[test]
    fn credential_absent() {
        let json = serde_json::json!({
            "description": "No creds",
            "parameters": {},
            "image": "alpine:latest",
            "command": "ls"
        });

        let spec: AirlockToolSpec = serde_json::from_value(json).unwrap();
        assert!(spec.credential.is_none());

        let serialized = serde_json::to_value(&spec).unwrap();
        assert!(serialized.get("credential").is_none());
    }

    #[test]
    fn parameters_json_schema_round_trip() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "branch": { "type": "string" },
                "force": { "type": "boolean", "default": false }
            },
            "required": ["branch"]
        });

        let json = serde_json::json!({
            "description": "test",
            "parameters": schema,
            "image": "test:latest",
            "command": "test"
        });

        let spec: AirlockToolSpec = serde_json::from_value(json).unwrap();
        assert_eq!(spec.parameters["required"][0], "branch");
        assert_eq!(spec.parameters["properties"]["force"]["default"], false);
    }

    #[test]
    fn crd_schema_generates() {
        use kube::CustomResourceExt;
        let crd = AirlockTool::crd();
        assert_eq!(
            crd.metadata.name.as_deref(),
            Some("airlocktools.airlock.dev")
        );
    }

    #[test]
    fn crd_parameters_has_type_and_preserve() {
        use kube::CustomResourceExt;
        let crd = AirlockTool::crd();
        let crd_json = serde_json::to_value(&crd).unwrap();
        let params_schema = &crd_json["spec"]["versions"][0]["schema"]["openAPIV3Schema"]
            ["properties"]["spec"]["properties"]["parameters"];

        assert_eq!(params_schema["type"], "object");
        assert_eq!(params_schema["x-kubernetes-preserve-unknown-fields"], true);
    }
}
