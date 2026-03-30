use std::collections::BTreeMap;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, EnvVarSource, KeyToPath, PodSpec, PodTemplateSpec, SecretKeySelector,
    SecretVolumeSource, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::{Api, Client};

use crate::crd::{AirlockChamberSpec, AirlockToolSpec};

pub fn build_tool_job(
    tool_name: &str,
    tool_spec: &AirlockToolSpec,
    chamber_spec: &AirlockChamberSpec,
    call_id: &str,
    namespace: &str,
    controller_addr: &str,
) -> Job {
    let job_name = format!("airlock-{tool_name}-{}", &call_id[..8]);
    let keepalive = chamber_spec.keepalive;

    let mut env_vars = vec![
        EnvVar {
            name: "AIRLOCK_CONTROLLER_ADDR".to_string(),
            value: Some(controller_addr.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "AIRLOCK_JOB_ID".to_string(),
            value: Some(call_id.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "AIRLOCK_TOOL_NAME".to_string(),
            value: Some(tool_name.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "AIRLOCK_EXEC_MODE".to_string(),
            value: Some("execve".to_string()),
            ..Default::default()
        },
    ];

    if keepalive {
        env_vars.push(EnvVar {
            name: "AIRLOCK_KEEPALIVE".to_string(),
            value: Some("true".to_string()),
            ..Default::default()
        });
    }

    let mut volumes = Vec::new();
    let mut volume_mounts = Vec::new();

    // Workspace PVC — always present from chamber
    let read_only = chamber_spec.workspace_mode == "readOnly";
    volumes.push(Volume {
        name: "workspace".to_string(),
        persistent_volume_claim: Some(
            k8s_openapi::api::core::v1::PersistentVolumeClaimVolumeSource {
                claim_name: chamber_spec.workspace.clone(),
                read_only: Some(read_only),
            },
        ),
        ..Default::default()
    });
    volume_mounts.push(VolumeMount {
        name: "workspace".to_string(),
        mount_path: chamber_spec.workspace_mount_path.clone(),
        read_only: Some(read_only),
        ..Default::default()
    });

    // Credentials from chamber
    for (i, cred) in chamber_spec.credentials.iter().enumerate() {
        if let Some(ref env_name) = cred.env {
            env_vars.push(EnvVar {
                name: env_name.clone(),
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        name: cred.secret.clone(),
                        key: cred.key.clone().unwrap_or_else(|| cred.secret.clone()),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            });
        } else if let Some(ref file_path) = cred.file {
            let vol_name = format!("cred-{i}");
            let (items, sub_path) = match &cred.key {
                Some(key) => {
                    let basename = std::path::Path::new(file_path)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("key")
                        .to_string();
                    (
                        Some(vec![KeyToPath {
                            key: key.clone(),
                            path: basename.clone(),
                            ..Default::default()
                        }]),
                        Some(basename),
                    )
                }
                None => (None, None),
            };
            volumes.push(Volume {
                name: vol_name.clone(),
                secret: Some(SecretVolumeSource {
                    secret_name: Some(cred.secret.clone()),
                    items,
                    ..Default::default()
                }),
                ..Default::default()
            });
            volume_mounts.push(VolumeMount {
                name: vol_name,
                mount_path: file_path.clone(),
                sub_path,
                read_only: Some(true),
                ..Default::default()
            });
        }
    }

    if !chamber_spec.credentials.is_empty() {
        let scrub_entries: Vec<serde_json::Value> = chamber_spec
            .credentials
            .iter()
            .map(|cred| {
                let mut entry = serde_json::json!({"name": cred.secret});
                if let Some(ref env_name) = cred.env {
                    entry["env"] = serde_json::json!(env_name);
                } else if let Some(ref file_path) = cred.file {
                    entry["file"] = serde_json::json!(file_path);
                }
                entry
            })
            .collect();
        env_vars.push(EnvVar {
            name: "AIRLOCK_SCRUB_SECRETS".to_string(),
            value: Some(serde_json::to_string(&scrub_entries).unwrap()),
            ..Default::default()
        });
    }

    let container = Container {
        name: "runtime".to_string(),
        image: Some(tool_spec.image.clone()),
        env: Some(env_vars),
        volume_mounts: Some(volume_mounts),
        ..Default::default()
    };

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/part-of".to_string(),
        "sycophant".to_string(),
    );
    labels.insert("airlock.dev/tool".to_string(), tool_name.to_string());
    labels.insert("airlock.dev/call-id".to_string(), call_id.to_string());
    labels.insert("airlock.dev/chamber".to_string(), tool_spec.chamber.clone());

    let mut pod_labels = BTreeMap::new();
    pod_labels.insert("airlock.dev/chamber".to_string(), tool_spec.chamber.clone());
    pod_labels.insert("airlock.dev/tool".to_string(), tool_name.to_string());

    Job {
        metadata: ObjectMeta {
            name: Some(job_name),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(JobSpec {
            ttl_seconds_after_finished: Some(30),
            backoff_limit: Some(0),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(pod_labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    restart_policy: Some(if keepalive {
                        "OnFailure".to_string()
                    } else {
                        "Never".to_string()
                    }),
                    share_process_namespace: Some(false),
                    containers: vec![container],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub async fn create_job(client: &Client, namespace: &str, job: &Job) -> anyhow::Result<Job> {
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    let result = jobs.create(&PostParams::default(), job).await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{AirlockChamberSpec, AirlockToolSpec, CredentialMapping};

    const TEST_CALL_ID: &str = "abcdef12-0000-0000-0000-000000000000";

    fn base_tool_spec() -> AirlockToolSpec {
        AirlockToolSpec {
            chamber: "test-chamber".to_string(),
            description: "test tool".to_string(),
            image: "ghcr.io/test/airlock-git:latest".to_string(),
            command: "git push".to_string(),
            max_calls: 0,
        }
    }

    fn base_chamber_spec() -> AirlockChamberSpec {
        AirlockChamberSpec {
            workspace: "workspace-data".to_string(),
            workspace_mode: "readWrite".to_string(),
            workspace_mount_path: "/workspace".to_string(),
            credentials: vec![],
            egress: vec![],
            keepalive: false,
        }
    }

    fn test_job(tool_spec: &AirlockToolSpec, chamber_spec: &AirlockChamberSpec) -> Job {
        build_tool_job(
            "git-push",
            tool_spec,
            chamber_spec,
            TEST_CALL_ID,
            "test-ns",
            "http://controller:9090",
        )
    }

    fn pod_spec(job: &Job) -> &PodSpec {
        job.spec.as_ref().unwrap().template.spec.as_ref().unwrap()
    }

    fn container(job: &Job) -> &Container {
        &pod_spec(job).containers[0]
    }

    fn env_map(job: &Job) -> BTreeMap<&str, &str> {
        container(job)
            .env
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|e| e.value.as_deref().map(|v| (e.name.as_str(), v)))
            .collect()
    }

    #[test]
    fn job_has_correct_metadata() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());

        assert_eq!(
            job.metadata.name.as_deref(),
            Some("airlock-git-push-abcdef12")
        );
        assert_eq!(job.metadata.namespace.as_deref(), Some("test-ns"));

        let labels = job.metadata.labels.as_ref().unwrap();
        assert_eq!(labels["app.kubernetes.io/part-of"], "sycophant");
        assert_eq!(labels["airlock.dev/tool"], "git-push");
        assert_eq!(labels["airlock.dev/chamber"], "test-chamber");
    }

    #[test]
    fn pod_template_has_chamber_label() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        let pod_labels = job
            .spec
            .as_ref()
            .unwrap()
            .template
            .metadata
            .as_ref()
            .unwrap()
            .labels
            .as_ref()
            .unwrap();
        assert_eq!(pod_labels["airlock.dev/chamber"], "test-chamber");
        assert_eq!(pod_labels["airlock.dev/tool"], "git-push");
    }

    #[test]
    fn job_has_correct_env_vars() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        let env = env_map(&job);

        assert_eq!(env["AIRLOCK_CONTROLLER_ADDR"], "http://controller:9090");
        assert_eq!(env["AIRLOCK_JOB_ID"], TEST_CALL_ID);
        assert_eq!(env["AIRLOCK_TOOL_NAME"], "git-push");
        assert_eq!(env["AIRLOCK_EXEC_MODE"], "execve");
        assert!(!env.contains_key("AIRLOCK_KEEPALIVE"));
    }

    #[test]
    fn keepalive_job_has_env_and_restart_policy() {
        let mut chamber = base_chamber_spec();
        chamber.keepalive = true;
        let job = test_job(&base_tool_spec(), &chamber);
        let env = env_map(&job);

        assert_eq!(env.get("AIRLOCK_KEEPALIVE"), Some(&"true"));
        assert_eq!(pod_spec(&job).restart_policy.as_deref(), Some("OnFailure"));
    }

    #[test]
    fn fire_and_forget_restart_policy() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        assert_eq!(pod_spec(&job).restart_policy.as_deref(), Some("Never"));
        assert_eq!(job.spec.as_ref().unwrap().backoff_limit, Some(0));
    }

    #[test]
    fn workspace_pvc_mounted() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        let ws_vol = volumes.iter().find(|v| v.name == "workspace").unwrap();
        let pvc = ws_vol.persistent_volume_claim.as_ref().unwrap();
        assert_eq!(pvc.claim_name, "workspace-data");
        assert_eq!(pvc.read_only, Some(false));

        let mounts = container(&job).volume_mounts.as_ref().unwrap();
        let ws_mount = mounts.iter().find(|m| m.name == "workspace").unwrap();
        assert_eq!(ws_mount.mount_path, "/workspace");
        assert_eq!(ws_mount.read_only, Some(false));
    }

    #[test]
    fn workspace_read_only() {
        let mut chamber = base_chamber_spec();
        chamber.workspace_mode = "readOnly".to_string();
        let job = test_job(&base_tool_spec(), &chamber);

        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        let ws_vol = volumes.iter().find(|v| v.name == "workspace").unwrap();
        assert_eq!(
            ws_vol.persistent_volume_claim.as_ref().unwrap().read_only,
            Some(true)
        );

        let mounts = container(&job).volume_mounts.as_ref().unwrap();
        let ws_mount = mounts.iter().find(|m| m.name == "workspace").unwrap();
        assert_eq!(ws_mount.read_only, Some(true));
    }

    #[test]
    fn credential_env_mode() {
        let mut chamber = base_chamber_spec();
        chamber.credentials.push(CredentialMapping {
            secret: "github-token".to_string(),
            key: Some("token".to_string()),
            env: Some("GITHUB_TOKEN".to_string()),
            file: None,
        });

        let job = test_job(&base_tool_spec(), &chamber);
        let env_vars = container(&job).env.as_ref().unwrap();
        let gh_env = env_vars.iter().find(|e| e.name == "GITHUB_TOKEN").unwrap();

        let secret_ref = gh_env
            .value_from
            .as_ref()
            .unwrap()
            .secret_key_ref
            .as_ref()
            .unwrap();
        assert_eq!(secret_ref.name, "github-token");
        assert_eq!(secret_ref.key, "token");
    }

    #[test]
    fn credential_file_mode() {
        let mut chamber = base_chamber_spec();
        chamber.credentials.push(CredentialMapping {
            secret: "git-ssh-key".to_string(),
            key: Some("id_ed25519".to_string()),
            env: None,
            file: Some("/run/secrets/airlock/git/id_ed25519".to_string()),
        });

        let job = test_job(&base_tool_spec(), &chamber);
        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        let cred_vol = volumes.iter().find(|v| v.name == "cred-0").unwrap();
        let secret = cred_vol.secret.as_ref().unwrap();
        assert_eq!(secret.secret_name.as_deref(), Some("git-ssh-key"));
        assert_eq!(secret.items.as_ref().unwrap()[0].key, "id_ed25519");

        let mounts = container(&job).volume_mounts.as_ref().unwrap();
        let cred_mount = mounts.iter().find(|m| m.name == "cred-0").unwrap();
        assert_eq!(cred_mount.mount_path, "/run/secrets/airlock/git/id_ed25519");
        assert_eq!(cred_mount.sub_path.as_deref(), Some("id_ed25519"));
        assert_eq!(cred_mount.read_only, Some(true));
    }

    #[test]
    fn ttl_seconds_set() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        assert_eq!(
            job.spec.as_ref().unwrap().ttl_seconds_after_finished,
            Some(30)
        );
    }

    #[test]
    fn correct_image() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        assert_eq!(
            container(&job).image.as_deref(),
            Some("ghcr.io/test/airlock-git:latest")
        );
    }

    fn scrub_env(job: &Job) -> Option<String> {
        container(job)
            .env
            .as_ref()
            .unwrap()
            .iter()
            .find(|e| e.name == "AIRLOCK_SCRUB_SECRETS")
            .and_then(|e| e.value.clone())
    }

    #[test]
    fn scrub_secrets_env_var_absent_for_zero_credential_chamber() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        assert!(scrub_env(&job).is_none());
    }

    #[test]
    fn scrub_secrets_env_var_set_for_credentialed_chamber() {
        let mut chamber = base_chamber_spec();
        chamber.credentials.push(CredentialMapping {
            secret: "db-url".to_string(),
            key: None,
            env: Some("DATABASE_URL".to_string()),
            file: None,
        });
        let job = test_job(&base_tool_spec(), &chamber);
        assert!(scrub_env(&job).is_some());
    }

    #[test]
    fn scrub_secrets_env_maps_correctly() {
        let mut chamber = base_chamber_spec();
        chamber.credentials.push(CredentialMapping {
            secret: "stripe-key".to_string(),
            key: Some("api_key".to_string()),
            env: Some("STRIPE_KEY".to_string()),
            file: None,
        });
        let job = test_job(&base_tool_spec(), &chamber);
        let json: Vec<serde_json::Value> = serde_json::from_str(&scrub_env(&job).unwrap()).unwrap();
        assert_eq!(json[0]["name"], "stripe-key");
        assert_eq!(json[0]["env"], "STRIPE_KEY");
        assert!(json[0].get("file").is_none());
    }

    #[test]
    fn scrub_secrets_file_maps_correctly() {
        let mut chamber = base_chamber_spec();
        chamber.credentials.push(CredentialMapping {
            secret: "ssh-key".to_string(),
            key: Some("id_ed25519".to_string()),
            env: None,
            file: Some("/run/secrets/ssh/id_ed25519".to_string()),
        });
        let job = test_job(&base_tool_spec(), &chamber);
        let json: Vec<serde_json::Value> = serde_json::from_str(&scrub_env(&job).unwrap()).unwrap();
        assert_eq!(json[0]["name"], "ssh-key");
        assert_eq!(json[0]["file"], "/run/secrets/ssh/id_ed25519");
        assert!(json[0].get("env").is_none());
    }

    #[test]
    fn share_process_namespace_disabled() {
        let job = test_job(&base_tool_spec(), &base_chamber_spec());
        assert_eq!(pod_spec(&job).share_process_namespace, Some(false));
    }
}
