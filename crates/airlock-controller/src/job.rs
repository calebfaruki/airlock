use std::collections::BTreeMap;

use k8s_openapi::api::batch::v1::{Job, JobSpec};
use k8s_openapi::api::core::v1::{
    Container, EnvVar, PodSpec, PodTemplateSpec, SecretVolumeSource, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::PostParams;
use kube::{Api, Client};

use crate::crd::AirlockToolSpec;

pub fn build_tool_job(
    tool_name: &str,
    spec: &AirlockToolSpec,
    call_id: &str,
    namespace: &str,
    controller_addr: &str,
    keepalive: bool,
) -> Job {
    let job_name = format!("airlock-{tool_name}-{}", &call_id[..8]);

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

    if spec.workspace_pvc {
        volumes.push(Volume {
            name: "workspace".to_string(),
            persistent_volume_claim: Some(
                k8s_openapi::api::core::v1::PersistentVolumeClaimVolumeSource {
                    claim_name: "workspace-data".to_string(),
                    read_only: Some(false),
                },
            ),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name: "workspace".to_string(),
            mount_path: spec.working_dir.clone(),
            ..Default::default()
        });
    }

    if let Some(ref cred) = spec.credential {
        volumes.push(Volume {
            name: "credential".to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(cred.secret_name.clone()),
                ..Default::default()
            }),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name: "credential".to_string(),
            mount_path: cred.mount_path.clone(),
            read_only: Some(true),
            ..Default::default()
        });
    }

    let container = Container {
        name: "agent".to_string(),
        image: Some(spec.image.clone()),
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
                spec: Some(PodSpec {
                    restart_policy: Some(if keepalive {
                        "OnFailure".to_string()
                    } else {
                        "Never".to_string()
                    }),
                    containers: vec![container],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
                ..Default::default()
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

pub async fn delete_job(client: &Client, namespace: &str, name: &str) -> anyhow::Result<()> {
    let jobs: Api<Job> = Api::namespaced(client.clone(), namespace);
    jobs.delete(name, &Default::default()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::CredentialSpec;

    const TEST_CALL_ID: &str = "abcdef12-0000-0000-0000-000000000000";

    fn base_spec() -> AirlockToolSpec {
        AirlockToolSpec {
            description: "test tool".to_string(),
            parameters: serde_json::json!({}),
            image: "ghcr.io/test/airlock-git:latest".to_string(),
            command: "git push {remote} {branch}".to_string(),
            working_dir: "/workspace".to_string(),
            workspace_pvc: true,
            credential: None,
            keepalive: 0,
            max_calls: 0,
        }
    }

    fn test_job(spec: &AirlockToolSpec, keepalive: bool) -> Job {
        build_tool_job(
            "git-push",
            spec,
            TEST_CALL_ID,
            "test-ns",
            "http://controller:9090",
            keepalive,
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
            .map(|e| (e.name.as_str(), e.value.as_deref().unwrap_or("")))
            .collect()
    }

    #[test]
    fn job_has_correct_metadata() {
        let job = test_job(&base_spec(), false);

        assert_eq!(
            job.metadata.name.as_deref(),
            Some("airlock-git-push-abcdef12")
        );
        assert_eq!(job.metadata.namespace.as_deref(), Some("test-ns"));

        let labels = job.metadata.labels.as_ref().unwrap();
        assert_eq!(labels["app.kubernetes.io/part-of"], "sycophant");
        assert_eq!(labels["airlock.dev/tool"], "git-push");
    }

    #[test]
    fn job_has_correct_env_vars() {
        let job = test_job(&base_spec(), false);
        let env = env_map(&job);

        assert_eq!(env["AIRLOCK_CONTROLLER_ADDR"], "http://controller:9090");
        assert_eq!(env["AIRLOCK_JOB_ID"], TEST_CALL_ID);
        assert_eq!(env["AIRLOCK_TOOL_NAME"], "git-push");
        assert!(!env.contains_key("AIRLOCK_KEEPALIVE"));
    }

    #[test]
    fn keepalive_job_has_env_and_restart_policy() {
        let job = test_job(&base_spec(), true);
        let env = env_map(&job);

        assert_eq!(env.get("AIRLOCK_KEEPALIVE"), Some(&"true"));
        assert_eq!(pod_spec(&job).restart_policy.as_deref(), Some("OnFailure"));
    }

    #[test]
    fn fire_and_forget_restart_policy() {
        let job = test_job(&base_spec(), false);
        assert_eq!(pod_spec(&job).restart_policy.as_deref(), Some("Never"));
        assert_eq!(job.spec.as_ref().unwrap().backoff_limit, Some(0));
    }

    #[test]
    fn workspace_pvc_mounted() {
        let job = test_job(&base_spec(), false);
        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        let ws_vol = volumes.iter().find(|v| v.name == "workspace").unwrap();
        assert_eq!(
            ws_vol.persistent_volume_claim.as_ref().unwrap().claim_name,
            "workspace-data"
        );

        let mounts = container(&job).volume_mounts.as_ref().unwrap();
        let ws_mount = mounts.iter().find(|m| m.name == "workspace").unwrap();
        assert_eq!(ws_mount.mount_path, "/workspace");
    }

    #[test]
    fn no_workspace_pvc_when_disabled() {
        let mut spec = base_spec();
        spec.workspace_pvc = false;

        let job = test_job(&spec, false);
        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        assert!(!volumes.iter().any(|v| v.name == "workspace"));
    }

    #[test]
    fn credential_secret_mounted() {
        let mut spec = base_spec();
        spec.credential = Some(CredentialSpec {
            secret_name: "git-ssh-key".to_string(),
            mount_path: "/run/secrets/airlock/git".to_string(),
        });

        let job = test_job(&spec, false);
        let volumes = pod_spec(&job).volumes.as_ref().unwrap();
        let cred_vol = volumes.iter().find(|v| v.name == "credential").unwrap();
        assert_eq!(
            cred_vol.secret.as_ref().unwrap().secret_name.as_deref(),
            Some("git-ssh-key")
        );

        let mounts = container(&job).volume_mounts.as_ref().unwrap();
        let cred_mount = mounts.iter().find(|m| m.name == "credential").unwrap();
        assert_eq!(cred_mount.mount_path, "/run/secrets/airlock/git");
        assert_eq!(cred_mount.read_only, Some(true));
    }

    #[test]
    fn ttl_seconds_set() {
        let job = test_job(&base_spec(), false);
        assert_eq!(
            job.spec.as_ref().unwrap().ttl_seconds_after_finished,
            Some(30)
        );
    }

    #[test]
    fn correct_image() {
        let job = test_job(&base_spec(), false);
        assert_eq!(
            container(&job).image.as_deref(),
            Some("ghcr.io/test/airlock-git:latest")
        );
    }
}
