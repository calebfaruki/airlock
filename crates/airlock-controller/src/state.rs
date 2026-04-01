use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{oneshot, Notify, RwLock};
use tracing::warn;

use crate::crd::AirlockChamber;

pub struct RegisteredTool {
    pub name: String,
    pub chamber_name: String,
    pub description: String,
    pub image: String,
}

pub struct ToolCallResult {
    pub output: String,
    pub is_error: bool,
    pub exit_code: i32,
}

pub struct PendingCall {
    pub call_id: String,
    pub tool_name: String,
    pub input_json: String,
    pub command_template: String,
    pub working_dir: String,
}

pub struct ActiveJob {
    pub job_name: String,
    pub tool_name: String,
    pub last_activity: Instant,
    pub keepalive_seconds: u64,
}

pub struct ControllerState {
    tools: RwLock<HashMap<String, RegisteredTool>>,
    chambers: RwLock<HashMap<String, AirlockChamber>>,
    pending_calls: RwLock<HashMap<String, Vec<PendingCall>>>,
    call_notify: Notify,
    result_txs: RwLock<HashMap<String, oneshot::Sender<ToolCallResult>>>,
    active_jobs: RwLock<HashMap<String, ActiveJob>>,
    kube_client: Option<kube::Client>,
    namespace: String,
    controller_addr: String,
}

impl ControllerState {
    pub fn new(
        kube_client: Option<kube::Client>,
        namespace: String,
        controller_addr: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            tools: RwLock::new(HashMap::new()),
            chambers: RwLock::new(HashMap::new()),
            pending_calls: RwLock::new(HashMap::new()),
            call_notify: Notify::new(),
            result_txs: RwLock::new(HashMap::new()),
            active_jobs: RwLock::new(HashMap::new()),
            kube_client,
            namespace,
            controller_addr,
        })
    }

    pub fn kube_client(&self) -> Option<&kube::Client> {
        self.kube_client.as_ref()
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn controller_addr(&self) -> &str {
        &self.controller_addr
    }

    // -- Tool registry --

    pub async fn get_tool(&self, name: &str) -> Option<(String, String, String)> {
        let tools = self.tools.read().await;
        tools.get(name).map(|t| {
            (
                t.chamber_name.clone(),
                t.image.clone(),
                t.description.clone(),
            )
        })
    }

    pub async fn list_tools(&self) -> Vec<(String, RegisteredTool)> {
        self.tools
            .read()
            .await
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    RegisteredTool {
                        name: v.name.clone(),
                        chamber_name: v.chamber_name.clone(),
                        description: v.description.clone(),
                        image: v.image.clone(),
                    },
                )
            })
            .collect()
    }

    pub async fn set_tools_for_chamber(&self, chamber_name: &str, tools: Vec<RegisteredTool>) {
        let mut registry = self.tools.write().await;
        registry.retain(|_, t| t.chamber_name != chamber_name);
        for tool in tools {
            if registry.contains_key(&tool.name) {
                warn!(
                    tool = %tool.name,
                    chamber = %chamber_name,
                    "duplicate tool name, first chamber wins"
                );
                continue;
            }
            registry.insert(tool.name.clone(), tool);
        }
    }

    pub async fn remove_tools_for_chamber(&self, chamber_name: &str) {
        self.tools
            .write()
            .await
            .retain(|_, t| t.chamber_name != chamber_name);
    }

    pub async fn clear_tools(&self) {
        self.tools.write().await.clear();
    }

    pub async fn tool_count(&self) -> usize {
        self.tools.read().await.len()
    }

    // -- Chamber registry --

    pub async fn get_chamber(&self, name: &str) -> Option<AirlockChamber> {
        self.chambers.read().await.get(name).cloned()
    }

    pub async fn set_chamber(&self, name: String, chamber: AirlockChamber) {
        self.chambers.write().await.insert(name, chamber);
    }

    pub async fn remove_chamber(&self, name: &str) {
        self.chambers.write().await.remove(name);
    }

    pub async fn clear_chambers(&self) {
        self.chambers.write().await.clear();
    }

    pub async fn chamber_count(&self) -> usize {
        self.chambers.read().await.len()
    }

    // -- Call queue --

    pub async fn enqueue_call(&self, call: PendingCall) {
        self.pending_calls
            .write()
            .await
            .entry(call.tool_name.clone())
            .or_default()
            .push(call);
        self.call_notify.notify_waiters();
    }

    pub async fn dequeue_call(&self, tool_name: &str) -> Option<PendingCall> {
        let mut pending = self.pending_calls.write().await;
        let calls = pending.get_mut(tool_name)?;
        if calls.is_empty() {
            None
        } else {
            Some(calls.remove(0))
        }
    }

    pub async fn wait_for_call(&self) {
        self.call_notify.notified().await;
    }

    // -- Result channels --

    pub async fn set_result_tx(&self, call_id: String, tx: oneshot::Sender<ToolCallResult>) {
        self.result_txs.write().await.insert(call_id, tx);
    }

    pub async fn take_result_tx(&self, call_id: &str) -> Option<oneshot::Sender<ToolCallResult>> {
        self.result_txs.write().await.remove(call_id)
    }

    // -- Active jobs (keepalive) --

    pub async fn list_active_jobs(&self) -> Vec<(String, String, u64, Instant)> {
        self.active_jobs
            .read()
            .await
            .iter()
            .map(|(name, job)| {
                (
                    name.clone(),
                    job.job_name.clone(),
                    job.keepalive_seconds,
                    job.last_activity,
                )
            })
            .collect()
    }

    pub async fn set_active_job(&self, name: String, job: ActiveJob) {
        self.active_jobs.write().await.insert(name, job);
    }

    pub async fn remove_active_job(&self, name: &str) {
        self.active_jobs.write().await.remove(name);
    }

    pub async fn active_job_count(&self) -> usize {
        self.active_jobs.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{AirlockChamber, AirlockChamberSpec};

    fn test_chamber(name: &str) -> AirlockChamber {
        AirlockChamber::new(
            name,
            AirlockChamberSpec {
                image: None,
                workspace: "ws".to_string(),
                workspace_mode: "readWrite".to_string(),
                workspace_mount_path: "/workspace".to_string(),
                credentials: vec![],
                egress: vec![],
                keepalive: false,
            },
        )
    }

    fn test_registered_tool(name: &str, chamber: &str) -> RegisteredTool {
        RegisteredTool {
            name: name.to_string(),
            chamber_name: chamber.to_string(),
            description: format!("Execute a {name} command."),
            image: "test:latest".to_string(),
        }
    }

    #[tokio::test]
    async fn tool_count_reflects_insertions() {
        let state = ControllerState::new(None, String::new(), String::new());
        assert_eq!(state.tool_count().await, 0);
        state
            .set_tools_for_chamber(
                "c1",
                vec![
                    test_registered_tool("git", "c1"),
                    test_registered_tool("gh", "c1"),
                ],
            )
            .await;
        assert_eq!(state.tool_count().await, 2);
    }

    #[tokio::test]
    async fn clear_tools_empties_registry() {
        let state = ControllerState::new(None, String::new(), String::new());
        state
            .set_tools_for_chamber("c1", vec![test_registered_tool("git", "c1")])
            .await;
        state.clear_tools().await;
        assert_eq!(state.tool_count().await, 0);
    }

    #[tokio::test]
    async fn set_tools_replaces_chamber_tools() {
        let state = ControllerState::new(None, String::new(), String::new());
        state
            .set_tools_for_chamber("c1", vec![test_registered_tool("git", "c1")])
            .await;
        state
            .set_tools_for_chamber("c1", vec![test_registered_tool("gh", "c1")])
            .await;
        assert_eq!(state.tool_count().await, 1);
        assert!(state.get_tool("gh").await.is_some());
        assert!(state.get_tool("git").await.is_none());
    }

    #[tokio::test]
    async fn remove_tools_for_chamber_only_affects_that_chamber() {
        let state = ControllerState::new(None, String::new(), String::new());
        state
            .set_tools_for_chamber("c1", vec![test_registered_tool("git", "c1")])
            .await;
        state
            .set_tools_for_chamber("c2", vec![test_registered_tool("gh", "c2")])
            .await;
        state.remove_tools_for_chamber("c1").await;
        assert_eq!(state.tool_count().await, 1);
        assert!(state.get_tool("gh").await.is_some());
    }

    #[tokio::test]
    async fn duplicate_tool_name_first_chamber_wins() {
        let state = ControllerState::new(None, String::new(), String::new());
        state
            .set_tools_for_chamber("c1", vec![test_registered_tool("git", "c1")])
            .await;
        state
            .set_tools_for_chamber("c2", vec![test_registered_tool("git", "c2")])
            .await;
        assert_eq!(state.tool_count().await, 1);
        let (chamber, _, _) = state.get_tool("git").await.unwrap();
        assert_eq!(chamber, "c1");
    }

    #[tokio::test]
    async fn chamber_count_reflects_insertions() {
        let state = ControllerState::new(None, String::new(), String::new());
        assert_eq!(state.chamber_count().await, 0);
        state.set_chamber("a".into(), test_chamber("a")).await;
        state.set_chamber("b".into(), test_chamber("b")).await;
        assert_eq!(state.chamber_count().await, 2);
    }

    #[tokio::test]
    async fn clear_chambers_empties_registry() {
        let state = ControllerState::new(None, String::new(), String::new());
        state.set_chamber("a".into(), test_chamber("a")).await;
        state.clear_chambers().await;
        assert_eq!(state.chamber_count().await, 0);
    }

    #[tokio::test]
    async fn wait_for_call_blocks_until_notify() {
        let state = ControllerState::new(None, String::new(), String::new());
        let state2 = state.clone();

        let wait_handle = tokio::spawn(async move {
            state2.wait_for_call().await;
        });

        tokio::task::yield_now().await;
        assert!(!wait_handle.is_finished(), "should be blocking");

        state
            .enqueue_call(PendingCall {
                call_id: "c".into(),
                tool_name: "t".into(),
                input_json: "{}".into(),
                command_template: "cmd".into(),
                working_dir: "/w".into(),
            })
            .await;

        tokio::time::timeout(std::time::Duration::from_secs(2), wait_handle)
            .await
            .expect("wait_for_call should unblock")
            .unwrap();
    }
}
