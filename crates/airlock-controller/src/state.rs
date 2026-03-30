use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{oneshot, Notify, RwLock};

use crate::crd::{AirlockChamber, AirlockTool};

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
    tools: RwLock<HashMap<String, AirlockTool>>,
    chambers: RwLock<HashMap<String, AirlockChamber>>,
    pending_calls: RwLock<HashMap<String, Vec<PendingCall>>>,
    call_notify: Notify,
    result_txs: RwLock<HashMap<String, oneshot::Sender<ToolCallResult>>>,
    active_jobs: RwLock<HashMap<String, ActiveJob>>,
    call_counts: RwLock<HashMap<String, u32>>,
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
            call_counts: RwLock::new(HashMap::new()),
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

    pub async fn get_tool(&self, name: &str) -> Option<AirlockTool> {
        self.tools.read().await.get(name).cloned()
    }

    pub async fn list_tools(&self) -> Vec<(String, AirlockTool)> {
        self.tools
            .read()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    pub async fn set_tool(&self, name: String, tool: AirlockTool) {
        self.tools.write().await.insert(name, tool);
    }

    pub async fn remove_tool(&self, name: &str) {
        self.tools.write().await.remove(name);
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

    // -- Call counters --

    pub async fn get_call_count(&self, tool_name: &str) -> u32 {
        self.call_counts
            .read()
            .await
            .get(tool_name)
            .copied()
            .unwrap_or(0)
    }

    pub async fn increment_call_count(&self, tool_name: &str) {
        let mut counts = self.call_counts.write().await;
        let count = counts.entry(tool_name.to_string()).or_insert(0);
        *count += 1;
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
    use crate::crd::{AirlockChamber, AirlockChamberSpec, AirlockTool, AirlockToolSpec};

    fn test_tool(name: &str) -> AirlockTool {
        AirlockTool::new(
            name,
            AirlockToolSpec {
                chamber: "c".to_string(),
                description: "d".to_string(),
                image: "i".to_string(),
                command: "cmd".to_string(),
                max_calls: 0,
            },
        )
    }

    fn test_chamber(name: &str) -> AirlockChamber {
        AirlockChamber::new(
            name,
            AirlockChamberSpec {
                workspace: "ws".to_string(),
                workspace_mode: "readWrite".to_string(),
                workspace_mount_path: "/workspace".to_string(),
                credentials: vec![],
                egress: vec![],
                keepalive: false,
            },
        )
    }

    #[tokio::test]
    async fn tool_count_reflects_insertions() {
        let state = ControllerState::new(None, String::new(), String::new());
        assert_eq!(state.tool_count().await, 0);
        state.set_tool("a".into(), test_tool("a")).await;
        state.set_tool("b".into(), test_tool("b")).await;
        assert_eq!(state.tool_count().await, 2);
    }

    #[tokio::test]
    async fn clear_tools_empties_registry() {
        let state = ControllerState::new(None, String::new(), String::new());
        state.set_tool("a".into(), test_tool("a")).await;
        state.clear_tools().await;
        assert_eq!(state.tool_count().await, 0);
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
