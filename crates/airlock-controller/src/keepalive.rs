use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{info, warn};

use crate::state::ControllerState;

const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub async fn find_expired_jobs(state: &ControllerState, now: Instant) -> Vec<(String, String)> {
    state
        .list_active_jobs()
        .await
        .into_iter()
        .filter(|(_, _, keepalive_secs, last_activity)| {
            *keepalive_secs > 0 && now.duration_since(*last_activity).as_secs() >= *keepalive_secs
        })
        .map(|(name, job_name, _, _)| (name, job_name))
        .collect()
}

pub async fn remove_expired_jobs(state: &ControllerState, expired: &[(String, String)]) {
    for (tool_name, job_name) in expired {
        info!(tool = %tool_name, job = %job_name, "deleting idle keepalive Job");
        state.remove_active_job(tool_name).await;
    }

    if !expired.is_empty() {
        warn!(count = expired.len(), "cleaned up expired keepalive Jobs");
    }
}

pub async fn cleanup_loop(state: Arc<ControllerState>) {
    loop {
        tokio::time::sleep(CLEANUP_INTERVAL).await;
        let expired = find_expired_jobs(&state, Instant::now()).await;
        remove_expired_jobs(&state, &expired).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ActiveJob;

    fn make_active_job(tool: &str, idle_secs: u64, keepalive_secs: u64) -> (String, ActiveJob) {
        (
            tool.to_string(),
            ActiveJob {
                job_name: format!("airlock-{tool}-abc"),
                tool_name: tool.to_string(),
                last_activity: Instant::now() - Duration::from_secs(idle_secs),
                keepalive_seconds: keepalive_secs,
            },
        )
    }

    #[tokio::test]
    async fn expired_job_removed() {
        let state = ControllerState::new(None, String::new(), String::new());
        let (name, job) = make_active_job("test-tool", 120, 60);
        state.set_active_job(name, job).await;

        let expired = find_expired_jobs(&state, Instant::now()).await;
        remove_expired_jobs(&state, &expired).await;

        assert_eq!(state.active_job_count().await, 0);
    }

    #[tokio::test]
    async fn active_job_not_removed() {
        let state = ControllerState::new(None, String::new(), String::new());
        let (name, job) = make_active_job("active-tool", 0, 300);
        state.set_active_job(name, job).await;

        let expired = find_expired_jobs(&state, Instant::now()).await;
        remove_expired_jobs(&state, &expired).await;

        assert_eq!(state.active_job_count().await, 1);
    }

    #[tokio::test]
    async fn zero_keepalive_never_expires() {
        let state = ControllerState::new(None, String::new(), String::new());
        let (name, job) = make_active_job("fire-forget", 9999, 0);
        state.set_active_job(name, job).await;

        let expired = find_expired_jobs(&state, Instant::now()).await;
        assert!(expired.is_empty());
    }

    #[tokio::test]
    async fn multiple_expired_at_once() {
        let state = ControllerState::new(None, String::new(), String::new());
        let (n1, j1) = make_active_job("tool-a", 120, 60);
        let (n2, j2) = make_active_job("tool-b", 200, 60);
        state.set_active_job(n1, j1).await;
        state.set_active_job(n2, j2).await;

        let expired = find_expired_jobs(&state, Instant::now()).await;
        assert_eq!(expired.len(), 2);

        remove_expired_jobs(&state, &expired).await;
        assert_eq!(state.active_job_count().await, 0);
    }

    #[tokio::test]
    async fn counters_independent_per_tool() {
        let state = ControllerState::new(None, String::new(), String::new());
        state.increment_call_count("tool-a").await;
        state.increment_call_count("tool-a").await;
        state.increment_call_count("tool-a").await;
        state.increment_call_count("tool-b").await;

        assert_eq!(state.get_call_count("tool-a").await, 3);
        assert_eq!(state.get_call_count("tool-b").await, 1);
    }
}
