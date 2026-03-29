use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use tracing::{info, warn};

use crate::crd::AirlockTool;
use crate::state::ControllerState;

pub async fn watch_tools(
    client: Client,
    namespace: &str,
    state: Arc<ControllerState>,
    ready_tx: tokio::sync::watch::Sender<bool>,
) -> anyhow::Result<()> {
    let api: Api<AirlockTool> = Api::namespaced(client, namespace);
    let watcher_config = watcher::Config::default();
    let mut stream = watcher::watcher(api, watcher_config).boxed();

    while let Some(event) = stream.try_next().await? {
        match event {
            Event::Apply(tool) => {
                let name = tool.metadata.name.clone().unwrap_or_default();
                info!(tool = %name, "tool applied");
                state.set_tool(name, tool).await;
            }
            Event::Delete(tool) => {
                let name = tool.metadata.name.clone().unwrap_or_default();
                info!(tool = %name, "tool deleted");
                state.remove_tool(&name).await;
            }
            Event::Init => {
                info!("tool watcher initialized, clearing registry");
                state.clear_tools().await;
            }
            Event::InitApply(tool) => {
                let name = tool.metadata.name.clone().unwrap_or_default();
                state.set_tool(name, tool).await;
            }
            Event::InitDone => {
                let count = state.tool_count().await;
                info!(count, "tool watcher initial sync complete");
                let _ = ready_tx.send(true);
            }
        }
    }

    warn!("tool watcher stream ended");
    Ok(())
}
