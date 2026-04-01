use std::sync::Arc;

use futures::{StreamExt, TryStreamExt};
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client};
use tracing::{error, info, warn};

use crate::crd::AirlockChamber;
use crate::registry;
use crate::state::{ControllerState, RegisteredTool};

async fn discover_and_register_tools(state: &ControllerState, chamber_name: &str, image: &str) {
    match registry::discover_tools(image).await {
        Ok(discovered) => {
            let tools: Vec<RegisteredTool> = discovered
                .into_iter()
                .map(|d| RegisteredTool {
                    name: d.name.clone(),
                    chamber_name: chamber_name.to_string(),
                    description: d.description.unwrap_or_else(|| {
                        format!(
                            "Execute a {} command. Pass the full command as a string.",
                            d.name
                        )
                    }),
                    image: image.to_string(),
                })
                .collect();
            let count = tools.len();
            state.set_tools_for_chamber(chamber_name, tools).await;
            info!(chamber = %chamber_name, %image, count, "discovered tools from image");
        }
        Err(e) => {
            error!(chamber = %chamber_name, %image, error = %e, "tool discovery failed");
            state.remove_tools_for_chamber(chamber_name).await;
        }
    }
}

pub async fn watch_chambers(
    client: Client,
    namespace: &str,
    state: Arc<ControllerState>,
    ready_tx: tokio::sync::watch::Sender<bool>,
) -> anyhow::Result<()> {
    let api: Api<AirlockChamber> = Api::namespaced(client, namespace);
    let watcher_config = watcher::Config::default();
    let mut stream = watcher::watcher(api, watcher_config).boxed();

    while let Some(event) = stream.try_next().await? {
        match event {
            Event::Apply(chamber) => {
                let name = chamber.metadata.name.clone().unwrap_or_default();
                info!(chamber = %name, "chamber applied");
                if let Some(image) = &chamber.spec.image {
                    discover_and_register_tools(&state, &name, image).await;
                } else {
                    state.remove_tools_for_chamber(&name).await;
                }
                state.set_chamber(name, chamber).await;
            }
            Event::Delete(chamber) => {
                let name = chamber.metadata.name.clone().unwrap_or_default();
                info!(chamber = %name, "chamber deleted");
                state.remove_tools_for_chamber(&name).await;
                state.remove_chamber(&name).await;
            }
            Event::Init => {
                info!("chamber watcher initialized, clearing registries");
                state.clear_chambers().await;
                state.clear_tools().await;
            }
            Event::InitApply(chamber) => {
                let name = chamber.metadata.name.clone().unwrap_or_default();
                if let Some(image) = &chamber.spec.image {
                    discover_and_register_tools(&state, &name, image).await;
                }
                state.set_chamber(name, chamber).await;
            }
            Event::InitDone => {
                let chamber_count = state.chamber_count().await;
                let tool_count = state.tool_count().await;
                info!(
                    chamber_count,
                    tool_count, "chamber watcher initial sync complete"
                );
                let _ = ready_tx.send(true);
            }
        }
    }

    warn!("chamber watcher stream ended");
    Ok(())
}
