use std::collections::HashMap;
use std::env;

use airlock_agent::execute;
use airlock_proto::airlock_controller_client::AirlockControllerClient;
use airlock_proto::{GetToolCallRequest, SendToolResultRequest};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_target(false).init();

    let controller_addr =
        env::var("AIRLOCK_CONTROLLER_ADDR").expect("AIRLOCK_CONTROLLER_ADDR must be set");
    let job_id = env::var("AIRLOCK_JOB_ID").expect("AIRLOCK_JOB_ID must be set");
    let tool_name = env::var("AIRLOCK_TOOL_NAME").expect("AIRLOCK_TOOL_NAME must be set");
    let keepalive = env::var("AIRLOCK_KEEPALIVE").unwrap_or_default() == "true";

    info!(%controller_addr, %job_id, %tool_name, keepalive, "starting airlock-agent");

    let mut client = {
        let mut connected = None;
        for attempt in 1..=10u64 {
            match AirlockControllerClient::connect(controller_addr.clone()).await {
                Ok(c) => {
                    connected = Some(c);
                    break;
                }
                Err(e) if attempt < 10 => {
                    tracing::warn!(attempt, error = %e, "controller not ready, retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        connected.unwrap()
    };

    loop {
        let assignment = client
            .get_tool_call(GetToolCallRequest {
                job_id: job_id.clone(),
                tool_name: tool_name.clone(),
            })
            .await?
            .into_inner();

        info!(call_id = %assignment.call_id, "received tool call assignment");

        let params: HashMap<String, String> =
            serde_json::from_str(&assignment.input_json).unwrap_or_default();

        let (output, is_error, exit_code) =
            match execute::interpolate(&assignment.command_template, &params) {
                Ok(command) => {
                    let working_dir = if assignment.working_dir.is_empty() {
                        "/workspace"
                    } else {
                        &assignment.working_dir
                    };

                    match execute::execute_command(&command, working_dir).await {
                        Ok(result) => {
                            let combined = if result.stderr.is_empty() {
                                result.stdout
                            } else {
                                format!("{}{}", result.stdout, result.stderr)
                            };
                            (combined, result.exit_code != 0, result.exit_code)
                        }
                        Err(e) => (format!("execution error: {e}"), true, -1),
                    }
                }
                Err(e) => (format!("interpolation error: {e}"), true, -1),
            };

        client
            .send_tool_result(SendToolResultRequest {
                call_id: assignment.call_id,
                output,
                is_error,
                exit_code,
            })
            .await?;

        if !keepalive {
            info!("fire-and-forget mode, exiting");
            break;
        }
    }

    Ok(())
}
