use std::sync::Arc;

use tokio::sync::oneshot;
use tonic::{Request, Response, Status};
use tracing::info;
use uuid::Uuid;

use airlock_proto::airlock_controller_server::AirlockController;
use airlock_proto::{
    CallToolRequest, CallToolResponse, GetToolCallRequest, ListToolsRequest, ListToolsResponse,
    SendToolResultAck, SendToolResultRequest, ToolCallAssignment, ToolInfo,
};

use crate::job;
use crate::state::{ControllerState, PendingCall, ToolCallResult};

const TOOL_PARAMETERS_SCHEMA: &str = r#"{"type":"object","properties":{"command":{"type":"string","description":"The full command to execute"}},"required":["command"]}"#;

pub struct ControllerService {
    state: Arc<ControllerState>,
}

impl ControllerService {
    pub fn new(state: Arc<ControllerState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl AirlockController for ControllerService {
    async fn list_tools(
        &self,
        _request: Request<ListToolsRequest>,
    ) -> Result<Response<ListToolsResponse>, Status> {
        let tools = self.state.list_tools().await;
        let tool_infos: Vec<ToolInfo> = tools
            .into_iter()
            .map(|(name, tool)| ToolInfo {
                name,
                description: tool.description,
                parameters_json: TOOL_PARAMETERS_SCHEMA.to_string(),
            })
            .collect();

        Ok(Response::new(ListToolsResponse { tools: tool_infos }))
    }

    async fn call_tool(
        &self,
        request: Request<CallToolRequest>,
    ) -> Result<Response<CallToolResponse>, Status> {
        let req = request.into_inner();
        let tool_name = &req.name;

        let (chamber_name, image, _description) = self
            .state
            .get_tool(tool_name)
            .await
            .ok_or_else(|| Status::not_found(format!("unknown tool: {tool_name}")))?;

        let chamber = self.state.get_chamber(&chamber_name).await.ok_or_else(|| {
            Status::failed_precondition(format!("chamber {chamber_name} not found"))
        })?;

        let call_id = Uuid::new_v4().to_string();
        let command_template = "{command}".to_string();
        let working_dir = chamber.spec.workspace_mount_path.clone();

        if let Some(client) = self.state.kube_client() {
            let job_spec = job::build_tool_job(
                tool_name,
                &image,
                &chamber_name,
                &chamber.spec,
                &call_id,
                self.state.namespace(),
                self.state.controller_addr(),
            );
            match tokio::time::timeout(
                std::time::Duration::from_secs(10),
                job::create_job(client, self.state.namespace(), &job_spec),
            )
            .await
            {
                Ok(Ok(_)) => {
                    info!(call_id = %call_id, tool = %tool_name, "tool Job created");
                }
                Ok(Err(e)) => {
                    tracing::error!(call_id = %call_id, "k8s API rejected tool Job creation: {e}");
                    return Err(Status::internal(format!("failed to create tool Job: {e}")));
                }
                Err(_) => {
                    tracing::error!(call_id = %call_id, "k8s API timed out creating tool Job (10s)");
                    return Err(Status::internal("k8s API timed out creating tool Job"));
                }
            }
        }

        let (result_tx, result_rx) = oneshot::channel::<ToolCallResult>();

        self.state.set_result_tx(call_id.clone(), result_tx).await;

        self.state
            .enqueue_call(PendingCall {
                call_id: call_id.clone(),
                tool_name: tool_name.clone(),
                input_json: req.input_json,
                command_template,
                working_dir,
            })
            .await;

        info!(call_id = %call_id, tool = %tool_name, "call enqueued, waiting for result");

        let result = result_rx
            .await
            .map_err(|_| Status::internal(format!("result channel dropped for call {call_id}")))?;

        Ok(Response::new(CallToolResponse {
            output: result.output,
            is_error: result.is_error,
        }))
    }

    async fn get_tool_call(
        &self,
        request: Request<GetToolCallRequest>,
    ) -> Result<Response<ToolCallAssignment>, Status> {
        let req = request.into_inner();
        let tool_name = &req.tool_name;

        loop {
            if let Some(call) = self.state.dequeue_call(tool_name).await {
                info!(
                    call_id = %call.call_id,
                    job_id = %req.job_id,
                    tool = %tool_name,
                    "dispatching call to runtime"
                );
                return Ok(Response::new(ToolCallAssignment {
                    call_id: call.call_id,
                    input_json: call.input_json,
                    command_template: call.command_template,
                    working_dir: call.working_dir,
                }));
            }

            self.state.wait_for_call().await;
        }
    }

    async fn send_tool_result(
        &self,
        request: Request<SendToolResultRequest>,
    ) -> Result<Response<SendToolResultAck>, Status> {
        let req = request.into_inner();

        let tx = self
            .state
            .take_result_tx(&req.call_id)
            .await
            .ok_or_else(|| {
                Status::not_found(format!("no pending result for call_id: {}", req.call_id))
            })?;

        info!(call_id = %req.call_id, exit_code = req.exit_code, "received tool result");

        let _ = tx.send(ToolCallResult {
            output: req.output,
            is_error: req.is_error,
            exit_code: req.exit_code,
        });

        Ok(Response::new(SendToolResultAck {}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{AirlockChamber, AirlockChamberSpec};
    use crate::state::RegisteredTool;

    fn make_chamber(name: &str) -> AirlockChamber {
        AirlockChamber::new(
            name,
            AirlockChamberSpec {
                image: None,
                workspace: "workspace-data".to_string(),
                workspace_mode: "readWrite".to_string(),
                workspace_mount_path: "/workspace".to_string(),
                credentials: vec![],
                egress: vec![],
                keepalive: false,
            },
        )
    }

    async fn register_tools(state: &ControllerState, chamber: &str, tools: Vec<(&str, &str)>) {
        let registered: Vec<RegisteredTool> = tools
            .into_iter()
            .map(|(name, desc)| RegisteredTool {
                name: name.to_string(),
                chamber_name: chamber.to_string(),
                description: desc.to_string(),
                image: "test:latest".to_string(),
            })
            .collect();
        state.set_tools_for_chamber(chamber, registered).await;
    }

    #[tokio::test]
    async fn list_tools_empty() {
        let state = ControllerState::new(None, String::new(), String::new());
        let svc = ControllerService::new(state);
        let resp = svc
            .list_tools(Request::new(ListToolsRequest {}))
            .await
            .unwrap();
        assert!(resp.get_ref().tools.is_empty());
    }

    #[tokio::test]
    async fn list_tools_returns_registered_tools() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(
            &state,
            "c1",
            vec![
                ("git-push", "Push commits"),
                ("git-commit", "Commit changes"),
            ],
        )
        .await;

        let svc = ControllerService::new(state);
        let resp = svc
            .list_tools(Request::new(ListToolsRequest {}))
            .await
            .unwrap();
        assert_eq!(resp.get_ref().tools.len(), 2);
    }

    #[tokio::test]
    async fn list_tools_parameters_json_has_command_property() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "c1", vec![("test", "Test")]).await;
        let svc = ControllerService::new(state);
        let resp = svc
            .list_tools(Request::new(ListToolsRequest {}))
            .await
            .unwrap();
        let params: serde_json::Value =
            serde_json::from_str(&resp.get_ref().tools[0].parameters_json).unwrap();
        assert_eq!(params["type"], "object");
        assert_eq!(params["properties"]["command"]["type"], "string");
        assert!(params["required"]
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("command")));
    }

    #[tokio::test]
    async fn list_tools_after_chamber_removal() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "c1", vec![("git-push", "Push commits")]).await;
        state.remove_tools_for_chamber("c1").await;

        let svc = ControllerService::new(state);
        let resp = svc
            .list_tools(Request::new(ListToolsRequest {}))
            .await
            .unwrap();
        assert!(resp.get_ref().tools.is_empty());
    }

    #[tokio::test]
    async fn list_tools_after_update() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "c1", vec![("git-push", "Old desc")]).await;
        register_tools(&state, "c1", vec![("git-push", "New desc")]).await;

        let svc = ControllerService::new(state);
        let resp = svc
            .list_tools(Request::new(ListToolsRequest {}))
            .await
            .unwrap();
        assert_eq!(resp.get_ref().tools.len(), 1);
        assert_eq!(resp.get_ref().tools[0].description, "New desc");
    }

    #[tokio::test]
    async fn call_tool_unknown_returns_not_found() {
        let state = ControllerState::new(None, String::new(), String::new());
        let svc = ControllerService::new(state);
        let err = svc
            .call_tool(Request::new(CallToolRequest {
                name: "nonexistent".to_string(),
                input_json: "{}".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    #[tokio::test]
    async fn call_tool_missing_chamber_returns_failed_precondition() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "test-chamber", vec![("echo", "Echo tool")]).await;

        let svc = ControllerService::new(state);
        let err = svc
            .call_tool(Request::new(CallToolRequest {
                name: "echo".to_string(),
                input_json: "{}".to_string(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn call_tool_round_trip() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "test-chamber", vec![("echo", "Echo tool")]).await;
        state
            .set_chamber("test-chamber".into(), make_chamber("test-chamber"))
            .await;

        let svc = Arc::new(ControllerService::new(state.clone()));

        let svc_clone = svc.clone();
        let call_handle = tokio::spawn(async move {
            svc_clone
                .call_tool(Request::new(CallToolRequest {
                    name: "echo".to_string(),
                    input_json: r#"{"command":"echo hello"}"#.to_string(),
                }))
                .await
        });

        tokio::task::yield_now().await;

        let assignment = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            svc.get_tool_call(Request::new(GetToolCallRequest {
                job_id: "job-1".to_string(),
                tool_name: "echo".to_string(),
            })),
        )
        .await
        .expect("get_tool_call timed out")
        .unwrap()
        .into_inner();

        assert_eq!(assignment.input_json, r#"{"command":"echo hello"}"#);
        assert_eq!(assignment.command_template, "{command}");

        svc.send_tool_result(Request::new(SendToolResultRequest {
            call_id: assignment.call_id,
            output: "hello\n".to_string(),
            is_error: false,
            exit_code: 0,
        }))
        .await
        .unwrap();

        let resp = tokio::time::timeout(std::time::Duration::from_secs(2), call_handle)
            .await
            .expect("call_tool timed out")
            .unwrap()
            .unwrap();
        assert_eq!(resp.get_ref().output, "hello\n");
        assert!(!resp.get_ref().is_error);
    }

    #[tokio::test]
    async fn get_tool_call_blocks_until_enqueued() {
        let state = ControllerState::new(None, String::new(), String::new());
        register_tools(&state, "test-chamber", vec![("tool", "test tool")]).await;
        state
            .set_chamber("test-chamber".into(), make_chamber("test-chamber"))
            .await;

        let svc = Arc::new(ControllerService::new(state.clone()));

        let svc_for_get = svc.clone();
        let get_handle = tokio::spawn(async move {
            svc_for_get
                .get_tool_call(Request::new(GetToolCallRequest {
                    job_id: "job-1".to_string(),
                    tool_name: "tool".to_string(),
                }))
                .await
        });

        tokio::task::yield_now().await;
        assert!(!get_handle.is_finished(), "GetToolCall should be blocking");

        let svc_for_call = svc.clone();
        tokio::spawn(async move {
            let _ = svc_for_call
                .call_tool(Request::new(CallToolRequest {
                    name: "tool".to_string(),
                    input_json: r#"{"command":"test"}"#.to_string(),
                }))
                .await;
        });

        let assignment = tokio::time::timeout(std::time::Duration::from_secs(2), get_handle)
            .await
            .expect("GetToolCall should resolve within timeout")
            .unwrap()
            .unwrap()
            .into_inner();

        assert_eq!(assignment.input_json, r#"{"command":"test"}"#);
    }

    #[tokio::test]
    async fn send_result_unknown_call_id() {
        let state = ControllerState::new(None, String::new(), String::new());
        let svc = ControllerService::new(state);
        let err = svc
            .send_tool_result(Request::new(SendToolResultRequest {
                call_id: "nonexistent".to_string(),
                output: "".to_string(),
                is_error: false,
                exit_code: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
    }
}
