use std::sync::Arc;

use airlock_controller::crd::{AirlockChamber, AirlockChamberSpec, AirlockTool, AirlockToolSpec};
use airlock_controller::grpc::ControllerService;
use airlock_controller::state::ControllerState;
use airlock_proto::airlock_controller_client::AirlockControllerClient;
use airlock_proto::airlock_controller_server::AirlockControllerServer;
use airlock_proto::{CallToolRequest, GetToolCallRequest, ListToolsRequest, SendToolResultRequest};
use tonic::transport::Server;

async fn start_server() -> (String, Arc<ControllerState>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}");

    let state = ControllerState::new(None, String::new(), String::new());
    let service = ControllerService::new(state.clone());

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(AirlockControllerServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (url, state)
}

fn make_chamber(name: &str) -> AirlockChamber {
    AirlockChamber::new(
        name,
        AirlockChamberSpec {
            workspace: "workspace-data".to_string(),
            workspace_mode: "readWrite".to_string(),
            workspace_mount_path: "/workspace".to_string(),
            credentials: vec![],
            egress: vec![],
            keepalive: false,
        },
    )
}

fn make_tool(name: &str, description: &str) -> AirlockTool {
    AirlockTool::new(
        name,
        AirlockToolSpec {
            chamber: "test-chamber".to_string(),
            description: description.to_string(),
            image: "test:latest".to_string(),
            command: "echo {msg}".to_string(),
            max_calls: 0,
        },
    )
}

#[tokio::test]
async fn list_tools_over_grpc() {
    let (url, state) = start_server().await;
    state
        .set_tool("git-push".into(), make_tool("git-push", "Push commits"))
        .await;

    let mut client = AirlockControllerClient::connect(url).await.unwrap();
    let resp = client
        .list_tools(ListToolsRequest {})
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.tools.len(), 1);
    assert_eq!(resp.tools[0].name, "git-push");
    assert_eq!(resp.tools[0].description, "Push commits");
}

#[tokio::test]
async fn get_tool_call_blocks_over_grpc() {
    let (url, _state) = start_server().await;
    let mut client = AirlockControllerClient::connect(url).await.unwrap();

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        client.get_tool_call(GetToolCallRequest {
            job_id: "job-1".into(),
            tool_name: "echo".into(),
        }),
    )
    .await;

    assert!(
        result.is_err(),
        "GetToolCall should block when no calls pending"
    );
}

#[tokio::test]
async fn call_tool_round_trip_over_grpc() {
    let (url, state) = start_server().await;
    state
        .set_tool("echo".into(), make_tool("echo", "Echo tool"))
        .await;
    state
        .set_chamber("test-chamber".into(), make_chamber("test-chamber"))
        .await;

    let agent_url = url.clone();

    let agent = tokio::spawn(async move {
        let mut client = AirlockControllerClient::connect(agent_url).await.unwrap();

        let assignment = client
            .get_tool_call(GetToolCallRequest {
                job_id: "job-1".into(),
                tool_name: "echo".into(),
            })
            .await
            .unwrap()
            .into_inner();

        assert_eq!(assignment.command_template, "echo {msg}");

        client
            .send_tool_result(SendToolResultRequest {
                call_id: assignment.call_id,
                output: "hello world\n".into(),
                is_error: false,
                exit_code: 0,
            })
            .await
            .unwrap();
    });

    let mut client = AirlockControllerClient::connect(url).await.unwrap();
    let resp = client
        .call_tool(CallToolRequest {
            name: "echo".into(),
            input_json: r#"{"msg":"hello world"}"#.into(),
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.output, "hello world\n");
    assert!(!resp.is_error);

    agent.await.unwrap();
}
