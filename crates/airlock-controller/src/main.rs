use std::net::SocketAddr;

use airlock_controller::{grpc, keepalive, state, watcher};

use airlock_proto::airlock_controller_server::AirlockControllerServer;
use clap::Parser;
use tonic::transport::Server;
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "airlock-controller", version)]
struct Args {
    /// gRPC listen port.
    #[arg(long, default_value = "9090")]
    port: u16,

    /// Kubernetes namespace to watch for AirlockTool CRDs.
    #[arg(long, default_value = "default")]
    namespace: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().json().with_target(false).init();

    let args = Args::parse();

    // Client for Job CRUD — stored in state.
    let kube_client = kube::Client::try_default().await.ok();
    if kube_client.is_some() {
        info!("k8s client initialized, Job creation enabled");
    } else {
        info!("no k8s client available, Job creation disabled");
    }

    let controller_addr = format!("http://0.0.0.0:{}", args.port);
    let state = state::ControllerState::new(kube_client, args.namespace.clone(), controller_addr);

    let addr: SocketAddr = ([0, 0, 0, 0], args.port).into();
    info!(%addr, namespace = %args.namespace, "starting airlock-controller");

    let grpc_state = state.clone();
    let grpc_handle = tokio::spawn(async move {
        let svc = grpc::ControllerService::new(grpc_state);
        Server::builder()
            .add_service(AirlockControllerServer::new(svc))
            .serve(addr)
            .await
    });

    let watcher_namespace = args.namespace.clone();
    let watcher_state = state.clone();
    let watcher_handle = tokio::spawn(async move {
        // Separate kube client for the watcher to avoid HTTP/2
        // connection multiplexing issues with the Job creation client.
        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                error!("watcher kube client failed: {e}");
                return Ok(());
            }
        };
        watcher::watch_tools(client, &watcher_namespace, watcher_state).await
    });

    let keepalive_state = state.clone();
    let keepalive_handle = tokio::spawn(async move {
        keepalive::cleanup_loop(keepalive_state).await;
    });

    tokio::select! {
        result = grpc_handle => {
            error!("gRPC server exited: {:?}", result);
        }
        result = watcher_handle => {
            error!("CRD watcher exited: {:?}", result);
        }
        _ = keepalive_handle => {
            error!("keepalive cleanup task exited");
        }
    }

    Ok(())
}
