use std::net::SocketAddr;

use airlock_controller::{grpc, keepalive, state, watcher};

use airlock_proto::airlock_controller_server::AirlockControllerServer;
use clap::Parser;
use tonic::transport::Server;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "airlock-controller", version)]
struct Args {
    /// gRPC listen port.
    #[arg(long, default_value = "9090")]
    port: u16,

    /// Kubernetes namespace to watch for AirlockTool CRDs.
    #[arg(long, default_value = "default")]
    namespace: String,

    /// Reachable address for Jobs to connect back to this controller.
    /// Defaults to http://0.0.0.0:{port} which only works when Jobs
    /// run on the same host. Set to the Kubernetes Service address
    /// (e.g. http://airlock-controller.ns.svc:9090) in cluster deployments.
    #[arg(long)]
    controller_addr: Option<String>,
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

    let controller_addr = args
        .controller_addr
        .unwrap_or_else(|| format!("http://0.0.0.0:{}", args.port));
    let state = state::ControllerState::new(kube_client, args.namespace.clone(), controller_addr);

    let addr: SocketAddr = ([0, 0, 0, 0], args.port).into();
    info!(%addr, namespace = %args.namespace, "starting airlock-controller");

    let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);

    let watcher_namespace = args.namespace.clone();
    let watcher_state = state.clone();
    let watcher_handle = tokio::spawn(async move {
        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                error!("watcher kube client failed: {e}");
                return Ok(());
            }
        };
        watcher::watch_tools(client, &watcher_namespace, watcher_state, ready_tx).await
    });

    let grpc_state = state.clone();
    let grpc_handle = tokio::spawn(async move {
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            ready_rx.wait_for(|&v| v),
        )
        .await
        {
            Ok(Ok(_)) => info!("watcher initial sync complete, starting gRPC server"),
            Ok(Err(_)) => warn!("watcher channel closed before sync, starting gRPC server"),
            Err(_) => warn!("watcher sync timed out after 10s, starting gRPC server"),
        }

        let (health_reporter, health_service) = tonic_health::server::health_reporter();
        health_reporter
            .set_serving::<AirlockControllerServer<grpc::ControllerService>>()
            .await;

        let svc = grpc::ControllerService::new(grpc_state);
        Server::builder()
            .add_service(health_service)
            .add_service(AirlockControllerServer::new(svc))
            .serve(addr)
            .await
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
