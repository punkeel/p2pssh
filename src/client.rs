use anyhow::Result;
use iroh::{EndpointAddr, EndpointId};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use crate::config::ALPN;
use crate::forward::forward_bidi_stdio;
use crate::key::load_or_generate_secret_key;
use crate::server::build_endpoint;

pub async fn cmd_connect(
    peer_id_str: String,
    key_path: Option<PathBuf>,
    bind: String,
    relay_url: Option<iroh::RelayUrl>,
    mdns: bool,
) -> Result<()> {
    let key_path = key_path.unwrap_or_else(crate::config::default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let endpoint_id = EndpointId::from_z32(&peer_id_str)?;

    info!("Connecting to peer: {}", peer_id_str);

    let bind_addr: SocketAddr = bind.parse()?;

    let addr = if let Some(ref url) = relay_url {
        EndpointAddr::from(endpoint_id).with_relay_url(url.clone())
    } else {
        EndpointAddr::from(endpoint_id)
    };

    let endpoint = build_endpoint(secret_key, bind_addr, relay_url, mdns, None, vec![]).await?;

    info!("Waiting for endpoint to come online...");
    match tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online()).await {
        Ok(()) => info!("Endpoint is online"),
        Err(_) => {
            info!("Endpoint did not come online within 30s; continuing anyway");
        }
    }

    info!("Connecting to {}...", peer_id_str);
    let connection = endpoint.connect(addr, ALPN).await?;
    info!("Connected to {}", peer_id_str);

    let (send, recv) = connection.open_bi().await?;
    info!("Opened bidirectional stream");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let result = forward_bidi_stdio(stdin, stdout, recv, send).await;

    info!("Connection closed");
    endpoint.close().await;
    result
}
