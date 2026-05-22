use anyhow::Result;
use iroh::{
    Endpoint, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::config::ALPN;
use crate::forward::forward_bidi;
use crate::key::AuthHook;

/// Build an endpoint with privacy-preserving configuration.
///
/// - No public discovery (no PkarrPublisher / DNS lookup)
/// - Optional custom relay for NAT traversal
/// - Optional mDNS for local network discovery
pub async fn build_endpoint(
    secret_key: SecretKey,
    bind: SocketAddr,
    relay_url: Option<RelayUrl>,
    mdns: bool,
    authorized_keys: Option<HashSet<EndpointId>>,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let mut builder = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(secret_key)
        .bind_addr(bind)?;

    if let Some(url) = relay_url {
        info!("Using custom relay: {}", url);
        let relay_config = RelayConfig::from(url);
        let relay_map = RelayMap::from(relay_config);
        builder = builder.relay_mode(RelayMode::Custom(relay_map));
    } else {
        info!("No relay configured; direct connections only");
        builder = builder.relay_mode(RelayMode::Disabled);
    }

    if !alpns.is_empty() {
        builder = builder.alpns(alpns);
    }

    if mdns {
        info!("Enabling mDNS discovery");
        builder = builder.address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
    }

    if let Some(keys) = authorized_keys
        && !keys.is_empty()
    {
        info!("Enabling authorization for {} keys", keys.len());
        builder = builder.hooks(AuthHook::new(keys));
    }

    let endpoint = builder.bind().await?;
    Ok(endpoint)
}

pub async fn cmd_serve(
    ssh_host: String,
    key_path: Option<std::path::PathBuf>,
    bind: String,
    relay_url: Option<RelayUrl>,
    mdns: bool,
    authorized_keys: Option<std::path::PathBuf>,
    max_connections: usize,
) -> Result<()> {
    use crate::config::{default_authorized_keys_path, default_key_path};
    use crate::key::{load_authorized_keys, load_or_generate_secret_key};

    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let peer_id = secret_key.public().to_z32();

    info!("Starting p2pssh server");
    info!("Peer ID: {}", peer_id);

    let bind_addr: SocketAddr = bind.parse()?;
    let auth_keys_path = authorized_keys.unwrap_or_else(default_authorized_keys_path);
    let authorized = load_authorized_keys(&auth_keys_path)?;

    let endpoint = build_endpoint(
        secret_key,
        bind_addr,
        relay_url.clone(),
        mdns,
        Some(authorized),
        vec![ALPN.to_vec()],
    )
    .await?;

    info!("Waiting for endpoint to come online...");
    match tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online()).await {
        Ok(()) => info!("Endpoint is online"),
        Err(_) => {
            warn!("Endpoint did not come online within 30s; continuing anyway");
        }
    }

    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "my-server".to_string());

    eprintln!("\n=== p2pssh Server Ready ===");
    eprintln!("Peer ID: {}", peer_id);
    if relay_url.is_some() {
        eprintln!("Relay: custom");
    } else {
        eprintln!("Relay: disabled (direct only)");
    }
    eprintln!("\nClients can configure ~/.ssh/config:");
    eprintln!("  Host {}", hostname);
    eprintln!("    ProxyCommand p2pssh connect {}", peer_id);
    eprintln!("    User <username>");
    if relay_url.is_some() {
        eprintln!("\nWith custom relay:");
        eprintln!(
            "    ProxyCommand p2pssh connect {} --relay-url <URL>{}",
            peer_id,
            if mdns { " --mdns" } else { "" }
        );
    }

    let conn_limit = Arc::new(Semaphore::new(max_connections));

    #[cfg(unix)]
    let mut sigterm = Some(tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?);
    #[cfg(not(unix))]
    let mut sigterm: Option<tokio::signal::unix::Signal> = None;

    loop {
        tokio::select! {
            Some(incoming) = endpoint.accept() => {
                let permit = match conn_limit.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("Connection limit ({}) reached; rejecting incoming connection", max_connections);
                        let _ = incoming.refuse();
                        continue;
                    }
                };
                let ssh_host = ssh_host.clone();
                tokio::spawn(async move {
                    let _permit = permit; // held for lifetime of task
                    let Ok(connecting) = incoming.accept() else {
                        warn!("Failed to accept incoming QUIC connection");
                        return;
                    };
                    if let Err(e) = handle_incoming_connection(connecting, ssh_host).await {
                        warn!("Connection handler error: {}", e);
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl-C, shutting down...");
                break;
            }
            _ = async {
                if let Some(ref mut sig) = sigterm {
                    sig.recv().await
                } else {
                    std::future::pending().await
                }
            } => {
                info!("Received SIGTERM, shutting down...");
                break;
            }
        }
    }

    endpoint.close().await;
    info!("Server shutdown complete");
    Ok(())
}

async fn handle_incoming_connection(
    accepting: iroh::endpoint::Accepting,
    ssh_host: String,
) -> Result<()> {
    let connection = accepting.await?;
    let remote_id = connection.remote_id();
    info!(remote_id = %remote_id.to_z32(), "Accepted incoming connection");

    let (send, recv) = connection.accept_bi().await?;
    let tcp_stream = tokio::net::TcpStream::connect(&ssh_host).await?;

    let res = forward_bidi(tcp_stream, recv, send).await;
    info!(remote_id = %remote_id.to_z32(), "Connection closed");
    res
}
