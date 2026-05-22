use anyhow::{Result, bail};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{AfterHandshakeOutcome, ConnectionInfo, EndpointHooks},
    endpoint_info::EndpointIdExt,
};
use noq::{RecvStream, SendStream};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tracing::{info, warn};

/// ALPN for p2pssh protocol
const ALPN: &[u8] = b"p2pssh/1";

/// Buffer size for forwarding
const FORWARD_BUF_SIZE: usize = 65536;

/// Default path for storing the secret key
fn default_key_path() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/p2pssh/secret.key")
    } else {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .and_then(|s| if s.is_empty() { None } else { Some(PathBuf::from(s)) })
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        config_dir.join("p2pssh").join("secret.key")
    }
}

/// Default path for authorized keys
fn default_authorized_keys_path() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/p2pssh/authorized_keys")
    } else {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .and_then(|s| if s.is_empty() { None } else { Some(PathBuf::from(s)) })
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."));
        config_dir.join("p2pssh").join("authorized_keys")
    }
}

/// Check if the current user is root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Load or generate a secret key from disk
fn load_or_generate_secret_key(path: &PathBuf) -> Result<SecretKey> {
    if path.exists() {
        info!("Loading secret key from: {}", path.display());
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            bail!("Invalid key file: expected 32 bytes, got {}", bytes.len());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        return Ok(SecretKey::from_bytes(&key_bytes));
    }
    info!("Generating new secret key at: {}", path.display());
    let key = SecretKey::generate(&mut rand::rng());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(path, key.to_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(key)
}

/// Load authorized keys from a file (z32-encoded public keys, one per line)
fn load_authorized_keys(path: &PathBuf) -> Result<HashSet<EndpointId>> {
    let mut keys = HashSet::new();
    if !path.exists() {
        return Ok(keys);
    }
    let content = std::fs::read_to_string(path)?;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match EndpointId::from_z32(line) {
            Ok(endpoint_id) => {
                keys.insert(endpoint_id);
            }
            Err(e) => {
                warn!("Invalid authorized key '{}': {}", line, e);
            }
        }
    }
    info!("Loaded {} authorized keys from {}", keys.len(), path.display());
    Ok(keys)
}

/// Hook to reject unauthorized connections based on EndpointId
#[derive(Debug)]
struct AuthHook {
    allowed: Arc<HashSet<EndpointId>>,
}

impl AuthHook {
    fn new(allowed: HashSet<EndpointId>) -> Self {
        Self {
            allowed: Arc::new(allowed),
        }
    }
}

impl EndpointHooks for AuthHook {
    async fn after_handshake<'a>(
        &'a self,
        conn: &'a ConnectionInfo,
    ) -> AfterHandshakeOutcome {
        if self.allowed.is_empty() || self.allowed.contains(&conn.remote_id()) {
            AfterHandshakeOutcome::Accept
        } else {
            warn!(
                remote_id = %conn.remote_id().to_z32(),
                "Rejecting unauthorized connection"
            );
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"unauthorized".to_vec(),
            }
        }
    }
}

enum Command {
    Id {
        key_path: Option<PathBuf>,
    },
    Serve {
        ssh_host: String,
        key_path: Option<PathBuf>,
        bind: String,
        relay_url: Option<RelayUrl>,
        mdns: bool,
        authorized_keys: Option<PathBuf>,
    },
    Connect {
        peer_id: String,
        key_path: Option<PathBuf>,
        bind: String,
        relay_url: Option<RelayUrl>,
        mdns: bool,
    },
}

fn print_help() {
    eprintln!(
        "p2pssh - Privacy-first P2P SSH tunnel using iroh

USAGE:
    p2pssh <COMMAND>

COMMANDS:
    id         Show your peer ID
    serve      Listen for incoming SSH connections
    connect    Connect to a peer (for use as SSH ProxyCommand)

OPTIONS:
    -h, --help    Print help information

Run 'p2pssh <COMMAND> --help' for more information on a command."
    );
}

fn print_id_help() {
    eprintln!(
        "p2pssh-id - Show your peer ID

USAGE:
    p2pssh id [OPTIONS]

OPTIONS:
    -k, --key <PATH>    Path to secret key file
    -h, --help          Print help information"
    );
}

fn print_serve_help() {
    eprintln!(
        "p2pssh-serve - Listen for incoming SSH connections

USAGE:
    p2pssh serve [OPTIONS]

OPTIONS:
    --ssh-host <ADDR>           SSH server address to forward to [default: 127.0.0.1:22]
    -k, --key <PATH>            Path to secret key file
    --bind <ADDR>               Bind address for the endpoint [default: 0.0.0.0:0]
    --relay-url <URL>           Custom relay URL (e.g. https://relay.example.com)
    --mdns                      Enable mDNS discovery on local network
    --authorized-keys <PATH>    Path to file with authorized client public keys (z32 format)
    -h, --help                  Print help information"
    );
}

fn print_connect_help() {
    eprintln!(
        "p2pssh-connect - Connect to a peer

USAGE:
    p2pssh connect <PEER_ID> [OPTIONS]

ARGS:
    <PEER_ID>    Peer ID to connect to

OPTIONS:
    -k, --key <PATH>     Path to secret key file
    --bind <ADDR>        Bind address for the endpoint [default: 0.0.0.0:0]
    --relay-url <URL>    Custom relay URL (e.g. https://relay.example.com)
    --mdns               Enable mDNS discovery on local network
    -h, --help           Print help information"
    );
}

fn parse_args() -> Result<Command> {
    use lexopt::prelude::*;

    let mut parser = lexopt::Parser::from_env();
    let mut key_path: Option<PathBuf> = None;

    let command = match parser.next()? {
        Some(Value(val)) => val.string()?,
        _ => {
            print_help();
            bail!("No command specified");
        }
    };

    match command.as_str() {
        "id" => {
            while let Some(arg) = parser.next()? {
                match arg {
                    Short('k') | Long("key") => {
                        key_path = Some(parser.value()?.parse()?);
                    }
                    Short('h') | Long("help") => {
                        print_id_help();
                        std::process::exit(0);
                    }
                    _ => bail!("Unexpected argument: {:?}", arg),
                }
            }
            Ok(Command::Id { key_path })
        }
        "serve" => {
            let mut ssh_host = "127.0.0.1:22".to_string();
            let mut bind = "0.0.0.0:0".to_string();
            let mut relay_url: Option<RelayUrl> = None;
            let mut mdns = false;
            let mut authorized_keys: Option<PathBuf> = None;

            while let Some(arg) = parser.next()? {
                match arg {
                    Long("ssh-host") => {
                        ssh_host = parser.value()?.parse()?;
                    }
                    Short('k') | Long("key") => {
                        key_path = Some(parser.value()?.parse()?);
                    }
                    Long("bind") => {
                        bind = parser.value()?.parse()?;
                    }
                    Long("relay-url") => {
                        let url: String = parser.value()?.parse()?;
                        relay_url = Some(url.parse()?);
                    }
                    Long("mdns") => {
                        mdns = true;
                    }
                    Long("authorized-keys") => {
                        authorized_keys = Some(parser.value()?.parse()?);
                    }
                    Short('h') | Long("help") => {
                        print_serve_help();
                        std::process::exit(0);
                    }
                    _ => bail!("Unexpected argument: {:?}", arg),
                }
            }
            Ok(Command::Serve {
                ssh_host,
                key_path,
                bind,
                relay_url,
                mdns,
                authorized_keys,
            })
        }
        "connect" => {
            let peer_id = match parser.next()? {
                Some(Value(val)) => val.string()?,
                _ => bail!("Missing peer ID argument"),
            };

            let mut bind = "0.0.0.0:0".to_string();
            let mut relay_url: Option<RelayUrl> = None;
            let mut mdns = false;

            while let Some(arg) = parser.next()? {
                match arg {
                    Short('k') | Long("key") => {
                        key_path = Some(parser.value()?.parse()?);
                    }
                    Long("bind") => {
                        bind = parser.value()?.parse()?;
                    }
                    Long("relay-url") => {
                        let url: String = parser.value()?.parse()?;
                        relay_url = Some(url.parse()?);
                    }
                    Long("mdns") => {
                        mdns = true;
                    }
                    Short('h') | Long("help") => {
                        print_connect_help();
                        std::process::exit(0);
                    }
                    _ => bail!("Unexpected argument: {:?}", arg),
                }
            }
            Ok(Command::Connect {
                peer_id,
                key_path,
                bind,
                relay_url,
                mdns,
            })
        }
        "help" | "--help" | "-h" => {
            print_help();
            std::process::exit(0);
        }
        _ => {
            bail!(
                "Unknown command: {}. Use '-h' for usage information.",
                command
            );
        }
    }
}

/// Build an endpoint with privacy-preserving configuration.
///
/// - No public discovery (no PkarrPublisher / DNS lookup)
/// - Optional custom relay for NAT traversal
/// - Optional mDNS for local network discovery
async fn build_endpoint(
    secret_key: SecretKey,
    bind: SocketAddr,
    relay_url: Option<RelayUrl>,
    mdns: bool,
    authorized_keys: Option<HashSet<EndpointId>>,
    alpns: Vec<Vec<u8>>,
) -> Result<Endpoint> {
    let endpoint_id = secret_key.public();
    let mut builder = iroh::Endpoint::empty_builder()
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
        let mdns_lookup = iroh::address_lookup::MdnsAddressLookup::builder()
            .build(endpoint_id)?;
        builder = builder.address_lookup(mdns_lookup);
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_level(true)
        .without_time()
        .with_ansi(false)
        .init();

    let command = parse_args()?;

    match command {
        Command::Id { key_path } => cmd_id(key_path).await,
        Command::Serve {
            ssh_host,
            key_path,
            bind,
            relay_url,
            mdns,
            authorized_keys,
        } => cmd_serve(ssh_host, key_path, bind, relay_url, mdns, authorized_keys).await,
        Command::Connect {
            peer_id,
            key_path,
            bind,
            relay_url,
            mdns,
        } => cmd_connect(peer_id, key_path, bind, relay_url, mdns).await,
    }
}

async fn cmd_id(key_path: Option<PathBuf>) -> Result<()> {
    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    println!("{}", secret_key.public().to_z32());
    Ok(())
}

async fn cmd_serve(
    ssh_host: String,
    key_path: Option<PathBuf>,
    bind: String,
    relay_url: Option<RelayUrl>,
    mdns: bool,
    authorized_keys: Option<PathBuf>,
) -> Result<()> {
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
    let _ = tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await;

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

    loop {
        select! {
            Some(incoming) = endpoint.accept() => {
                let ssh_host = ssh_host.clone();
                tokio::spawn(async move {
                    let Ok(connecting) = incoming.accept() else {
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
    info!("Incoming connection from: {}", remote_id.to_z32());

    let (send, recv) = connection.accept_bi().await?;
    info!("Accepted bidirectional stream from: {}", remote_id.to_z32());

    let tcp_stream = TcpStream::connect(&ssh_host).await?;
    info!("Connected to SSH server at: {}", ssh_host);

    forward_bidi(tcp_stream, recv, send).await?;

    info!("Connection closed: {}", remote_id.to_z32());
    Ok(())
}

async fn cmd_connect(
    peer_id_str: String,
    key_path: Option<PathBuf>,
    bind: String,
    relay_url: Option<RelayUrl>,
    mdns: bool,
) -> Result<()> {
    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let endpoint_id = EndpointId::from_z32(&peer_id_str)?;

    info!("Connecting to peer: {}", peer_id_str);

    let bind_addr: SocketAddr = bind.parse()?;

    let endpoint = build_endpoint(
        secret_key,
        bind_addr,
        relay_url,
        mdns,
        None,
        vec![],
    )
    .await?;

    info!("Waiting for endpoint to come online...");
    let _ = tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await;

    let addr = EndpointAddr::from(endpoint_id);

    info!("Connecting to {}...", peer_id_str);
    let connection = endpoint.connect(addr, ALPN).await?;
    info!("Connected to {}", peer_id_str);

    let (send, recv) = connection.open_bi().await?;
    info!("Opened bidirectional stream");

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    forward_bidi_stdio(stdin, stdout, recv, send).await?;

    info!("Connection closed");
    Ok(())
}

/// Forward data between TCP stream and QUIC streams, shutting down gracefully
async fn forward_bidi(tcp_stream: TcpStream, recv: RecvStream, send: SendStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // QUIC → TCP
    let quic_to_tcp = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        let mut recv = recv;
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tcp_write.write_all(&buf[..n]).await?;
                }
                Ok(None) => {
                    // Stream closed, shutdown TCP write half to signal EOF
                    tcp_write.shutdown().await?;
                    break;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    // TCP → QUIC
    let tcp_to_quic = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        let mut send = send;
        loop {
            match tokio::io::AsyncReadExt::read(&mut tcp_read, &mut buf).await {
                Ok(0) => {
                    // TCP EOF, finish QUIC send stream
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    let (r1, r2) = tokio::join!(quic_to_tcp, tcp_to_quic);
    r1?;
    r2?;
    Ok(())
}

/// Forward data between stdio and QUIC streams, shutting down gracefully
async fn forward_bidi_stdio<R, W>(
    mut stdin: R,
    mut stdout: W,
    recv: RecvStream,
    send: SendStream,
) -> Result<()>
where
    R: AsyncRead + Send + Sync + Unpin + 'static,
    W: AsyncWrite + Send + Sync + Unpin + 'static,
{
    // QUIC → stdout
    let quic_to_stdout = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        let mut recv = recv;
        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    stdout.write_all(&buf[..n]).await?;
                    stdout.flush().await?;
                }
                Ok(None) => break,
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    // stdin → QUIC
    let stdin_to_quic = async {
        let mut buf = vec![0u8; FORWARD_BUF_SIZE];
        let mut send = send;
        loop {
            match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
                Ok(0) => {
                    let _ = send.finish();
                    break;
                }
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    let (r1, r2) = tokio::join!(quic_to_stdout, stdin_to_quic);
    r1?;
    r2?;
    Ok(())
}
