use anyhow::{Result, bail};
use iroh::PublicKey;
use iroh::endpoint_info::EndpointIdExt;
use iroh::{Endpoint, EndpointAddr, SecretKey};
use quinn::{RecvStream, SendStream};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::select;
use tracing::Event;
use tracing::span::{Attributes, Id};
use tracing::{Level, Metadata, Subscriber, info, warn};

/// ALPN for p2pssh protocol
const ALPN: &[u8] = b"p2pssh/1";

/// Minimal tracing subscriber that writes to stderr
struct SimpleSubscriber;

impl Subscriber for SimpleSubscriber {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        // Only show info and above by default (can be controlled via RUST_LOG)
        metadata.level() <= &Level::INFO
    }

    fn new_span(&self, _span: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let level = metadata.level();

        // Format: LEVEL message
        let level_str = match *level {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        // Extract the message
        struct MessageVisitor(String);
        impl tracing::field::Visit for MessageVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{:?}", value);
                    // Remove quotes added by Debug formatting
                    if self.0.starts_with('"') && self.0.ends_with('"') {
                        self.0 = self.0[1..self.0.len() - 1].to_string();
                    }
                }
            }
        }

        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        eprintln!("{} {}", level_str, visitor.0);
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

/// Default path for storing the secret key
fn default_key_path() -> PathBuf {
    // Root user uses /etc/p2pssh/secret.key
    // Non-root users use XDG_CONFIG_HOME/p2pssh/secret.key or ~/.config/p2pssh/secret.key
    if is_root() {
        PathBuf::from("/etc/p2pssh/secret.key")
    } else {
        // Use XDG_CONFIG_HOME if available, otherwise ~/.config
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .and_then(|s| {
                if s.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(s))
                }
            })
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|home| PathBuf::from(home).join(".config"))
            })
            .unwrap_or_else(|| PathBuf::from("."));

        config_dir.join("p2pssh").join("secret.key")
    }
}

/// Check if the current user is root
fn is_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: getuid is always safe to call
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

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write key with restricted permissions
    std::fs::write(path, key.to_bytes())?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }

    Ok(key)
}

enum Command {
    Id {
        key_path: Option<PathBuf>,
    },
    Serve {
        ssh_host: String,
        key_path: Option<PathBuf>,
        bind: String,
    },
    Connect {
        peer_id: String,
        key_path: Option<PathBuf>,
        bind: String,
    },
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
            })
        }
        "connect" => {
            let peer_id = match parser.next()? {
                Some(Value(val)) => val.string()?,
                _ => bail!("Missing peer ID argument"),
            };

            let mut bind = "0.0.0.0:0".to_string();

            while let Some(arg) = parser.next()? {
                match arg {
                    Short('k') | Long("key") => {
                        key_path = Some(parser.value()?.parse()?);
                    }
                    Long("bind") => {
                        bind = parser.value()?.parse()?;
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

fn print_help() {
    eprintln!(
        "p2pssh - P2P SSH tunnel using iroh

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
    --ssh-host <ADDR>    SSH server address to forward to [default: 127.0.0.1:22]
    -k, --key <PATH>     Path to secret key file
    --bind <ADDR>        Bind address for the endpoint [default: 0.0.0.0:0]
    -h, --help           Print help information"
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
    -k, --key <PATH>    Path to secret key file
    --bind <ADDR>       Bind address for the endpoint [default: 0.0.0.0:0]
    -h, --help          Print help information"
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize minimal tracing subscriber
    tracing::subscriber::set_global_default(SimpleSubscriber)
        .expect("setting default subscriber failed");

    let command = parse_args()?;

    match command {
        Command::Id { key_path } => cmd_id(key_path).await,
        Command::Serve {
            ssh_host,
            key_path,
            bind,
        } => cmd_serve(ssh_host, key_path, bind).await,
        Command::Connect {
            peer_id,
            key_path,
            bind,
        } => cmd_connect(peer_id, key_path, bind).await,
    }
}

async fn cmd_id(key_path: Option<PathBuf>) -> Result<()> {
    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let endpoint_id = secret_key.public();

    println!("{}", &endpoint_id.to_z32());
    Ok(())
}

async fn cmd_serve(ssh_host: String, key_path: Option<PathBuf>, bind: String) -> Result<()> {
    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let endpoint_id = secret_key.public();
    let peer_id = &endpoint_id.to_z32();

    info!("Starting p2pssh server");
    info!("Peer ID: {}", peer_id);

    // Parse bind address
    let bind_addr: SocketAddr = bind.parse()?;

    // Create iroh endpoint
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind_addr(bind_addr)?
        .bind()
        .await?;

    // Wait for the endpoint to come online
    info!("Waiting for endpoint to come online...");
    let _ = tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await;

    // Get system hostname for SSH config example
    let hostname = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "my-server".to_string());

    // Print the peer ID for the user
    eprintln!("\n=== p2pssh Server Ready ===");
    eprintln!("\nClients can configure ~/.ssh/config:");
    eprintln!("  Host {}", hostname);
    eprintln!("    ProxyCommand p2pssh connect {}", peer_id);
    eprintln!("    User <username>");

    // Accept incoming connections
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

    // Graceful shutdown
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
    info!("Incoming connection from: {}", &remote_id.to_z32());

    // Accept bidirectional stream
    let (send, recv) = connection.accept_bi().await?;
    info!(
        "Accepted bidirectional stream from: {}",
        &remote_id.to_z32()
    );

    // Connect to SSH server
    let tcp_stream = TcpStream::connect(&ssh_host).await?;
    info!("Connected to SSH server at: {}", ssh_host);

    // Forward data bidirectionally
    forward_bidi(tcp_stream, recv, send).await?;

    info!("Connection closed: {}", &remote_id.to_z32());
    Ok(())
}

async fn cmd_connect(peer_id_str: String, key_path: Option<PathBuf>, bind: String) -> Result<()> {
    let key_path = key_path.unwrap_or_else(default_key_path);
    let secret_key = load_or_generate_secret_key(&key_path)?;
    let endpoint_id = PublicKey::from_z32(&peer_id_str)?;

    info!("Connecting to peer: {}", peer_id_str);

    // Parse bind address
    let bind_addr: SocketAddr = bind.parse()?;

    // Create iroh endpoint
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .bind_addr(bind_addr)?
        .bind()
        .await?;

    // Wait for endpoint to come online
    info!("Waiting for endpoint to come online...");
    let _ = tokio::time::timeout(Duration::from_secs(30), endpoint.online()).await;

    // Create address from endpoint ID (uses discovery)
    let addr = EndpointAddr::from(endpoint_id);

    // Connect to remote endpoint
    info!("Connecting to {}...", peer_id_str);
    let connection = endpoint.connect(addr, ALPN).await?;
    info!("Connected to {}", peer_id_str);

    // Open bidirectional stream
    let (send, recv) = connection.open_bi().await?;
    info!("Opened bidirectional stream");

    // Proxy stdin/stdout
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    forward_bidi_stdio(stdin, stdout, recv, send).await?;

    info!("Connection closed");
    Ok(())
}

/// Forward data between TCP stream and QUIC streams
async fn forward_bidi(tcp_stream: TcpStream, recv: RecvStream, send: SendStream) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // Forward from QUIC to TCP
    let forward_to_tcp = async {
        let mut buf = vec![0u8; 8192];
        let mut recv = recv;

        loop {
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    tcp_write.write_all(&buf[..n]).await?;
                    tcp_write.flush().await?;
                }
                Ok(None) => break,
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        Ok(())
    };

    // Forward from TCP to QUIC
    let forward_from_tcp = async {
        let mut buf = vec![0u8; 8192];
        let mut send = send;

        loop {
            match tokio::io::AsyncReadExt::read(&mut tcp_read, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        let _ = send.finish();
        Ok(())
    };

    // Wait for either direction to complete
    tokio::select! {
        result = forward_to_tcp => result?,
        result = forward_from_tcp => result?,
    }

    Ok(())
}

/// Forward data between stdio and QUIC streams
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
    // Forward from QUIC to stdout
    let forward_to_stdout = async {
        let mut buf = vec![0u8; 8192];
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

    // Forward from stdin to QUIC
    let forward_from_stdin = async {
        let mut buf = vec![0u8; 8192];
        let mut send = send;

        loop {
            match tokio::io::AsyncReadExt::read(&mut stdin, &mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    send.write_all(&buf[..n]).await?;
                }
                Err(e) => return Err::<(), anyhow::Error>(e.into()),
            }
        }
        let _ = send.finish();
        Ok(())
    };

    // Wait for either direction to complete
    tokio::select! {
        result = forward_to_stdout => result?,
        result = forward_from_stdin => result?,
    }

    Ok(())
}
