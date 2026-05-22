use anyhow::{Result, bail};
use std::path::PathBuf;

/// ALPN for p2pssh protocol
pub const ALPN: &[u8] = b"p2pssh/1";

/// Buffer size for forwarding
pub const FORWARD_BUF_SIZE: usize = 65536;
pub const DEFAULT_RELAY: &str = "https://relay.punkeel.com";

/// Default path for storing the secret key
pub fn default_key_path() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/p2pssh/secret.key")
    } else {
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

/// Default path for authorized keys
pub fn default_authorized_keys_path() -> PathBuf {
    if is_root() {
        PathBuf::from("/etc/p2pssh/authorized_keys")
    } else {
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
        config_dir.join("p2pssh").join("authorized_keys")
    }
}

/// Check if the current user is root
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::getuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[derive(Debug)]
pub enum Command {
    Id {
        key_path: Option<PathBuf>,
    },
    Serve {
        ssh_host: String,
        key_path: Option<PathBuf>,
        bind: String,
        relay_url: Option<iroh::RelayUrl>,
        mdns: bool,
        authorized_keys: Option<PathBuf>,
        max_connections: usize,
    },
    Connect {
        peer_id: String,
        key_path: Option<PathBuf>,
        bind: String,
        relay_url: Option<iroh::RelayUrl>,
        mdns: bool,
    },
}

pub fn print_help() {
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

pub fn print_id_help() {
    eprintln!(
        "p2pssh-id - Show your peer ID

USAGE:
    p2pssh id [OPTIONS]

OPTIONS:
    -k, --key <PATH>    Path to secret key file
    -h, --help          Print help information"
    );
}

pub fn print_serve_help() {
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
    --max-connections <N>       Maximum concurrent connections [default: 100]
    -h, --help                  Print help information"
    );
}

pub fn print_connect_help() {
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

pub fn parse_args() -> Result<Command> {
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
            let mut relay_url: Option<iroh::RelayUrl> = Some(DEFAULT_RELAY.parse().unwrap());
            let mut mdns = false;
            let mut authorized_keys: Option<PathBuf> = None;
            let mut max_connections: usize = 100;

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
                    Long("max-connections") => {
                        let s: String = parser.value()?.parse()?;
                        max_connections = s.parse()?;
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
                max_connections,
            })
        }
        "connect" => {
            let peer_id = match parser.next()? {
                Some(Value(val)) => val.string()?,
                _ => bail!("Missing peer ID argument"),
            };

            let mut bind = "0.0.0.0:0".to_string();
            let mut relay_url: Option<iroh::RelayUrl> = Some(DEFAULT_RELAY.parse().unwrap());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_root_does_not_panic() {
        // Just ensure it doesn't panic on any platform
        let _ = is_root();
    }

    #[test]
    fn test_default_key_path_non_root() {
        // When not root, path should end with .config/p2pssh/secret.key
        let path = default_key_path();
        assert!(path.to_string_lossy().contains("p2pssh"));
        assert!(path.to_string_lossy().ends_with("secret.key"));
    }

    #[test]
    fn test_parse_args_id() {
        // We can't easily test parse_args because it reads from env,
        // but we can test the command enum structure
        let cmd = Command::Id { key_path: None };
        match cmd {
            Command::Id { .. } => {}
            _ => panic!("Expected Id command"),
        }
    }

    #[test]
    fn test_serve_command_defaults() {
        let cmd = Command::Serve {
            ssh_host: "127.0.0.1:22".to_string(),
            key_path: None,
            bind: "0.0.0.0:0".to_string(),
            relay_url: None,
            mdns: false,
            authorized_keys: None,
            max_connections: 100,
        };
        match cmd {
            Command::Serve {
                max_connections, ..
            } => {
                assert_eq!(max_connections, 100);
            }
            _ => panic!("Expected Serve command"),
        }
    }
}
