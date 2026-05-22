use anyhow::Result;

use p2pssh::config::Command;
use p2pssh::config::parse_args;
use p2pssh::key::load_or_generate_secret_key;

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
        Command::Id { key_path } => {
            let key_path = key_path.unwrap_or_else(p2pssh::config::default_key_path);
            let secret_key = load_or_generate_secret_key(&key_path)?;
            println!("{}", secret_key.public().to_z32());
            Ok(())
        }
        Command::Serve {
            ssh_host,
            key_path,
            bind,
            relay_url,
            mdns,
            authorized_keys,
            max_connections,
        } => {
            p2pssh::server::cmd_serve(
                ssh_host,
                key_path,
                bind,
                relay_url,
                mdns,
                authorized_keys,
                max_connections,
            )
            .await
        }
        Command::Connect {
            peer_id,
            key_path,
            bind,
            relay_url,
            mdns,
        } => p2pssh::client::cmd_connect(peer_id, key_path, bind, relay_url, mdns).await,
    }
}
