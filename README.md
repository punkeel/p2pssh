# p2pssh

A minimal P2P SSH tunnel using [iroh](https://iroh.computer/) for peer-to-peer connectivity.

## Overview

p2pssh enables secure SSH connections over peer-to-peer QUIC tunnels with automatic NAT traversal. It's a single binary that works as both client and server.

**Key Features:**
- Single binary for both modes (serve and connect)
- Automatic NAT traversal via iroh
- Direct QUIC connections with relay fallback
- Self-generated cryptographic identities (Ed25519)

## Installation

Build from source:

```bash
cargo build --release
sudo cp target/release/p2pssh /usr/local/bin/
```

## Usage

### Server (Remote Machine)

1. Start the server:
```bash
p2pssh serve
```

The server will display your peer ID and connection instructions.

### Client (Local Machine)

Use as SSH ProxyCommand by adding to `~/.ssh/config`:
```
Host my-server
    ProxyCommand p2pssh connect <peer-id>
    User your-username
```

Then connect:
```bash
ssh my-server
```

## Commands

### `p2pssh id`
Display your peer ID (generates a new identity if needed).

Options:
- `-k, --key <path>` - Custom key file path

### `p2pssh serve`
Run in server mode, forwarding connections to SSH.

Options:
- `--ssh-host <addr>` - SSH server address (default: 127.0.0.1:22)
- `--bind <addr>` - Local bind address (default: 0.0.0.0:0)
- `-k, --key <path>` - Custom key file path

### `p2pssh connect <peer-id>`
Connect to a remote peer (for use with SSH ProxyCommand).

Options:
- `--bind <addr>` - Local bind address (default: 127.0.0.1:0)
- `-k, --key <path>` - Custom key file path

## Configuration

### Key Storage

- **Non-root users**: `~/.config/p2pssh/secret.key` (or `$XDG_CONFIG_HOME/p2pssh/secret.key`)
- **Root user**: `/etc/p2pssh/secret.key`

Keys are automatically generated on first use with 0600 permissions.

### Peer ID Format

Peer IDs use z32 encoding (base32 with the z-base-32 alphabet), which is the same format used internally by iroh. Example:

```
316zwcpy7dxn51mh6cnus9mn97i8uwn8xjsnnx988xx6izdnsuty
```

## Architecture

p2pssh is built on [iroh](https://iroh.computer/), which handles:
- Peer discovery and NAT traversal
- Direct QUIC connections with relay fallback
- Connection multiplexing and reliability

The p2pssh binary simply:
1. Manages Ed25519 identities
2. Accepts QUIC connections (server mode)
3. Establishes QUIC connections (client mode)
4. Forwards bidirectional streams to/from SSH

All dependencies use `default-features = false` with minimal feature sets to reduce bloat.

## Security

p2pssh is a minimal proxy that forwards connections over P2P tunnels to your SSH server.
Security is maintained through simplicity: authentication and ecryption remain handled by SSH itself.

## Production Deployment

For production use, consider:
1. Running as a systemd service (see `p2pssh.service`)
2. Monitoring with systemd journal: `journalctl -u p2pssh -f`
3. Regular updates to keep iroh relay compatibility
4. Firewall rules to allow UDP for QUIC (iroh handles NAT traversal)

## License

MIT or Apache 2.0

## Contributing

Pull requests welcome! Please keep the focus on simplicity and minimal dependencies.
