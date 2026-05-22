# p2pssh

A privacy-first P2P SSH tunnel using [iroh](https://iroh.computer/) for peer-to-peer connectivity.

## Overview

p2pssh enables secure SSH connections over peer-to-peer QUIC tunnels with automatic NAT traversal. It's a single binary that works as both client and server.

**Key Features:**
- Single binary for both modes (serve and connect)
- Privacy-first: no public DHT or DNS discovery by default
- Custom relay support for NAT traversal
- mDNS discovery on local networks
- QUIC-layer authorization via authorized keys
- Direct connections with relay fallback
- Self-generated cryptographic identities (Ed25519)

## Installation

Build from source:

```bash
cargo build --release
sudo cp target/release/p2pssh /usr/local/bin/
```

## Usage

### Show your peer ID

```bash
p2pssh id
```

The peer ID is a z32-encoded public key used by others to connect to you.

### Server (Remote Machine)

Start the server with a custom relay (_recommended for privacy_):

```bash
p2pssh serve --relay-url https://relay.example.com
```

With authorized keys (any client whose peer ID is not in the file will be rejected at the QUIC layer):

```bash
p2pssh serve --relay-url https://relay.example.com --authorized-keys /etc/p2pssh/authorized_keys
```

Enable mDNS for local network discovery:

```bash
p2pssh serve --relay-url https://relay.example.com --mdns
```

Limit concurrent connections:

```bash
p2pssh serve --relay-url https://relay.example.com --max-connections 50
```

### Client (Local Machine)

Use as SSH ProxyCommand by adding to `~/.ssh/config`:

```
Host my-server
    ProxyCommand p2pssh connect <peer-id> --relay-url https://relay.example.com
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
- `--ssh-host <addr>` - SSH server address (default: `127.0.0.1:22`)
- `--bind <addr>` - Local bind address (default: `0.0.0.0:0`)
- `-k, --key <path>` - Custom key file path
- `--relay-url <url>` - Custom relay URL (e.g. `https://relay.example.com`)
- `--mdns` - Enable mDNS discovery on local network
- `--authorized-keys <path>` - Path to file with authorized client peer IDs (z32 format, one per line)
- `--max-connections <N>` - Maximum concurrent connections (default: `100`)

### `p2pssh connect <peer-id>`
Connect to a remote peer (for use with SSH ProxyCommand).

Options:
- `--bind <addr>` - Local bind address (default: `0.0.0.0:0`)
- `-k, --key <path>` - Custom key file path
- `--relay-url <url>` - Custom relay URL
- `--mdns` - Enable mDNS discovery on local network

## Configuration

### Key Storage

- **Non-root users**: `~/.config/p2pssh/secret.key` (or `$XDG_CONFIG_HOME/p2pssh/secret.key`)
- **Root user**: `/etc/p2pssh/secret.key`

Keys are automatically generated on first use with `0600` permissions.

### Authorized Keys

The authorized keys file contains z32-encoded peer IDs, one per line. Lines starting with `#` and empty lines are ignored.

**Important**: If the authorized keys file exists but contains no valid keys, the server will refuse to start. This prevents accidentally creating an empty file and unknowingly opening the server to all peers.

Example `/etc/p2pssh/authorized_keys`:

```
# Admin laptop
miu6idybyptstd4u9xognugzzxpbrjujhe9q1fcu4sa5i4w6x3ro

# Backup server
w5qdgcky6dxnn1aqk7c63f86gcw5di871mck3mhd4nyeu78ydj9y
```

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

The p2pssh binary:
1. Manages Ed25519 identities
2. Accepts QUIC connections (server mode)
3. Establishes QUIC connections (client mode)
4. Forwards bidirectional streams to/from SSH

Authorization is enforced at the QUIC layer via `EndpointHooks::after_handshake`, before any SSH bytes are exchanged. SSH handles authentication and encryption end-to-end.

## Security

p2pssh is a minimal proxy that forwards connections over P2P tunnels to your SSH server. Authentication and encryption remain handled by SSH itself. The QUIC layer provides an additional authorization gate via peer ID allowlisting.

## Production Deployment

For production use, consider:
1. Running as a systemd service (see `p2pssh.service`)
2. Monitoring with systemd journal: `journalctl -u p2pssh -f`
3. Using `--authorized-keys` to restrict access
4. Using `--relay-url` with a private relay for privacy
5. Regular updates to keep iroh relay compatibility
6. Firewall rules to allow UDP for QUIC (iroh handles NAT traversal)

## License

MIT or Apache 2.0

## Contributing

Pull requests welcome! Please keep the focus on simplicity and minimal dependencies.
