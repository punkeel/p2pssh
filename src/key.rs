use anyhow::{Result, bail};
use iroh::{
    EndpointId, SecretKey,
    endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks},
};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Load or generate a secret key from disk
pub fn load_or_generate_secret_key(path: &PathBuf) -> Result<SecretKey> {
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
    let key = SecretKey::generate();

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

/// Load authorized keys from a file (z32-encoded public keys, one per line).
/// Returns an error if the file exists but contains no valid keys.
pub fn load_authorized_keys(path: &PathBuf) -> Result<HashSet<EndpointId>> {
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
    if keys.is_empty() {
        bail!(
            "authorized_keys file exists at {} but contains no valid keys. \
             Add valid z32-encoded public keys or remove the file to disable authorization.",
            path.display()
        );
    }
    info!(
        "Loaded {} authorized keys from {}",
        keys.len(),
        path.display()
    );
    Ok(keys)
}

/// Hook to reject unauthorized connections based on EndpointId
#[derive(Debug)]
pub struct AuthHook {
    allowed: Arc<HashSet<EndpointId>>,
}

impl AuthHook {
    pub fn new(allowed: HashSet<EndpointId>) -> Self {
        Self {
            allowed: Arc::new(allowed),
        }
    }
}

impl EndpointHooks for AuthHook {
    async fn after_handshake<'a>(&'a self, conn: &'a Connection) -> AfterHandshakeOutcome {
        if self.allowed.contains(&conn.remote_id()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_authorized_keys_valid() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        // Generate a valid key
        let key = SecretKey::generate();
        let id = key.public();
        writeln!(tmp, "{}", id.to_z32()).unwrap();
        writeln!(tmp, "# comment line").unwrap();
        writeln!(tmp, "  {}  ", id.to_z32()).unwrap(); // duplicate, with whitespace

        let keys = load_authorized_keys(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&id));
    }

    #[test]
    fn test_load_authorized_keys_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let result = load_authorized_keys(&tmp.path().to_path_buf());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no valid keys"));
    }

    #[test]
    fn test_load_authorized_keys_nonexistent() {
        let path = PathBuf::from("/nonexistent/path/to/authorized_keys");
        let keys = load_authorized_keys(&path).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_load_authorized_keys_invalid_lines() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmp, "not-a-valid-z32-key").unwrap();
        writeln!(tmp, "{}", SecretKey::generate().public().to_z32()).unwrap();

        let keys = load_authorized_keys(&tmp.path().to_path_buf()).unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn test_auth_hook_allow() {
        let key = SecretKey::generate();
        let id = key.public();
        let mut allowed = HashSet::new();
        allowed.insert(id);
        let hook = AuthHook::new(allowed);
        // We can't easily test the async after_handshake without a mock Connection,
        // but we can verify the allowed set is stored correctly.
        assert!(hook.allowed.contains(&id));
    }

    #[test]
    fn test_auth_hook_deny_unknown() {
        let key1 = SecretKey::generate();
        let key2 = SecretKey::generate();
        let mut allowed = HashSet::new();
        allowed.insert(key1.public());
        let hook = AuthHook::new(allowed);
        assert!(!hook.allowed.contains(&key2.public()));
    }

    #[test]
    fn test_load_or_generate_secret_key_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.key");

        // First call generates
        let key1 = load_or_generate_secret_key(&path).unwrap();
        // Second call loads
        let key2 = load_or_generate_secret_key(&path).unwrap();
        assert_eq!(key1.public().to_z32(), key2.public().to_z32());
    }

    #[test]
    fn test_load_or_generate_invalid_key_file() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"too-short").unwrap();
        let result = load_or_generate_secret_key(&tmp.path().to_path_buf());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("expected 32 bytes")
        );
    }
}
