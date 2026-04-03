//! API key store — reads OWS key files from /ows/keys/.

use ows_core::ApiKeyFile;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const KEYS_DIR: &str = "/ows/keys";

/// Token prefix that signals agent mode.
pub const TOKEN_PREFIX: &str = "ows_key_";

/// SHA-256 hash of the raw token string, hex-encoded.
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    hex::encode(digest)
}

/// Look up an API key by the SHA-256 hash of the token.
pub fn load_by_token_hash(token_hash: &str) -> Result<ApiKeyFile, String> {
    let dir = Path::new(KEYS_DIR);
    if !dir.exists() {
        return Err("API key not found (no keys directory)".into());
    }

    let entries = fs::read_dir(dir).map_err(|e| format!("failed to read keys dir: {e}"))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let data = match fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let key: ApiKeyFile = match serde_json::from_str(&data) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if key.token_hash == token_hash {
            return Ok(key);
        }
    }

    Err("API key not found".into())
}

/// Check if a key has expired.
pub fn check_expiry(key: &ApiKeyFile) -> Result<(), String> {
    if let Some(ref expires) = key.expires_at {
        let now = chrono::Utc::now().to_rfc3339();
        if now.as_str() > expires.as_str() {
            return Err(format!("API key '{}' has expired", key.name));
        }
    }
    Ok(())
}
