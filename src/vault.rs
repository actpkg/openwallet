//! Vault I/O layer — reads/writes OWS encrypted wallet files under a
//! host-configured vault root directory. Compatible with the OWS CLI
//! vault format. The root is supplied per-call via the Config metadata
//! (`vault_root`); the component has no baked-in path.

use ows_core::EncryptedWallet;
use std::fs;
use std::path::{Path, PathBuf};

const WALLETS_DIR: &str = "wallets";

fn wallets_dir(root: &Path) -> PathBuf {
    root.join(WALLETS_DIR)
}

fn wallet_path(root: &Path, id: &str) -> PathBuf {
    wallets_dir(root).join(format!("{id}.json"))
}

/// Ensure the wallets directory exists under the given root.
pub fn ensure_wallets_dir(root: &Path) -> Result<(), String> {
    let dir = wallets_dir(root);
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("failed to create wallets dir: {e}"))?;
    }
    Ok(())
}

/// List all encrypted wallets in the vault.
pub fn list_wallets(root: &Path) -> Result<Vec<EncryptedWallet>, String> {
    let dir = wallets_dir(root);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut wallets = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| format!("failed to read wallets dir: {e}"))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("failed to read dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            let data = fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            let wallet: EncryptedWallet = serde_json::from_str(&data)
                .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
            wallets.push(wallet);
        }
    }

    Ok(wallets)
}

/// Load a wallet by name or ID.
pub fn load_wallet(root: &Path, name_or_id: &str) -> Result<EncryptedWallet, String> {
    // Try by ID first (direct file lookup).
    let id_path = wallet_path(root, name_or_id);
    if id_path.exists() {
        let data =
            fs::read_to_string(&id_path).map_err(|e| format!("failed to read wallet: {e}"))?;
        return serde_json::from_str(&data).map_err(|e| format!("failed to parse wallet: {e}"));
    }

    // Fall back to name search.
    let wallets = list_wallets(root)?;
    let matches: Vec<_> = wallets
        .into_iter()
        .filter(|w| w.name == name_or_id)
        .collect();

    match matches.len() {
        0 => Err(format!("wallet not found: '{name_or_id}'")),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(format!(
            "ambiguous wallet name '{name_or_id}' matches {n} wallets; use the wallet ID instead"
        )),
    }
}

/// Save an encrypted wallet to the vault.
pub fn save_wallet(root: &Path, wallet: &EncryptedWallet) -> Result<(), String> {
    ensure_wallets_dir(root)?;
    let path = wallet_path(root, &wallet.id);
    let data = serde_json::to_string_pretty(wallet)
        .map_err(|e| format!("failed to serialize wallet: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("failed to write wallet: {e}"))
}

/// Check if a wallet name already exists.
pub fn wallet_name_exists(root: &Path, name: &str) -> Result<bool, String> {
    let wallets = list_wallets(root)?;
    Ok(wallets.iter().any(|w| w.name == name))
}
