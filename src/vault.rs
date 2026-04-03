//! Vault I/O layer — reads/writes OWS encrypted wallet files from the
//! WASI-mounted `/ows/wallets/` directory. Compatible with the OWS CLI vault format.

use ows_core::EncryptedWallet;
use std::fs;
use std::path::{Path, PathBuf};

const VAULT_ROOT: &str = "/ows";
const WALLETS_DIR: &str = "wallets";

fn wallets_dir() -> PathBuf {
    Path::new(VAULT_ROOT).join(WALLETS_DIR)
}

fn wallet_path(id: &str) -> PathBuf {
    wallets_dir().join(format!("{id}.json"))
}

/// Ensure the wallets directory exists.
pub fn ensure_wallets_dir() -> Result<(), String> {
    let dir = wallets_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| format!("failed to create wallets dir: {e}"))?;
    }
    Ok(())
}

/// List all encrypted wallets in the vault.
pub fn list_wallets() -> Result<Vec<EncryptedWallet>, String> {
    let dir = wallets_dir();
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
pub fn load_wallet(name_or_id: &str) -> Result<EncryptedWallet, String> {
    // Try by ID first (direct file lookup).
    let id_path = wallet_path(name_or_id);
    if id_path.exists() {
        let data =
            fs::read_to_string(&id_path).map_err(|e| format!("failed to read wallet: {e}"))?;
        return serde_json::from_str(&data).map_err(|e| format!("failed to parse wallet: {e}"));
    }

    // Fall back to name search.
    let wallets = list_wallets()?;
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
pub fn save_wallet(wallet: &EncryptedWallet) -> Result<(), String> {
    ensure_wallets_dir()?;
    let path = wallet_path(&wallet.id);
    let data = serde_json::to_string_pretty(wallet)
        .map_err(|e| format!("failed to serialize wallet: {e}"))?;
    fs::write(&path, data).map_err(|e| format!("failed to write wallet: {e}"))
}

/// Check if a wallet name already exists.
pub fn wallet_name_exists(name: &str) -> Result<bool, String> {
    let wallets = list_wallets()?;
    Ok(wallets.iter().any(|w| w.name == name))
}
