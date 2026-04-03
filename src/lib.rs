mod key_store;
mod policy;
mod vault;

use act_sdk::prelude::*;
use ows_core::{
    default_chain_for_type, parse_chain, ApiKeyFile, ChainType, EncryptedWallet, KeyType,
    WalletAccount, ALL_CHAIN_TYPES,
};
use ows_signer::{
    decrypt, encrypt, signer_for_chain, CryptoEnvelope, HdDeriver, Mnemonic, MnemonicStrength,
    SecretBytes,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

act_sdk::embed_skill!("skill/");

/// Metadata passed per-call by the host.
/// The agent never sees this — the host injects it from configuration.
#[derive(Deserialize, schemars::JsonSchema)]
struct Config {
    /// Credential: either a passphrase (owner mode) or an API key `ows_key_...` (agent mode).
    /// Agent mode enables policy enforcement and scoped wallet access.
    #[serde(default)]
    credential: String,
}

// ── Response types ──

#[derive(Serialize)]
struct WalletInfo {
    id: String,
    name: String,
    accounts: Vec<AccountInfo>,
    created_at: String,
}

#[derive(Serialize)]
struct AccountInfo {
    chain_id: String,
    address: String,
    derivation_path: String,
}

#[derive(Serialize)]
struct SignResult {
    signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_id: Option<u8>,
}

fn wallet_to_info(w: &EncryptedWallet) -> WalletInfo {
    WalletInfo {
        id: w.id.clone(),
        name: w.name.clone(),
        accounts: w
            .accounts
            .iter()
            .map(|a| AccountInfo {
                chain_id: a.chain_id.clone(),
                address: a.address.clone(),
                derivation_path: a.derivation_path.clone(),
            })
            .collect(),
        created_at: w.created_at.clone(),
    }
}

// ── Crypto helpers ──

fn derive_all_accounts(mnemonic: &Mnemonic, index: u32) -> Result<Vec<WalletAccount>, String> {
    let mut accounts = Vec::with_capacity(ALL_CHAIN_TYPES.len());
    for ct in &ALL_CHAIN_TYPES {
        let chain = default_chain_for_type(*ct);
        let signer = signer_for_chain(*ct);
        let path = signer.default_derivation_path(index);
        let curve = signer.curve();
        let key = HdDeriver::derive_from_mnemonic(mnemonic, "", &path, curve)
            .map_err(|e| format!("HD derivation failed for {ct}: {e}"))?;
        let address = signer
            .derive_address(key.expose())
            .map_err(|e| format!("address derivation failed for {ct}: {e}"))?;
        accounts.push(WalletAccount {
            account_id: format!("{}:{}", chain.chain_id, address),
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

/// Convert decrypted secret material to a signing key for a specific chain.
fn secret_to_signing_key(
    secret: &SecretBytes,
    key_type: &KeyType,
    chain_type: ChainType,
    index: u32,
) -> Result<SecretBytes, String> {
    match key_type {
        KeyType::Mnemonic => {
            let phrase = std::str::from_utf8(secret.expose())
                .map_err(|_| "wallet contains invalid UTF-8 mnemonic".to_string())?;
            let mnemonic =
                Mnemonic::from_phrase(phrase).map_err(|e| format!("invalid mnemonic: {e}"))?;
            let signer = signer_for_chain(chain_type);
            let path = signer.default_derivation_path(index);
            let curve = signer.curve();
            HdDeriver::derive_from_mnemonic(&mnemonic, "", &path, curve)
                .map_err(|e| format!("HD derivation failed: {e}"))
        }
        KeyType::PrivateKey => {
            let s = String::from_utf8(secret.expose().to_vec())
                .map_err(|_| "invalid key pair data".to_string())?;
            let obj: serde_json::Value =
                serde_json::from_str(&s).map_err(|e| format!("invalid key pair JSON: {e}"))?;
            let signer = signer_for_chain(chain_type);
            let key_field = match signer.curve() {
                ows_signer::Curve::Secp256k1 => "secp256k1",
                ows_signer::Curve::Ed25519 => "ed25519",
            };
            let hex_key = obj[key_field]
                .as_str()
                .ok_or_else(|| format!("missing {key_field} key in key pair"))?;
            let mut key_bytes =
                hex::decode(hex_key).map_err(|e| format!("invalid hex in {key_field}: {e}"))?;
            let result = SecretBytes::from_slice(&key_bytes);
            key_bytes.zeroize();
            Ok(result)
        }
    }
}

// ── Credential resolution ──

/// Resolve a credential to a signing key. Handles both owner mode (passphrase)
/// and agent mode (API key with policy enforcement).
fn resolve_signing_key(
    credential: &str,
    wallet_name_or_id: &str,
    chain_id: &str,
    chain_type: ChainType,
    index: u32,
) -> Result<SecretBytes, ActError> {
    let wallet = vault::load_wallet(wallet_name_or_id).map_err(ActError::invalid_args)?;

    if credential.starts_with(key_store::TOKEN_PREFIX) {
        // Agent mode: look up key → check expiry → check scope → evaluate policies → HKDF decrypt
        resolve_agent_mode(credential, &wallet, chain_id, chain_type, index)
    } else {
        // Owner mode: decrypt with passphrase directly
        resolve_owner_mode(credential, &wallet, chain_type, index)
    }
}

fn resolve_owner_mode(
    passphrase: &str,
    wallet: &EncryptedWallet,
    chain_type: ChainType,
    index: u32,
) -> Result<SecretBytes, ActError> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())
        .map_err(|e| ActError::internal(format!("invalid crypto envelope: {e}")))?;
    let secret = decrypt(&envelope, passphrase)
        .map_err(|e| ActError::internal(format!("decryption failed (wrong passphrase?): {e}")))?;
    secret_to_signing_key(&secret, &wallet.key_type, chain_type, index).map_err(ActError::internal)
}

fn resolve_agent_mode(
    token: &str,
    wallet: &EncryptedWallet,
    chain_id: &str,
    chain_type: ChainType,
    index: u32,
) -> Result<SecretBytes, ActError> {
    // 1. Look up key by token hash
    let token_hash = key_store::hash_token(token);
    let key_file = key_store::load_by_token_hash(&token_hash)
        .map_err(|e| ActError::capability_denied(format!("invalid API key: {e}")))?;

    // 2. Check expiry
    key_store::check_expiry(&key_file)
        .map_err(|e| ActError::capability_denied(e))?;

    // 3. Check wallet scope
    if !key_file.wallet_ids.contains(&wallet.id) {
        return Err(ActError::capability_denied(format!(
            "API key '{}' does not have access to wallet '{}'",
            key_file.name, wallet.name,
        )));
    }

    // 4. Evaluate policies
    evaluate_policies(&key_file, chain_id)?;

    // 5. Decrypt wallet secret from key file using HKDF(token)
    decrypt_from_api_key(&key_file, wallet, token, chain_type, index)
}

fn evaluate_policies(key_file: &ApiKeyFile, chain_id: &str) -> Result<(), ActError> {
    if key_file.policy_ids.is_empty() {
        return Ok(());
    }

    let policies = policy::load_policies(&key_file.policy_ids)
        .map_err(|e| ActError::internal(format!("failed to load policies: {e}")))?;

    let now = chrono::Utc::now();
    let context = ows_core::PolicyContext {
        chain_id: chain_id.to_string(),
        wallet_id: key_file.wallet_ids.first().cloned().unwrap_or_default(),
        api_key_id: key_file.id.clone(),
        transaction: ows_core::policy::TransactionContext {
            to: None,
            value: None,
            raw_hex: String::new(),
            data: None,
        },
        spending: ows_core::policy::SpendingContext {
            daily_total: "0".to_string(),
            date: now.format("%Y-%m-%d").to_string(),
        },
        timestamp: now.to_rfc3339(),
    };

    let result = policy::evaluate(&policies, &context);
    if !result.allow {
        let reason = result.reason.unwrap_or_else(|| "denied by policy".into());
        let policy_id = result.policy_id.unwrap_or_default();
        return Err(ActError::capability_denied(format!(
            "policy '{policy_id}' denied: {reason}"
        )));
    }

    Ok(())
}

fn decrypt_from_api_key(
    key_file: &ApiKeyFile,
    wallet: &EncryptedWallet,
    token: &str,
    chain_type: ChainType,
    index: u32,
) -> Result<SecretBytes, ActError> {
    let envelope_value = key_file.wallet_secrets.get(&wallet.id).ok_or_else(|| {
        ActError::internal(format!(
            "API key has no encrypted secret for wallet {}",
            wallet.id
        ))
    })?;

    let envelope: CryptoEnvelope = serde_json::from_value(envelope_value.clone())
        .map_err(|e| ActError::internal(format!("invalid HKDF envelope: {e}")))?;

    // HKDF decrypt: the token itself is the "passphrase" for HKDF-derived keys
    let secret = decrypt(&envelope, token)
        .map_err(|e| ActError::capability_denied(format!("HKDF decryption failed: {e}")))?;

    secret_to_signing_key(&secret, &wallet.key_type, chain_type, index).map_err(ActError::internal)
}

// ── ACT Component ──

#[act_component]
mod component {
    use super::*;

    /// Create a new universal wallet with addresses for all supported chains.
    #[act_tool(description = "Create a new HD wallet with addresses for EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, and Sui", destructive)]
    fn create_wallet(
        /// Name for the new wallet
        name: String,
        /// Number of mnemonic words: 12 (default) or 24
        words: Option<u32>,
        ctx: &mut ActContext<Config>,
    ) -> ActResult<serde_json::Value> {
        let credential = &ctx.metadata().credential;
        let words = words.unwrap_or(12);

        let strength = match words {
            12 => MnemonicStrength::Words12,
            24 => MnemonicStrength::Words24,
            _ => return Err(ActError::invalid_args("words must be 12 or 24")),
        };

        if vault::wallet_name_exists(&name).map_err(ActError::internal)? {
            return Err(ActError::invalid_args(format!(
                "wallet name already exists: '{name}'"
            )));
        }

        let mnemonic =
            Mnemonic::generate(strength).map_err(|e| ActError::internal(e.to_string()))?;
        let accounts = derive_all_accounts(&mnemonic, 0).map_err(ActError::internal)?;

        let phrase = mnemonic.phrase();
        let crypto_envelope = encrypt(phrase.expose(), credential)
            .map_err(|e| ActError::internal(format!("encryption failed: {e}")))?;
        let crypto_json = serde_json::to_value(&crypto_envelope)
            .map_err(|e| ActError::internal(e.to_string()))?;

        let wallet_id = uuid::Uuid::new_v4().to_string();
        let wallet = EncryptedWallet::new(wallet_id, name, accounts, crypto_json, KeyType::Mnemonic);

        vault::save_wallet(&wallet).map_err(ActError::internal)?;

        let info = wallet_to_info(&wallet);
        serde_json::to_value(&info).map_err(|e| ActError::internal(e.to_string()))
    }

    /// List all wallets in the vault.
    #[act_tool(description = "List all wallets in the vault with their addresses", read_only)]
    fn list_wallets() -> ActResult<serde_json::Value> {
        let wallets = vault::list_wallets().map_err(ActError::internal)?;
        let infos: Vec<WalletInfo> = wallets.iter().map(wallet_to_info).collect();
        serde_json::to_value(&infos).map_err(|e| ActError::internal(e.to_string()))
    }

    /// Get a single wallet by name or ID.
    #[act_tool(description = "Get wallet details and addresses by name or ID", read_only)]
    fn get_wallet(
        /// Wallet name or ID
        wallet: String,
    ) -> ActResult<serde_json::Value> {
        let w = vault::load_wallet(&wallet).map_err(ActError::invalid_args)?;
        let info = wallet_to_info(&w);
        serde_json::to_value(&info).map_err(|e| ActError::internal(e.to_string()))
    }

    /// Get the address for a specific chain.
    #[act_tool(
        description = "Get wallet address for a specific chain (evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui)",
        read_only
    )]
    fn get_address(
        /// Wallet name or ID
        wallet: String,
        /// Chain: evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui, or CAIP-2 ID
        chain: String,
    ) -> ActResult<String> {
        let w = vault::load_wallet(&wallet).map_err(ActError::invalid_args)?;
        let parsed = parse_chain(&chain).map_err(ActError::invalid_args)?;

        let chain_id_prefix = parsed.chain_type.namespace();
        let account = w
            .accounts
            .iter()
            .find(|a| a.chain_id.starts_with(chain_id_prefix))
            .ok_or_else(|| {
                ActError::invalid_args(format!("no account for chain '{chain}' in this wallet"))
            })?;

        Ok(account.address.clone())
    }

    /// Sign an arbitrary message.
    #[act_tool(description = "Sign a message with chain-specific formatting (EIP-191 for EVM, Ed25519 for Solana/TON)")]
    fn sign_message(
        /// Wallet name or ID
        wallet: String,
        /// Chain: evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui
        chain: String,
        /// Message to sign
        message: String,
        /// Message encoding: 'utf8' (default) or 'hex'
        encoding: Option<String>,
        /// Account index (default: 0)
        index: Option<u32>,
        ctx: &mut ActContext<Config>,
    ) -> ActResult<serde_json::Value> {
        let credential = &ctx.metadata().credential;
        let parsed = parse_chain(&chain).map_err(ActError::invalid_args)?;
        let encoding = encoding.as_deref().unwrap_or("utf8");
        let index = index.unwrap_or(0);

        let msg_bytes = match encoding {
            "utf8" => message.as_bytes().to_vec(),
            "hex" => hex::decode(&message)
                .map_err(|e| ActError::invalid_args(format!("invalid hex message: {e}")))?,
            _ => {
                return Err(ActError::invalid_args(format!(
                    "unsupported encoding: {encoding} (use 'utf8' or 'hex')"
                )));
            }
        };

        let key =
            resolve_signing_key(credential, &wallet, parsed.chain_id, parsed.chain_type, index)?;

        let signer = signer_for_chain(parsed.chain_type);
        let output = signer
            .sign_message(key.expose(), &msg_bytes)
            .map_err(|e| ActError::internal(format!("signing failed: {e}")))?;

        let result = SignResult {
            signature: hex::encode(&output.signature),
            recovery_id: output.recovery_id,
        };
        serde_json::to_value(&result).map_err(|e| ActError::internal(e.to_string()))
    }

    /// Sign a raw transaction.
    #[act_tool(description = "Sign a raw transaction (hex-encoded). Returns hex-encoded signature.")]
    fn sign_transaction(
        /// Wallet name or ID
        wallet: String,
        /// Chain: evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui
        chain: String,
        /// Hex-encoded raw transaction (with or without 0x prefix)
        tx_hex: String,
        /// Account index (default: 0)
        index: Option<u32>,
        ctx: &mut ActContext<Config>,
    ) -> ActResult<serde_json::Value> {
        let credential = &ctx.metadata().credential;
        let parsed = parse_chain(&chain).map_err(ActError::invalid_args)?;
        let index = index.unwrap_or(0);

        let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);
        let tx_bytes = hex::decode(tx_hex_clean)
            .map_err(|e| ActError::invalid_args(format!("invalid hex transaction: {e}")))?;

        let key =
            resolve_signing_key(credential, &wallet, parsed.chain_id, parsed.chain_type, index)?;

        let signer = signer_for_chain(parsed.chain_type);
        let signable = signer
            .extract_signable_bytes(&tx_bytes)
            .map_err(|e| ActError::invalid_args(format!("failed to parse transaction: {e}")))?;
        let output = signer
            .sign_transaction(key.expose(), signable)
            .map_err(|e| ActError::internal(format!("signing failed: {e}")))?;

        let result = SignResult {
            signature: hex::encode(&output.signature),
            recovery_id: output.recovery_id,
        };
        serde_json::to_value(&result).map_err(|e| ActError::internal(e.to_string()))
    }
}
