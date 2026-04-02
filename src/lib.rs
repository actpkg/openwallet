mod vault;

use act_sdk::prelude::*;
use ows_core::{
    default_chain_for_type, parse_chain, ChainType, EncryptedWallet, KeyType, WalletAccount,
    ALL_CHAIN_TYPES,
};
use ows_signer::{
    decrypt, encrypt, signer_for_chain, CryptoEnvelope, HdDeriver, Mnemonic, MnemonicStrength,
    SecretBytes,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

act_sdk::embed_skill!("skill/");

/// Metadata passed per-call: passphrase to unlock the vault.
#[derive(Deserialize, schemars::JsonSchema)]
struct Config {
    /// Passphrase to decrypt the wallet (empty string if none set).
    #[serde(default)]
    passphrase: String,
}

/// Binding-friendly wallet info returned to the caller.
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

/// Derive accounts for all chain families from a mnemonic.
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
        let account_id = format!("{}:{}", chain.chain_id, address);
        accounts.push(WalletAccount {
            account_id,
            address,
            chain_id: chain.chain_id.to_string(),
            derivation_path: path,
        });
    }
    Ok(accounts)
}

/// Decrypt the mnemonic from a wallet and derive the signing key for a chain.
fn decrypt_signing_key(
    wallet: &EncryptedWallet,
    chain_type: ChainType,
    passphrase: &str,
    index: u32,
) -> Result<SecretBytes, String> {
    let envelope: CryptoEnvelope = serde_json::from_value(wallet.crypto.clone())
        .map_err(|e| format!("invalid crypto envelope: {e}"))?;

    let secret = decrypt(&envelope, passphrase)
        .map_err(|e| format!("decryption failed (wrong passphrase?): {e}"))?;

    match wallet.key_type {
        KeyType::Mnemonic => {
            let phrase = std::str::from_utf8(secret.expose())
                .map_err(|_| "wallet contains invalid UTF-8 mnemonic".to_string())?;
            let mnemonic = Mnemonic::from_phrase(phrase)
                .map_err(|e| format!("invalid mnemonic: {e}"))?;
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
            let mut key_bytes = hex::decode(hex_key)
                .map_err(|e| format!("invalid hex in {key_field}: {e}"))?;
            let result = SecretBytes::from_slice(&key_bytes);
            key_bytes.zeroize();
            Ok(result)
        }
    }
}

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
        let passphrase = &ctx.metadata().passphrase;
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
        let accounts =
            derive_all_accounts(&mnemonic, 0).map_err(ActError::internal)?;

        let phrase = mnemonic.phrase();
        let crypto_envelope = encrypt(phrase.expose(), passphrase)
            .map_err(|e| ActError::internal(format!("encryption failed: {e}")))?;
        let crypto_json = serde_json::to_value(&crypto_envelope)
            .map_err(|e| ActError::internal(e.to_string()))?;

        let wallet_id = uuid::Uuid::new_v4().to_string();
        let wallet = EncryptedWallet::new(
            wallet_id,
            name,
            accounts,
            crypto_json,
            KeyType::Mnemonic,
        );

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
    #[act_tool(description = "Get wallet address for a specific chain (evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui)", read_only)]
    fn get_address(
        /// Wallet name or ID
        wallet: String,
        /// Chain: evm, solana, bitcoin, cosmos, tron, ton, filecoin, sui, or CAIP-2 ID
        chain: String,
    ) -> ActResult<String> {
        let w = vault::load_wallet(&wallet).map_err(ActError::invalid_args)?;
        let parsed = parse_chain(&chain).map_err(ActError::invalid_args)?;

        // Find account matching the chain type.
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
        let passphrase = &ctx.metadata().passphrase;
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

        let w = vault::load_wallet(&wallet).map_err(ActError::invalid_args)?;
        let key = decrypt_signing_key(&w, parsed.chain_type, passphrase, index)
            .map_err(ActError::internal)?;

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
        let passphrase = &ctx.metadata().passphrase;
        let parsed = parse_chain(&chain).map_err(ActError::invalid_args)?;
        let index = index.unwrap_or(0);

        let tx_hex_clean = tx_hex.strip_prefix("0x").unwrap_or(&tx_hex);
        let tx_bytes = hex::decode(tx_hex_clean)
            .map_err(|e| ActError::invalid_args(format!("invalid hex transaction: {e}")))?;

        let w = vault::load_wallet(&wallet).map_err(ActError::invalid_args)?;
        let key = decrypt_signing_key(&w, parsed.chain_type, passphrase, index)
            .map_err(ActError::internal)?;

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
