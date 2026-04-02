---
name: openwallet
description: Open Wallet Standard — crypto wallet for AI agents. Create wallets, get addresses, sign messages and transactions across 8 blockchains.
metadata:
  act:
    passphrase: ""
---

# openwallet

Crypto wallet tools for AI agents using the Open Wallet Standard. Supports EVM, Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, and Sui.

## Setup

The host must mount `~/.ows/` to `/ows/` in the component for vault access.

## Tools

### create-wallet
Create a new HD wallet with addresses for all supported chains.

```
create-wallet(name: "agent-treasury")
→ { id, name, accounts: [{ chain_id, address, derivation_path }], created_at }
```

### list-wallets
List all wallets in the vault.

```
list-wallets()
→ [{ id, name, accounts, created_at }]
```

### get-wallet
Get wallet details by name or ID.

```
get-wallet(wallet: "agent-treasury")
→ { id, name, accounts, created_at }
```

### get-address
Get the address for a specific chain.

```
get-address(wallet: "agent-treasury", chain: "solana")
→ "ATcgyZfvPyVkV1nsbKQwGh5a55uWKj2LYpKxGHwWUeo8"
```

### sign-message
Sign a message with chain-specific formatting.

```
sign-message(wallet: "agent-treasury", chain: "evm", message: "hello world")
→ { signature: "0x...", recovery_id: 28 }
```

### sign-transaction
Sign a raw hex-encoded transaction.

```
sign-transaction(wallet: "agent-treasury", chain: "evm", tx_hex: "02f8...")
→ { signature: "0x...", recovery_id: 1 }
```

## Chains

| Chain | ID | Address Format |
|-------|----|----------------|
| EVM | evm, ethereum, base, arbitrum, polygon | 0x... (42 chars) |
| Solana | solana | Base58 (32 bytes) |
| Bitcoin | bitcoin | bc1... (bech32) |
| Cosmos | cosmos | cosmos1... |
| Tron | tron | T... (34 chars) |
| TON | ton | UQ... (48 chars) |
| Filecoin | filecoin | f1... |
| Sui | sui | 0x... (66 chars) |
