# component-openwallet

**OWS wallet tools for AI agents — works everywhere, including Android.**

```bash
# Any AI agent runtime (MCP)
act run --mcp component-openwallet.wasm --allow-dir /ows:~/.ows

# Direct CLI call
act call component-openwallet.wasm create-wallet --args '{"name":"agent-treasury"}'
act call component-openwallet.wasm get-address --args '{"wallet":"agent-treasury","chain":"solana"}'
act call component-openwallet.wasm sign-message --args '{"wallet":"agent-treasury","chain":"evm","message":"hello"}'

# Android (no npm, no Python, no Docker needed)
./act call component-openwallet.wasm get-address --args '{"wallet":"demo","chain":"solana"}'
```

ACT is the first tool format that works natively on mobile devices.
MCP requires a full Node.js/Python environment. ACT requires nothing but a WASM runtime.

## Tools

| Tool | Description |
|------|-------------|
| `create-wallet` | Create a new HD wallet with addresses for all 8 chains |
| `list-wallets` | List all wallets in the vault |
| `get-wallet` | Get wallet details by name or ID |
| `get-address` | Get address for a specific chain |
| `sign-message` | Sign a message (EIP-191 for EVM, Ed25519 for Solana/TON) |
| `sign-transaction` | Sign a raw transaction (hex in, hex out) |

## Supported Chains

EVM (Ethereum, Base, Arbitrum, Polygon, ...), Solana, Bitcoin, Cosmos, Tron, TON, Filecoin, Sui

## Architecture

```
component-openwallet.wasm (674 KB)
  ├── ows-core    — types, CAIP chain IDs, wallet file format
  ├── ows-signer  — HD derivation, signing, AES-256-GCM encryption
  └── vault       — read/write ~/.ows/wallets/ via wasi:filesystem
```

One `.wasm` file. Zero runtime dependencies. Compatible with the OWS CLI vault format.

## Metadata

Pass `passphrase` in metadata to unlock encrypted wallets:

```json
{"passphrase": "my-secret"}
```

## Build

```bash
just init   # fetch WIT deps
just build  # build wasm component
just test   # run e2e tests
```

## Why ACT for OWS?

| | MCP Server | ACT Component |
|-|-----------|---------------|
| Runtime | Node.js / Python | None (WASM) |
| Binary size | ~100MB+ | 674 KB |
| Android | Impossible without root | Native binary + .wasm |
| Dependencies | npm install / pip install | Zero |
| Sandboxing | Process-level | WASM capability-based |

## License

MIT OR Apache-2.0
