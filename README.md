# component-openwallet

**OWS wallet tools for AI agents — works everywhere, including Android.**

One `.wasm` file. Zero runtime dependencies. Full OWS vault compatibility.
Policy-gated API keys give agents scoped wallet access without a blank check.

```bash
# Serve over MCP (Claude, GPT, any MCP client)
act run --mcp component-openwallet.wasm --allow-dir /ows:~/.ows

# Direct CLI call
act call component-openwallet.wasm create-wallet --args '{"name":"agent-treasury"}' --allow-dir /ows:~/.ows
act call component-openwallet.wasm sign-message --args '{"wallet":"agent-treasury","chain":"evm","message":"hello"}' --allow-dir /ows:~/.ows

# Android (no npm, no Python, no Docker)
adb push act component-openwallet.wasm /data/local/tmp/
adb shell /data/local/tmp/act call /data/local/tmp/component-openwallet.wasm create-wallet --args '{"name":"demo"}'
```

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

## Agent Mode (API Keys + Policies)

Agents authenticate with scoped API keys instead of wallet passphrases.
The host injects the credential via metadata — the agent never sees it.

```bash
# Owner creates a policy and API key using OWS CLI
ows policy create --file evm-only-policy.json
ows key create --name claude-agent --wallet agent-treasury --policy evm-only
# → ows_key_9c54077282011e978ee12b934cfd627520f0faf9...

# Host passes the key in metadata — agent calls tools normally
act call component-openwallet.wasm sign-message \
  --args '{"wallet":"agent-treasury","chain":"evm","message":"hello"}' \
  -m '{"credential":"ows_key_9c54..."}' \
  --allow-dir /ows:~/.ows
```

**What gets enforced:**

| Check | Example |
|-------|---------|
| Key expiry | `expires_at: "2026-12-31T00:00:00Z"` |
| Wallet scope | Key only accesses wallets it was created for |
| Chain allowlist | `evm-only` policy blocks Solana signing |
| Token validation | Invalid/unknown keys rejected immediately |

## Architecture

```
component-openwallet.wasm (736 KB)
  ├── ows-core    — types, CAIP chain IDs, wallet file format, policy types
  ├── ows-signer  — HD derivation, signing, AES-256-GCM / HKDF encryption
  ├── vault       — read/write ~/.ows/wallets/ via wasi:filesystem
  ├── key_store   — API key lookup by token hash, expiry check
  └── policy      — declarative policy evaluation (AllowedChains, ExpiresAt)
```

Compatible with the OWS CLI vault format (`~/.ows/`). Wallets, keys, and policies
created by `ows` CLI work seamlessly with this component.

## Security Model

The component runs inside a WASM sandbox with capability-based access control:

- **wasi:filesystem** — host controls which directories are mounted
- **No network** — the component cannot make HTTP requests
- **No subprocess** — executable policies are not supported (by design)
- **zeroize** — key material is zeroed after use

The host (act-cli) is the trust boundary. It decides what the component can access.
Audit logging belongs in the host runtime, not the component — the host sees all calls.

**Compared to native OWS CLI:**

| | OWS CLI | ACT Component |
|-|---------|---------------|
| Trust model | OS process isolation | WASM capability sandbox |
| Memory protection | mlock + PR_SET_DUMPABLE | Host-controlled (wasmtime store) |
| Auditability | Binary + dependencies | Single .wasm, reproducible build |
| Policy engine | Declarative + executable | Declarative only (no subprocess in WASM) |
| Portability | Per-platform binary | One .wasm runs everywhere |

## Build

```bash
just init   # fetch WIT deps
just build  # build wasm component
just test   # run e2e tests (owner mode)
just test-agent  # run agent mode tests (requires ows CLI)
```

## Why ACT?

| | MCP Server | ACT Component |
|-|-----------|---------------|
| Runtime | Node.js / Python | None (WASM) |
| Binary size | ~100MB+ | 736 KB |
| Android | Impossible without root | Native `act` binary + .wasm |
| Dependencies | npm install / pip install | Zero |
| Sandboxing | Process-level | WASM capability-based |
| Distribution | Registry per language | OCI registry (one artifact) |

## License

MIT OR Apache-2.0
