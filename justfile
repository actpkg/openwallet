wasm := "target/wasm32-wasip2/release/component_openwallet.wasm"
# OCI reference to publish to (registry/namespace/name, no tag). Override with OCI_REF.
component_ref := env("OCI_REF", "actpkg.dev/library/openwallet")

act := env("ACT", "npx @actcore/act")
actbuild := env("ACT_BUILD", "npx @actcore/act-build")
hurl := env("HURL", "hurl")
ows := env("OWS", "npx @open-wallet-standard/core")
# Random port for the e2e server, in a safe range: above the well-known/common
# dev ports and below the Linux outbound ephemeral range (32768+).
port := `shuf -i 10000-29999 -n 1`
addr := "[::1]:" + port
baseurl := "http://" + addr

# Fetch WIT deps from the registry (ghcr.io/actcore) into wit/deps/.
# wkg-registry.toml maps the act namespace -> actcore.dev (well-known -> ghcr.io/actcore).
init:
    WKG_CONFIG_FILE=wkg-registry.toml wkg wit fetch --type wit

setup: init
    prek install

build:
    cargo build --release

# Embed act:component metadata and act:skill into the wasm.
pack: build
    {{actbuild}} pack {{wasm}}

test: pack
    #!/usr/bin/env bash
    set -euo pipefail
    VAULT=$(mktemp -d)
    mkdir -p "$VAULT/wallets"
    GRANT="{\"wasi:filesystem\":{\"mode\":\"allowlist\",\"allow\":[{\"path\":\"$VAULT\",\"mode\":\"rw\"}]}}"
    {{act}} run {{wasm}} --http --listen "{{addr}}" \
      --grant "$GRANT" \
      -m "vault_root=$VAULT" &
    trap "kill $!; rm -rf $VAULT" EXIT
    curl --retry 60 --retry-connrefused --retry-delay 1 -fsS -o /dev/null {{baseurl}}/info
    {{hurl}} --test --jobs 1 --variable "baseurl={{baseurl}}" --variable "api_key=skip" \
      e2e/info.hurl e2e/tools.hurl \
      e2e/01-create-wallet.hurl e2e/02-list-wallets.hurl e2e/03-get-wallet.hurl \
      e2e/04-get-address.hurl e2e/05-sign-message.hurl e2e/06-sign-transaction.hurl

# Agent mode e2e: creates wallet + policy + API key in ~/.ows, then tests policy enforcement.
test-agent:
    #!/usr/bin/env bash
    set -euo pipefail
    WALLET="e2e-agent-$(date +%s)"
    {{ows}} wallet create --name "$WALLET" >/dev/null
    [ -f "$HOME/.ows/policies/evm-only.json" ] || \
      {{ows}} policy create --file e2e/fixtures/evm-only-policy.json >/dev/null
    TOKEN=$({{ows}} key create --name "$WALLET-key" --wallet "$WALLET" --policy evm-only 2>&1 | grep "^ows_key_")

    GRANT="{\"wasi:filesystem\":{\"mode\":\"allowlist\",\"allow\":[{\"path\":\"$HOME/.ows\",\"mode\":\"rw\"}]}}"
    {{act}} run {{wasm}} --http --listen "{{addr}}" --grant "$GRANT" &
    trap "kill $!" EXIT
    curl --retry 60 --retry-connrefused --retry-delay 1 -fsS -o /dev/null {{baseurl}}/info
    {{hurl}} --test --variable "baseurl={{baseurl}}" --variable "api_key=$TOKEN" --variable "agent_wallet=$WALLET" \
      e2e/07-agent-mode.hurl

publish: pack
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} inspect component-manifest {{wasm}})
    VERSION=$(echo "$INFO" | jq -r .std.version)
    OUTPUT=$({{actbuild}} push {{wasm}} "{{component_ref}}:$VERSION" \
      --skip-if-exists \
      --also-tag latest 2>&1) || { echo "$OUTPUT" >&2; exit 1; }
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}' || true)
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{component_ref}}" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi
