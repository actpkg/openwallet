wasm := "target/wasm32-wasip2/release/component_openwallet.wasm"

act := env("ACT", "npx @actcore/act")
hurl := env("HURL", "npx @orangeopensource/hurl")
ows := env("OWS", "npx @open-wallet-standard/core")
oras := env("ORAS", "oras")
registry := env("OCI_REGISTRY", "ghcr.io/actpkg")
port := `npx get-port-cli`
addr := "[::1]:" + port
baseurl := "http://" + addr

init:
    wit-deps

setup: init
    prek install

build:
    cargo build --release

test:
    #!/usr/bin/env bash
    set -euo pipefail
    VAULT=$(mktemp -d)
    mkdir -p "$VAULT/wallets"
    {{act}} run {{wasm}} --http --listen "{{addr}}" \
      --fs-policy allowlist --fs-allow "$VAULT/**" \
      --metadata "{\"vault_root\":\"$VAULT\"}" &
    trap "kill $!; rm -rf $VAULT" EXIT
    npx wait-on -t 180s {{baseurl}}/info
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

    {{act}} run {{wasm}} --http --listen "{{addr}}" --allow-dir "/ows:$HOME/.ows" &
    trap "kill $!" EXIT
    npx wait-on -t 10s {{baseurl}}/info
    {{hurl}} --test --variable "baseurl={{baseurl}}" --variable "api_key=$TOKEN" --variable "agent_wallet=$WALLET" \
      e2e/07-agent-mode.hurl

publish:
    #!/usr/bin/env bash
    set -euo pipefail
    INFO=$({{act}} info {{wasm}} --format json)
    NAME=$(echo "$INFO" | jq -r .name)
    VERSION=$(echo "$INFO" | jq -r .version)
    DESC=$(echo "$INFO" | jq -r .description)
    if {{oras}} manifest fetch "{{registry}}/$NAME:$VERSION" >/dev/null 2>&1; then
      echo "$NAME:$VERSION already published, skipping"
      exit 0
    fi
    SOURCE=$(git remote get-url origin 2>/dev/null | sed 's/\.git$//' | sed 's|git@github.com:|https://github.com/|' || echo "")
    OUTPUT=$({{oras}} push "{{registry}}/$NAME:$VERSION" \
      --artifact-type application/wasm \
      --annotation "org.opencontainers.image.version=$VERSION" \
      --annotation "org.opencontainers.image.description=$DESC" \
      --annotation "org.opencontainers.image.source=$SOURCE" \
      "{{wasm}}:application/wasm" 2>&1)
    echo "$OUTPUT"
    DIGEST=$(echo "$OUTPUT" | grep "^Digest:" | awk '{print $2}')
    {{oras}} tag "{{registry}}/$NAME:$VERSION" latest
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
      echo "image={{registry}}/$NAME" >> "$GITHUB_OUTPUT"
      echo "digest=$DIGEST" >> "$GITHUB_OUTPUT"
    fi
