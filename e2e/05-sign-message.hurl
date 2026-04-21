# EVM (EIP-191)
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"hello world"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" matches /^[0-9a-f]+$/
jsonpath "$.content[0].data.recovery_id" isInteger

# Solana (Ed25519)
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"solana","message":"hello solana"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" matches /^[0-9a-f]+$/

# Bitcoin
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"bitcoin","message":"hello btc"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" isString

# Cosmos
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"cosmos","message":"hello cosmos"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" isString

# Hex encoding
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"deadbeef","encoding":"hex"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" isString

# Deterministic: same input → same signature
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"deterministic-test"}}
HTTP 200
[Captures]
sig1: jsonpath "$.content[0].data.signature"

POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"deterministic-test"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" == {{sig1}}

# Invalid hex message
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"not-hex","encoding":"hex"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "invalid hex"

# Unsupported encoding
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"test-wallet-1","chain":"evm","message":"hello","encoding":"base64"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "unsupported encoding"

# Unknown wallet
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"nope","chain":"evm","message":"hello"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "wallet not found"
