# Agent mode: API key + policy enforcement
# agent-wallet, evm-only policy, and api_key are created by justfile setup

# Sign on EVM — allowed by policy
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"{{agent_wallet}}","chain":"evm","message":"hello from agent"}, "metadata":{"credential":"{{api_key}}"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.signature" matches /^[0-9a-f]+$/
jsonpath "$.content[0].data.recovery_id" isInteger

# Sign on Solana — denied by evm-only policy
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"{{agent_wallet}}","chain":"solana","message":"should fail"}, "metadata":{"credential":"{{api_key}}"}}
HTTP 403
[Asserts]
jsonpath "$.error.kind" == "std:capability-denied"
jsonpath "$.error.message" contains "not in allowlist"

# Invalid API key
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"{{agent_wallet}}","chain":"evm","message":"fail"}, "metadata":{"credential":"ows_key_invalid"}}
HTTP 403
[Asserts]
jsonpath "$.error.kind" == "std:capability-denied"
jsonpath "$.error.message" contains "API key"

# Create a second wallet the agent key has no access to
POST {{baseurl}}/tools/create_wallet
{"arguments":{"name":"out-of-scope-wallet"}}
HTTP 200

# Agent key cannot access out-of-scope-wallet
POST {{baseurl}}/tools/sign_message
{"arguments":{"wallet":"out-of-scope-wallet","chain":"evm","message":"fail"}, "metadata":{"credential":"{{api_key}}"}}
HTTP 403
[Asserts]
jsonpath "$.error.kind" == "std:capability-denied"
jsonpath "$.error.message" contains "does not have access"
