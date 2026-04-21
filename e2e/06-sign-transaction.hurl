# Invalid hex
POST {{baseurl}}/tools/sign_transaction
{"arguments":{"wallet":"test-wallet-1","chain":"evm","tx_hex":"not-valid-hex"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "invalid hex"

# Unknown wallet
POST {{baseurl}}/tools/sign_transaction
{"arguments":{"wallet":"nope","chain":"evm","tx_hex":"deadbeef"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "wallet not found"
