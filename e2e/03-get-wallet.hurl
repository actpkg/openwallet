# Get by name
POST {{baseurl}}/tools/get_wallet
{"arguments":{"wallet":"test-wallet-1"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.name" == "test_wallet_1"
jsonpath "$.content[0].data.accounts" count == 8

# Unknown wallet
POST {{baseurl}}/tools/get_wallet
{"arguments":{"wallet":"nonexistent-wallet"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "wallet not found"
