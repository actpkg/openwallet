# Create a wallet with default 12 words
POST {{baseurl}}/tools/create-wallet
{"arguments":{"name":"test-wallet-1"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.name" == "test-wallet-1"
jsonpath "$.content[0].data.id" isString
jsonpath "$.content[0].data.created_at" isString
jsonpath "$.content[0].data.accounts" count == 8
jsonpath "$.content[0].data.accounts[0].chain_id" == "eip155:1"
jsonpath "$.content[0].data.accounts[0].address" startsWith "0x"
jsonpath "$.content[0].data.accounts[1].chain_id" startsWith "solana:"
jsonpath "$.content[0].data.accounts[2].address" startsWith "bc1"
jsonpath "$.content[0].data.accounts[3].address" startsWith "cosmos1"
jsonpath "$.content[0].data.accounts[4].address" startsWith "T"
jsonpath "$.content[0].data.accounts[5].address" startsWith "UQ"
jsonpath "$.content[0].data.accounts[6].address" startsWith "f1"
jsonpath "$.content[0].data.accounts[7].chain_id" == "sui:mainnet"

# Duplicate name is rejected
POST {{baseurl}}/tools/create-wallet
{"arguments":{"name":"test-wallet-1"}}
HTTP 422
[Asserts]
jsonpath "$.error.kind" == "std:invalid-args"
jsonpath "$.error.message" contains "already exists"

# Create with 24 words
POST {{baseurl}}/tools/create-wallet
{"arguments":{"name":"test-wallet-24","words":24}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data.accounts" count == 8

# Invalid word count
POST {{baseurl}}/tools/create-wallet
{"arguments":{"name":"bad-words","words":15}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "12 or 24"
