# All 8 chains
POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"evm"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "0x"
jsonpath "$.content[0].mime_type" == "text/plain"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"solana"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" isString

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"bitcoin"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "bc1"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"cosmos"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "cosmos1"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"tron"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "T"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"ton"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "UQ"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"filecoin"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "f1"

POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"sui"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "0x"

# Chain alias: "ethereum" = "evm"
POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"ethereum"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "0x"

# CAIP-2 chain ID
POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"eip155:1"}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" startsWith "0x"

# Unknown chain
POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"test-wallet-1","chain":"fakecoin"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "unknown chain"

# Unknown wallet
POST {{baseurl}}/tools/get-address
{"arguments":{"wallet":"nope","chain":"evm"}}
HTTP 422
[Asserts]
jsonpath "$.error.message" contains "wallet not found"
