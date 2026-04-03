# At least 3: test-wallet-1, test-wallet-24, and agent-wallet from justfile setup
POST {{baseurl}}/tools/list-wallets
{"arguments":{}}
HTTP 200
[Asserts]
jsonpath "$.content[0].data" count >= 2
jsonpath "$.content[0].data[0].name" isString
jsonpath "$.content[0].data[0].id" isString
jsonpath "$.content[0].data[0].accounts" count == 8
