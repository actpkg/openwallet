# All 6 tools are listed
POST {{baseurl}}/tools
{"arguments":{}}
HTTP 200
[Asserts]
jsonpath "$.tools" count == 6
jsonpath "$.tools[*].name" contains "create_wallet"
jsonpath "$.tools[*].name" contains "list_wallets"
jsonpath "$.tools[*].name" contains "get_wallet"
jsonpath "$.tools[*].name" contains "get_address"
jsonpath "$.tools[*].name" contains "sign_message"
jsonpath "$.tools[*].name" contains "sign_transaction"
