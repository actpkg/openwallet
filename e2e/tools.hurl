# All 6 tools are listed
POST {{baseurl}}/tools
{"arguments":{}}
HTTP 200
[Asserts]
jsonpath "$.tools" count == 6
jsonpath "$.tools[?(@.name=='create_wallet')]" count == 1
jsonpath "$.tools[?(@.name=='list_wallets')]" count == 1
jsonpath "$.tools[?(@.name=='get_wallet')]" count == 1
jsonpath "$.tools[?(@.name=='get_address')]" count == 1
jsonpath "$.tools[?(@.name=='sign_message')]" count == 1
jsonpath "$.tools[?(@.name=='sign_transaction')]" count == 1
