# All 6 tools are listed
POST {{baseurl}}/tools
{"arguments":{}}
HTTP 200
[Asserts]
jsonpath "$.tools" count == 6
jsonpath "$.tools[?(@.name=='create-wallet')]" count == 1
jsonpath "$.tools[?(@.name=='list-wallets')]" count == 1
jsonpath "$.tools[?(@.name=='get-wallet')]" count == 1
jsonpath "$.tools[?(@.name=='get-address')]" count == 1
jsonpath "$.tools[?(@.name=='sign-message')]" count == 1
jsonpath "$.tools[?(@.name=='sign-transaction')]" count == 1
