# Component metadata
GET {{baseurl}}/info
HTTP 200
[Asserts]
jsonpath "$.std.name" == "openwallet"
jsonpath "$.std.version" == "0.3.0"
jsonpath "$.std.description" contains "Open Wallet Standard"
