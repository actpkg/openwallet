async def test_get_wallet_by_name(client, wallet):
    result = await client.call_tool("get_wallet", {"wallet": wallet["name"]})
    info = result.structured_content
    assert info["name"] == "test-wallet"
    assert len(info["accounts"]) == 12


async def test_get_wallet_unknown_raises_not_found(client, expect_error):
    message = await expect_error(
        client, "get_wallet", {"wallet": "nonexistent-wallet"}, "std:invalid-args"
    )
    assert "wallet not found" in message
