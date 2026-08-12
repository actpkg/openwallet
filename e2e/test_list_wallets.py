import json


async def test_list_wallets_returns_created_wallets(client):
    await client.call_tool("create_wallet", {"name": "wallet-a"})
    await client.call_tool("create_wallet", {"name": "wallet-b"})

    result = await client.call_tool("list_wallets", {})
    # list_wallets returns a JSON *array*, not an object — the MCP bridge
    # only structures a lone object part (see the encoding suite's
    # projection notes), so structured_content stays unpopulated here.
    # Asserted explicitly so this breaks loudly if that shape ever changes.
    assert result.structured_content is None
    wallets = json.loads(result.content[0].text)

    # The old hurl file asserted `count >= 2` because its vault was shared
    # across the whole suite (test-wallet-1, test-wallet-24, and an
    # agent-mode wallet could all be present). This vault is private to this
    # test and holds exactly the two wallets created above, so `== 2` is the
    # precise version of the same check, not a stronger invented one.
    assert len(wallets) == 2
    assert isinstance(wallets[0]["name"], str)
    assert isinstance(wallets[0]["id"], str)
    assert len(wallets[0]["accounts"]) == 12
