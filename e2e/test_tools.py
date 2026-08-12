EXPECTED_TOOLS = [
    "create_wallet",
    "list_wallets",
    "get_wallet",
    "get_address",
    "sign_message",
    "sign_transaction",
]


async def test_lists_all_six_tools(client):
    tools = await client.list_tools()
    names = [t.name for t in tools]
    assert len(tools) == 6
    for name in EXPECTED_TOOLS:
        assert name in names
