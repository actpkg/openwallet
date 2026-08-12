async def test_create_wallet_default_12_words(client):
    result = await client.call_tool("create_wallet", {"name": "test-wallet-1"})
    info = result.structured_content

    assert info["name"] == "test-wallet-1"
    assert isinstance(info["id"], str)
    assert isinstance(info["created_at"], str)

    accounts = info["accounts"]
    assert len(accounts) == 12
    # Positional checks, carried verbatim from the old hurl file. Index 6 was
    # (and still is) not asserted there — ALL_CHAIN_TYPES grew a "spark"
    # entry between "ton" and "filecoin" since the hurl was written, without
    # disturbing any of the other indices, so these still hold unchanged.
    assert accounts[0]["chain_id"] == "eip155:1"
    assert accounts[0]["address"].startswith("0x")
    assert accounts[1]["chain_id"].startswith("solana:")
    assert accounts[2]["address"].startswith("bc1")
    assert accounts[3]["address"].startswith("cosmos1")
    assert accounts[4]["address"].startswith("T")
    assert accounts[5]["address"].startswith("UQ")
    assert accounts[7]["address"].startswith("f1")
    assert accounts[8]["chain_id"] == "sui:mainnet"


async def test_create_wallet_rejects_duplicate_name(client, expect_error):
    await client.call_tool("create_wallet", {"name": "test-wallet-1"})
    message = await expect_error(
        client, "create_wallet", {"name": "test-wallet-1"}, "std:invalid-args"
    )
    assert "already exists" in message


async def test_create_wallet_with_24_words(client):
    # Word count changes mnemonic strength, not the number of derived chains.
    result = await client.call_tool(
        "create_wallet", {"name": "test-wallet-24", "words": 24}
    )
    assert len(result.structured_content["accounts"]) == 12


async def test_create_wallet_rejects_invalid_word_count(client, expect_error):
    message = await expect_error(
        client, "create_wallet", {"name": "bad-words", "words": 15}, "std:invalid-args"
    )
    assert "12 or 24" in message
