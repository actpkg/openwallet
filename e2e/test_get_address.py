import pytest

# (chain, expected address prefix) — carried verbatim from the old hurl file,
# including the two chain-alias/CAIP-2 cases at the end.
CHAIN_PREFIX_CASES = [
    ("evm", "0x"),
    ("bitcoin", "bc1"),
    ("cosmos", "cosmos1"),
    ("tron", "T"),
    ("ton", "UQ"),
    ("filecoin", "f1"),
    ("sui", "0x"),
    ("ethereum", "0x"),  # chain alias for evm
    ("eip155:1", "0x"),  # CAIP-2 chain ID
]


@pytest.mark.parametrize("chain,prefix", CHAIN_PREFIX_CASES)
async def test_get_address_by_chain(client, wallet, chain, prefix):
    result = await client.call_tool("get_address", {"wallet": wallet["name"], "chain": chain})
    assert result.content[0].text.startswith(prefix)


async def test_get_address_evm_is_text_plain(client, wallet):
    result = await client.call_tool("get_address", {"wallet": wallet["name"], "chain": "evm"})
    assert result.content[0].meta["dev.actcore/mime-type"] == "text/plain"


async def test_get_address_solana_is_non_empty_string(client, wallet):
    # The old hurl only asserted `isString` here (no prefix check). MCP text
    # content is always a Python `str` by type, so the meaningful equivalent
    # is non-emptiness, not a redundant isinstance check.
    result = await client.call_tool("get_address", {"wallet": wallet["name"], "chain": "solana"})
    assert len(result.content[0].text) > 0


async def test_get_address_unknown_chain(client, wallet, expect_error):
    message = await expect_error(
        client, "get_address", {"wallet": wallet["name"], "chain": "fakecoin"}, "std:invalid-args"
    )
    assert "unknown chain" in message


async def test_get_address_unknown_wallet(client, expect_error):
    message = await expect_error(
        client, "get_address", {"wallet": "nope", "chain": "evm"}, "std:invalid-args"
    )
    assert "wallet not found" in message
