import re

import pytest

# (chain, message) — both need a hex signature back.
HEX_SIGNATURE_CASES = [
    ("evm", "hello world"),
    ("solana", "hello solana"),
]


@pytest.mark.parametrize("chain,message", HEX_SIGNATURE_CASES)
async def test_sign_message_hex_signature(client, wallet, chain, message):
    result = await client.call_tool(
        "sign_message", {"wallet": wallet["name"], "chain": chain, "message": message}
    )
    signature = result.structured_content["signature"]
    # hurl's `matches` is an unanchored search, not a full match (verified
    # against hurl 8.0.1). This pattern already carries its own ^/$, so
    # search and fullmatch agree here — re.search per house convention.
    assert re.search(r"^[0-9a-f]+$", signature)


async def test_sign_message_evm_has_recovery_id(client, wallet):
    result = await client.call_tool(
        "sign_message", {"wallet": wallet["name"], "chain": "evm", "message": "hello world"}
    )
    assert isinstance(result.structured_content["recovery_id"], int)


async def test_sign_message_bitcoin_signature_is_string(client, wallet):
    result = await client.call_tool(
        "sign_message", {"wallet": wallet["name"], "chain": "bitcoin", "message": "hello btc"}
    )
    assert isinstance(result.structured_content["signature"], str)


async def test_sign_message_cosmos_signature_is_string(client, wallet):
    result = await client.call_tool(
        "sign_message", {"wallet": wallet["name"], "chain": "cosmos", "message": "hello cosmos"}
    )
    assert isinstance(result.structured_content["signature"], str)


async def test_sign_message_hex_encoding(client, wallet):
    result = await client.call_tool(
        "sign_message",
        {"wallet": wallet["name"], "chain": "evm", "message": "deadbeef", "encoding": "hex"},
    )
    assert isinstance(result.structured_content["signature"], str)


async def test_sign_message_is_deterministic(client, wallet):
    args = {"wallet": wallet["name"], "chain": "evm", "message": "deterministic-test"}
    first = await client.call_tool("sign_message", args)
    second = await client.call_tool("sign_message", args)
    assert first.structured_content["signature"] == second.structured_content["signature"]


async def test_sign_message_rejects_invalid_hex(client, wallet, expect_error):
    message = await expect_error(
        client, "sign_message",
        {"wallet": wallet["name"], "chain": "evm", "message": "not-hex", "encoding": "hex"},
        "std:invalid-args",
    )
    assert "invalid hex" in message


async def test_sign_message_rejects_unsupported_encoding(client, wallet, expect_error):
    message = await expect_error(
        client, "sign_message",
        {"wallet": wallet["name"], "chain": "evm", "message": "hello", "encoding": "base64"},
        "std:invalid-args",
    )
    assert "unsupported encoding" in message


async def test_sign_message_unknown_wallet(client, expect_error):
    message = await expect_error(
        client, "sign_message", {"wallet": "nope", "chain": "evm", "message": "hello"}, "std:invalid-args"
    )
    assert "wallet not found" in message
