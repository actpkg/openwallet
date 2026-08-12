async def test_sign_transaction_rejects_invalid_hex(client, expect_error):
    # No `wallet` fixture needed: sign_transaction hex-decodes tx_hex before
    # it ever resolves the wallet (see src/lib.rs), so this error fires
    # whether or not "test-wallet-1" exists — measured from source, not
    # assumed, and the old hurl file's dependency on it existing was
    # incidental to its shared-vault ordering, not load-bearing.
    message = await expect_error(
        client, "sign_transaction",
        {"wallet": "test-wallet-1", "chain": "evm", "tx_hex": "not-valid-hex"},
        "std:invalid-args",
    )
    assert "invalid hex" in message


async def test_sign_transaction_unknown_wallet(client, expect_error):
    message = await expect_error(
        client, "sign_transaction", {"wallet": "nope", "chain": "evm", "tx_hex": "deadbeef"}, "std:invalid-args"
    )
    assert "wallet not found" in message
