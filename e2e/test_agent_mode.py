"""Agent-mode e2e: API key + policy enforcement.

NOT part of `just test` / CI, same as the old 07-agent-mode.hurl: it needs a
real `ows` CLI (`npx @open-wallet-standard/core`) writing into `$HOME/.ows`,
plus the component's own `/ows/keys` and `/ows/policies` reads (see
src/key_store.rs, src/policy.rs) — real, un-sandboxed host locations, not a
per-test `tmp_path`. Run via `just test-agent`.

Could NOT be verified end-to-end in the migration sandbox: `mkdir /ows` is
`Permission denied` for a non-root user there, and `key_store.rs`/`policy.rs`
hard-code that absolute path (not `vault_root`-relative), so this is a
pre-existing environment requirement of the component, not something the
migration introduced or can route around from the test side.

Separately, and independently of the above: the old `test-agent` justfile
recipe never passed `-m vault_root=$HOME/.ows` to `act run`, so `vault_root`
stayed at its default ("ows_vault"), which cannot be where `ows wallet
create` actually wrote the agent's wallet (`ows config show` reports its
vault as `$HOME/.ows`). Every wallet lookup in this flow would have 404'd
before ever reaching the policy check the file exists to test. Fixed here by
setting `vault_root` explicitly. Flagging both findings rather than treating
either as verified.
"""

import json
import os
import re
import subprocess
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

OWS = os.environ.get("OWS", "npx @open-wallet-standard/core").split()
LOG_FILE = Path(".pytest-act-stderr.log")


async def test_agent_mode_policy_enforcement(act_command, wasm_path):
    home = Path(os.environ["HOME"])
    wallet_name = f"e2e-agent-pytest-{os.getpid()}"

    subprocess.run(
        [*OWS, "wallet", "create", "--name", wallet_name], check=True, capture_output=True
    )

    policy_file = home / ".ows" / "policies" / "evm-only.json"
    if not policy_file.exists():
        fixture = Path(__file__).parent / "fixtures" / "evm-only-policy.json"
        subprocess.run(
            [*OWS, "policy", "create", "--file", str(fixture)], check=True, capture_output=True
        )

    key_out = subprocess.run(
        [*OWS, "key", "create", "--name", f"{wallet_name}-key",
         "--wallet", wallet_name, "--policy", "evm-only"],
        check=True, capture_output=True, text=True,
    ).stdout
    api_key = next(line for line in key_out.splitlines() if line.startswith("ows_key_"))

    grant = json.dumps({
        "wasi:filesystem": {
            "mode": "allowlist",
            "allow": [{"path": str(home / ".ows"), "mode": "rw"}],
        },
    })
    transport = StdioTransport(
        command=act_command[0],
        args=[
            *act_command[1:], "run", str(wasm_path), "--mcp",
            "--grant", grant,
            "-m", f"vault_root={home / '.ows'}",
        ],
        keep_alive=False,
        log_file=LOG_FILE,
    )

    async with Client(transport) as client:
        # Sign on EVM — allowed by the evm-only policy.
        allowed = await client.call_tool(
            "sign_message",
            {"wallet": wallet_name, "chain": "evm", "message": "hello from agent",
             "_meta": {"credential": api_key}},
        )
        assert re.search(r"^[0-9a-f]+$", allowed.structured_content["signature"])
        assert isinstance(allowed.structured_content["recovery_id"], int)

        # Sign on Solana — denied by the evm-only policy.
        denied = await client.call_tool(
            "sign_message",
            {"wallet": wallet_name, "chain": "solana", "message": "should fail",
             "_meta": {"credential": api_key}},
            raise_on_error=False,
        )
        assert denied.is_error
        assert denied.meta.get("dev.actcore/error-kind") == "std:capability-denied"
        assert "not in allowlist" in denied.content[0].text

        # Invalid API key.
        bad_key = await client.call_tool(
            "sign_message",
            {"wallet": wallet_name, "chain": "evm", "message": "fail",
             "_meta": {"credential": "ows_key_invalid"}},
            raise_on_error=False,
        )
        assert bad_key.is_error
        assert bad_key.meta.get("dev.actcore/error-kind") == "std:capability-denied"
        assert "API key" in bad_key.content[0].text

        # A second wallet the agent key has no access to.
        await client.call_tool("create_wallet", {"name": "out-of-scope-wallet-pytest"})
        out_of_scope = await client.call_tool(
            "sign_message",
            {"wallet": "out-of-scope-wallet-pytest", "chain": "evm", "message": "fail",
             "_meta": {"credential": api_key}},
            raise_on_error=False,
        )
        assert out_of_scope.is_error
        assert out_of_scope.meta.get("dev.actcore/error-kind") == "std:capability-denied"
        assert "does not have access" in out_of_scope.content[0].text
