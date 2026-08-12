"""Shared fixtures for the MCP-driven e2e suite.

The suite drives the packed component through `act run --mcp` over stdio with
a real MCP client, so what the tests observe is what an agent observes.
"""

import json
import os
import shlex
import subprocess
import pytest
from pathlib import Path

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

# Measured in docs/specs/2026-08-08-e2e-harness-findings.md, question 1.
from mcp.shared.exceptions import McpError

WASM = "target/wasm32-wasip2/release/component_openwallet.wasm"

# ACT's audit trail writes to stderr unconditionally — it is not governed by
# RUST_LOG — so it is redirected to a file rather than left to flood pytest.
LOG_FILE = Path(".pytest-act-stderr.log")


@pytest.fixture(scope="session")
def act_command() -> list[str]:
    """The ACT invocation, honouring the same override the justfile uses.

    Parsed with shlex, not treated as a single path: the justfile's own
    default for its `act` variable is `npx @actcore/act` — two words — which
    cannot be `argv[0]` for a non-shell `subprocess.run`/`StdioTransport`
    call. A bare `os.environ.get("ACT", "act")` string breaks that default;
    splitting it is what makes both forms ("act" on PATH, and the npx
    two-word default) actually spawn.
    """
    return shlex.split(os.environ.get("ACT", "act"))


@pytest.fixture(scope="session")
def wasm_path(act_command: list[str]) -> Path:
    """The packed component.

    Existence is not enough and neither is a fresh mtime: `cargo build`
    produces a wasm with no `act:component` custom section, and an unpacked
    artifact declares no capability ceiling, so every grant is refused as
    "outside ceiling" and the failures point anywhere but here. This has
    already bitten three times in this workspace, so the fixture checks the
    section rather than the file.
    """
    path = Path(WASM)
    if not path.exists():
        pytest.fail(f"{path} is missing — run `just build && just pack` first")
    probe = subprocess.run(
        [*act_command, "inspect", "component-manifest", str(path)],
        capture_output=True, text=True,
    )
    name = json.loads(probe.stdout or "{}").get("std", {}).get("name", "unknown")
    if name in ("", "unknown"):
        pytest.fail(f"{path} is built but not packed — run `just pack`")
    return path


@pytest.fixture
async def client(act_command: list[str], wasm_path: Path, tmp_path: Path):
    """A connected MCP client, one `act` process AND one private vault per test.

    openwallet needs a `wasi:filesystem` grant to do anything, and it is
    stateful across *wallets* — the nine old hurl files shared a single
    `mktemp -d` vault for the whole suite run (`--jobs 1`, run in file
    order), so 02-06 all read wallets that 01 created. That is real cross-file
    coupling, not incidental: it is exactly the "hidden ordering requirement"
    the migration brief calls out. Rather than reproduce a fixed run order in
    pytest, each test gets its own process AND its own vault directory
    (`tmp_path`, pytest's function-scoped temp dir), and creates whatever
    wallet(s) it needs — see the `wallet` fixture below. Strictly tighter
    isolation than the hurl suite had, not a like-for-like port of its
    ordering.

    `vault_root` is set here, once, via `-m` (the same mechanism the old
    justfile used for the base recipe) rather than per-call `_meta`, because
    every test in this process wants the same vault for its whole lifetime —
    there is no case in the migrated suite where a single test needs two
    different vaults.
    """
    grant = json.dumps({
        "wasi:filesystem": {
            "mode": "allowlist",
            "allow": [{"path": str(tmp_path), "mode": "rw"}],
        }
    })
    transport = StdioTransport(
        command=act_command[0],
        args=[
            *act_command[1:], "run", str(wasm_path), "--mcp",
            "--grant", grant,
            "-m", f"vault_root={tmp_path}",
        ],
        keep_alive=False,  # stateful component: fresh process per test is not optional here
        log_file=LOG_FILE,
    )
    async with Client(transport) as connected:
        yield connected


@pytest.fixture
async def wallet(client) -> dict:
    """A freshly created 12-word wallet in this test's private vault.

    Returns the `WalletInfo` object create_wallet hands back (name, id,
    created_at, accounts) so callers can address it by name without
    hardcoding one. Function-scoped, like `client`, so nothing here survives
    between tests.
    """
    result = await client.call_tool("create_wallet", {"name": "test-wallet"})
    return result.structured_content


@pytest.fixture
def expect_error():
    """Assert a call fails with a specific ACT error kind, and hand back the
    human-readable message so callers can also check its text.

    Exposed as a fixture rather than a plain function so tests never have to
    import from `conftest` — that import only resolves when the test
    directory happens to be on `sys.path`, which is not something to rely on.

    Measured, not assumed. `call-tool` in `act:tools` returns a bare
    `tool-result` with NO `result<>` wrapper — only `list-tools` has one — so
    a guest reporting a failed tool call can only do it through
    `tool-event::error`, which arrives as a result with `is_error` set and the
    kind in `_meta`. **That is the path a tool test will take.**

    The JSON-RPC error path exists for failures that are not the guest's tool
    body: `list-tools`, the session operations, a wasmtime trap, an
    unreachable actor. It raises `mcp.shared.exceptions.McpError` with the
    payload at `exc.error.data` and the human text at `exc.error.message`.
    openwallet's tool bodies raise every error the migrated hurl files check
    (`ActError::invalid_args`/`capability_denied`), so tests take the isError
    path; the exception path is handled here so callers need not care which
    one fires.

    Unlike crypto/filesystem's version of this fixture, openwallet's hurl
    suite asserts on `$.error.message` (substring `contains` checks), not
    just `$.error.kind` — so this version returns the message text instead
    of `None`.
    """

    async def _expect(client, tool: str, arguments: dict, kind: str) -> str:
        try:
            result = await client.call_tool(tool, arguments, raise_on_error=False)
        except McpError as exc:
            data = getattr(getattr(exc, "error", None), "data", None) or {}
            assert data.get("dev.actcore/error-kind") == kind, (
                f"expected {kind} on the JSON-RPC error path, got {data!r}"
            )
            return getattr(exc.error, "message", str(exc))

        assert result.is_error, f"expected {tool} to fail, got {result!r}"
        meta = result.meta or {}
        assert meta.get("dev.actcore/error-kind") == kind, (
            f"expected {kind} on the isError path, got {meta!r}"
        )
        return result.content[0].text if result.content else ""

    return _expect
