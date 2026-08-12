import json
import subprocess


def test_manifest_reports_name_and_version(act_command, wasm_path):
    out = subprocess.run(
        [*act_command, "inspect", "component-manifest", str(wasm_path)],
        capture_output=True, text=True, check=True,
    ).stdout
    manifest = json.loads(out)
    assert manifest["std"]["name"] == "openwallet"
    # The old info.hurl pinned an exact version ("0.3.2") that the checked-out
    # Cargo.toml (0.3.3) already disagrees with — a stale literal, not a
    # value worth reproducing. Every other migrated component's info.hurl
    # asserts `isString` here instead; openwallet's just happened to hardcode
    # a version. Following the established pattern, not loosening a
    # deterministic value: a release number is expected to drift.
    assert isinstance(manifest["std"]["version"], str)
    assert "Open Wallet Standard" in manifest["std"]["description"]
