"""Opt-in licensed native CLI tests, each with a fresh core and private user folder.

Run with BN_CLI_NATIVE_TESTS=1 and PYTHONPATH containing the licensed BN API.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from binary_ninja_headless_mcp.cli_verify import build_fixture
from binary_ninja_headless_mcp.cli_verify_special import COMMANDS, prepare_special

pytestmark = pytest.mark.skipif(
    os.environ.get("BN_CLI_NATIVE_TESTS") != "1",
    reason="set BN_CLI_NATIVE_TESTS=1 to require licensed native CLI verification",
)

WORKER = r"""
import contextlib
import json
import os
import sys
from pathlib import Path
from binary_ninja_headless_mcp.cli_verify import Runner, tcp_server
from binary_ninja_headless_mcp.cli_verify_special import SpecialFixtures, run_special
root, fixture, mode, style = map(str, sys.argv[1:])
root = Path(root)
request_file = root / "special" / "http-observed.json"
class Requests:
    def __iter__(self):
        return iter(json.loads(request_file.read_text()) if request_file.exists() else [])
special = SpecialFixtures(root / "special", Path(os.environ["BN_USER_DIRECTORY"]),
    {k: os.environ[k] for k in ("BN_USER_DIRECTORY", "BN_CLI_NATIVE_REPOSITORY_URL")}, Requests())
backend = None
with contextlib.ExitStack() as stack:
    if mode == "inprocess":
        import binaryninja as bn
        from binary_ninja_headless_mcp import BinjaBackend, SimpleMcpServer
        backend = BinjaBackend(bn)
        server = SimpleMcpServer(backend)
        endpoint = None
    else:
        server = None
        endpoint = stack.enter_context(tcp_server(root, dict(os.environ)))
    runner = Runner(Path(fixture), root, mode=mode, argument_style=style,
        server=server, endpoint=endpoint, env=dict(os.environ))
    try:
        runner.tool("binja.eval", code="bn._init_plugins(); _ = True")
        with runner.isolated(options={"analysis.debugInfo.internal": False,
                                      "analysis.debugInfo.external": False}):
            run_special(runner, special)
        assert all(item["passed"] for item in runner.assertions)
        (root / "special-result.json").write_text(json.dumps(runner.assertions, indent=2))
    finally:
        runner.close()
        if backend is not None:
            backend.shutdown()
"""


@pytest.mark.parametrize("mode", ["inprocess", "tcp"])
@pytest.mark.parametrize("style", ["json", "flags"])
def test_native_special_features(tmp_path: Path, mode: str, style: str):
    fixture = build_fixture(tmp_path / "analysis" / "binja_cli_native")
    root = tmp_path / f"{mode}-{style}"
    with prepare_special(root / "special") as special:
        env = {**os.environ, **special.env}
        for key in (
            "BN_DISABLE_USER_PLUGINS",
            "BN_DISABLE_USER_SETTINGS",
            "BN_DISABLE_REPOSITORY_PLUGINS",
        ):
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, "-c", WORKER, str(root), str(fixture), mode, style],
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        (root / "worker.stdout").write_text(result.stdout)
        (root / "worker.stderr").write_text(result.stderr)
        assert result.returncode == 0, result.stdout + "\n" + result.stderr
        assertions = json.loads((root / "special-result.json").read_text())
        variants = {(item["tool"], item["variant"]) for item in assertions if item["passed"]}
        assert ("debug.parse_and_apply", "native-dwarf") in variants
        assert ("plugin_repo.plugin_action", "restart-after-uninstall") in variants
        assert ("debug.parse_and_apply", "native-separate-debug") in variants
        for context in COMMANDS:
            assert ("plugin.execute", "native-" + context) in variants
    assert not (special.user_directory / "license.dat").exists()
