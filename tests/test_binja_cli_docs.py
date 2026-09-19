from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from binary_ninja_headless_mcp.catalog import TOOL_DEFAULTS, TOOL_DEFINITIONS
from binary_ninja_headless_mcp.cli_docs import END, START, main, render_reference, update_document

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "BINJA_CLI.md"


def test_generated_reference_is_current_and_complete():
    document = DOCUMENT.read_text(encoding="utf-8")
    assert update_document(document) == document
    entries = re.findall(
        r"#### `([^`]+)`\n\n.*?\n\n```json\n(.*?)\n```\n\nEffective defaults: `(.*?)`\.",
        render_reference(),
        re.DOTALL,
    )
    actual = {
        name: (json.loads(schema), json.loads(defaults)) for name, schema, defaults in entries
    }
    assert len(entries) == len(TOOL_DEFINITIONS)
    assert actual == {
        item["name"]: (item["inputSchema"], TOOL_DEFAULTS.get(item["name"], {}))
        for item in TOOL_DEFINITIONS
    }


def test_reference_check_detects_drift_without_writing(tmp_path):
    path = tmp_path / "guide.md"
    stale = f"Handwritten prefix\n{START}\nstale schema\n{END}\nHandwritten suffix\n"
    path.write_text(stale, encoding="utf-8")
    with pytest.raises(SystemExit) as failure:
        main(["--path", str(path), "--check"])
    assert failure.value.code == 1
    assert path.read_text(encoding="utf-8") == stale
    assert main(["--path", str(path)]) == 0
    updated = path.read_text(encoding="utf-8")
    assert updated.startswith("Handwritten prefix\n")
    assert updated.endswith("\nHandwritten suffix\n")
    assert main(["--path", str(path), "--check"]) == 0


@pytest.mark.parametrize("document", ["", START, END, START + END + START + END])
def test_generation_rejects_missing_or_ambiguous_markers(document):
    with pytest.raises(ValueError, match="exactly one"):
        update_document(document)


@pytest.mark.parametrize("name", ["offline", "fake-batch"])
def test_documented_client_examples(name, tmp_path):
    document = DOCUMENT.read_text(encoding="utf-8")
    match = re.search(rf"<!-- smoke: {name} -->\n```bash\n(.*?)\n```", document, re.DOTALL)
    assert match, f"missing runnable example: {name}"
    # A shell function preserves each documented command verbatim and uses the
    # current test interpreter, including in source checkouts without entry points.
    script = (
        'set -eu\nbinja_cli() { "$DOCS_PYTHON" -m binary_ninja_headless_mcp.binja_cli "$@"; }\n'
    )
    script += match.group(1)
    env = dict(os.environ, DOCS_PYTHON=sys.executable, BINJA_CLI_HOME=str(tmp_path / "managed"))
    env.pop("BINJA_CLI_CONNECT", None)
    env.pop("BINJA_CLI_SESSION", None)
    result = subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    if name == "fake-batch":
        records = [json.loads(line) for line in result.stdout.splitlines()]
        assert [record["tool"] for record in records] == ["session.open", "binary.functions"]
        assert all(record["isError"] is False for record in records)


def test_readme_links_cli_reference():
    assert "[complete CLI guide and generated tool reference](BINJA_CLI.md)" in (
        ROOT / "README.md"
    ).read_text(encoding="utf-8")


def test_generator_does_not_import_binary_ninja():
    script = """
import importlib.abc
import sys

class RejectNativeImport(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'binaryninja' or fullname.startswith('binaryninja.'):
            raise AssertionError('offline documentation imported the native runtime')
        return None

sys.meta_path.insert(0, RejectNativeImport())
from binary_ninja_headless_mcp.cli_docs import main
raise SystemExit(main(['--check']))
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
