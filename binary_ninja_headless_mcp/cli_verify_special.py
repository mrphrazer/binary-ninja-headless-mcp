"""Real native fixtures for debug parsers, commands, and repository actions.

No Binary Ninja import occurs here: prepare_special must run before a licensed
runtime is initialized, and its environment must reach every worker process.
The downloadable extension is harmless and all writes stay in a private user
folder. This intentionally uses the native extension loader, not an API double.
"""

from __future__ import annotations

import base64
import contextlib
import functools
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPOSITORY = "cli-native-fixtures"
PLUGIN = "cli_native_fixture"
PARSER = "CLI native deterministic parser"
COMMANDS = {
    "default": "CLI Native Fixture\\Default",
    "address": "CLI Native Fixture\\Address",
    "range": "CLI Native Fixture\\Range",
    "function": "CLI Native Fixture\\Function",
    "llil_function": "CLI Native Fixture\\LLIL function",
    "llil_instruction": "CLI Native Fixture\\LLIL instruction",
    "mlil_function": "CLI Native Fixture\\MLIL function",
    "mlil_instruction": "CLI Native Fixture\\MLIL instruction",
    "hlil_function": "CLI Native Fixture\\HLIL function",
    "hlil_instruction": "CLI Native Fixture\\HLIL instruction",
    "global": "CLI Native Fixture\\Global",
    "project": "CLI Native Fixture\\Project",
}

# The fixture parser requires a metadata marker, so it cannot run automatically
# at load time and make the explicit parse/apply assertion vacuously true.
STARTUP_PLUGIN = r"""
import os
from pathlib import Path
import binaryninja as bn

def default_command(bv):
    bv.store_metadata("cli.fixture.default", "executed")
    bv.set_comment_at(bv.entry_point, "cli-default-executed")

def address_command(bv, address):
    bv.store_metadata("cli.fixture.address", address)
    bv.set_comment_at(address, "cli-address-executed")

def range_command(bv, address, length):
    bv.store_metadata("cli.fixture.range", [address, length])
    bv.set_comment_at(address, "cli-range-executed:" + str(length))

bn.PluginCommand.register("CLI Native Fixture\\Default", "Native default fixture", default_command)
bn.PluginCommand.register_for_address(
    "CLI Native Fixture\\Address", "Native address fixture", address_command)
bn.PluginCommand.register_for_range(
    "CLI Native Fixture\\Range", "Native range fixture", range_command)


def function_command(bv, function):
    bv.store_metadata("cli.fixture.function", {"start": function.start,
        "class": type(function).__name__})

bn.PluginCommand.register_for_function(
    "CLI Native Fixture\\Function", "Native function fixture", function_command)

def il_callback(kind, instruction):
    def callback(bv, item):
        function = item.function if instruction else item
        marker = {"start": function.source_function.start, "class": type(item).__name__}
        if instruction:
            marker.update(address=item.address, index=item.instr_index)
        bv.store_metadata("cli.fixture." + kind, marker)
    return callback

for level, label in (("low_level", "LLIL"), ("medium_level", "MLIL"), ("high_level", "HLIL")):
    for kind in ("function", "instruction"):
        register = getattr(bn.PluginCommand, "register_for_" + level + "_il_" + kind)
        register("CLI Native Fixture\\" + label + " " + kind, "Native IL fixture",
                 il_callback(label.lower() + "_" + kind, kind == "instruction"))

def global_command():
    Path(bn.user_directory(), "global-command-executed").write_text("executed")

def project_command(project):
    project.store_metadata("cli.fixture.project", project.id)

bn.PluginCommand.register_global(
    "CLI Native Fixture\\Global", "Native global fixture", global_command)
bn.PluginCommand.register_for_project(
    "CLI Native Fixture\\Project", "Native project fixture", project_command)

def valid_debug(bv):
    try:
        return bv.query_metadata("cli.fixture.debug.enabled") is True
    except KeyError:
        return False

def parse_debug(info, bv, debug_view, progress):
    info.add_type("CLI_NATIVE_DEBUG_TYPE", bn.Type.int(4, False))
    info.add_function(bn.DebugFunctionInfo(address=bv.entry_point,
        short_name="cli_native_debug_entry", full_name="cli_native_debug_entry",
        raw_name="cli_native_debug_entry", function_type=bn.Type.function(bn.Type.int(4), [])))
    bv.store_metadata("cli.fixture.debug.parsed", True)
    return True

bn.DebugInfoParser.register("CLI native deterministic parser", valid_debug, parse_debug)
url = os.environ.get("BN_CLI_NATIVE_REPOSITORY_URL")
if url:
    bn.RepositoryManager().add_repository(url, "cli-native-fixtures")
Path(bn.user_directory(), "startup-fixture-loaded").write_text("loaded")
"""

INSTALLED_PLUGIN = """from pathlib import Path
import binaryninja as bn
Path(bn.user_directory(), "installed-fixture-loaded").write_text("loaded")
"""


@dataclass
class SpecialFixtures:
    root: Path
    user_directory: Path
    env: dict[str, str]
    requests: list[str]

    def restart_state(self) -> dict[str, Any]:
        """Inspect persisted native state using a genuinely fresh core process."""
        code = f"""
import json
import binaryninja as bn
m = bn.RepositoryManager()
p = m[{REPOSITORY!r}][{PLUGIN!r}]
print(json.dumps({{"installed": p.installed, "enabled": p.enabled,
    "disable_pending": p.disable_pending, "delete_pending": p.delete_pending}}))
"""
        env = {**os.environ, **self.env}
        for key in (
            "BN_DISABLE_USER_SETTINGS",
            "BN_DISABLE_USER_PLUGINS",
            "BN_DISABLE_REPOSITORY_PLUGINS",
        ):
            env.pop(key, None)
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        return json.loads(result.stdout.strip().splitlines()[-1])


def _write_repository(directory: Path, base: str) -> None:
    extension = {
        "id": "cli-native-fixture",
        "name": "CLI Native Fixture",
        "type": 0,
        "short_description": "Harmless native CLI verification fixture",
        "author_name": "CLI verification",
        "categories": [{"id": 5, "name": "helper"}],
        "homepage": base,
        "path": PLUGIN,
        "using_apis": ["python3"],
        "state": 0,
        "versions_url": base + "/versions.json",
        "official": False,
        "is_paid": False,
        "latest_version_id": "1",
        "view_only": False,
        "license_name": "MIT",
        "license": "",
    }
    version = {
        "id": "1",
        "version_string": "1.0.0",
        "long_description": "Native fixture",
        "changelog": "",
        "dependencies": {},
        "minimum_client_version": 0,
        "created": "2026-01-01T00:00:00Z",
        "subdir": "",
        "platform_versions": [
            {
                "platform": {"name": platform},
                "download_url": base + "/fixture.zip",
                "untracked_download_url": base + "/fixture.zip",
            }
            for platform in (
                "linux-x64",
                "linux-arm64",
                "darwin-x64",
                "darwin-arm64",
                "win-x64",
                "win-arm64",
            )
        ],
    }
    for filename, item in (("plugins.json", extension), ("versions.json", version)):
        (directory / filename).write_text(
            json.dumps(
                {
                    "count": 1,
                    "next": None,
                    "previous": None,
                    "results": [item],
                }
            )
        )
    with zipfile.ZipFile(directory / "fixture.zip", "w") as archive:
        archive.writestr("fixture/__init__.py", INSTALLED_PLUGIN)


@contextlib.contextmanager
def prepare_special(root: Path, license_source: Path | None = None):
    """Yield fixture environment; remove the private license copy on completion.

    Binary Ninja 6's v2 repository format is required. The core may read its
    official manifest discovery endpoint, but public repositories are disabled;
    the only downloadable plugin comes from this localhost server.
    """
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)
    user_directory = root / "user"
    user_directory.mkdir(exist_ok=True, mode=0o700)
    user_directory.chmod(0o700)
    if license_source is None:
        configured = Path(os.environ.get("BN_USER_DIRECTORY", Path.home() / ".binaryninja"))
        candidate = configured / "license.dat"
        license_source = candidate if candidate.is_file() else None
    copied_license = user_directory / "license.dat"
    if license_source is not None:
        # Use an exclusive create with private permissions, never a permissive
        # intermediate copy of the license contents.
        if copied_license.exists():
            copied_license.chmod(0o600)
        fd = os.open(copied_license, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as out, Path(license_source).open("rb") as source:
            shutil.copyfileobj(source, out)
    (user_directory / "settings.json").write_text(
        json.dumps(
            {
                "extensionManager.communityRepo": False,
                "extensionManager.officialRepo": False,
                "network.enableExtensionManager": True,
            }
        )
    )
    plugin_directory = user_directory / "plugins" / "cli_native_startup"
    plugin_directory.mkdir(parents=True, exist_ok=True)
    (plugin_directory / "__init__.py").write_text(STARTUP_PLUGIN)
    http_directory = root / "http"
    http_directory.mkdir(exist_ok=True)
    requests: list[str] = []

    class Handler(http.server.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: ARG002
            requests.append(self.path)
            (root / "http-observed.json").write_text(json.dumps(requests))

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0),
        functools.partial(Handler, directory=str(http_directory)),
    )
    _write_repository(http_directory, f"http://127.0.0.1:{server.server_port}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fixture = SpecialFixtures(
        root,
        user_directory,
        {
            "BN_USER_DIRECTORY": str(user_directory),
            "BN_CLI_NATIVE_REPOSITORY_URL": f"http://127.0.0.1:{server.server_port}/plugins.json",
        },
        requests,
    )
    try:
        yield fixture
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        (root / "http-requests.json").write_text(json.dumps(requests, indent=2))
        copied_license.unlink(missing_ok=True)


def _run_plugin_contexts(runner, special: SpecialFixtures) -> None:
    sid = runner.session_id
    address = runner.function_start
    runner.verify(
        "plugin.valid_commands",
        "registered-native-contexts",
        {"session_id": sid},
        lambda p: set(COMMANDS.values()) <= {item["name"] for item in p["items"]},
        "Native loader exposes all twelve registered command types",
    )
    for kind, name in COMMANDS.items():
        if kind in {"global", "project"}:
            continue
        arguments = {"session_id": sid, "name": name, "perform": True}
        if kind != "default":
            arguments["address"] = address
        if kind == "default":
            marker = "executed"
        elif kind == "address":
            marker = address
        elif kind == "range":
            arguments["length"] = 4
            marker = [address, 4]
        elif kind == "function":
            marker = {"start": address, "class": "Function"}
        else:
            level, context = kind.split("_")
            il = f"bv.get_function_at({address}).{level}"
            if context == "instruction":
                marker = runner.native(
                    f"i = next(iter({il}.instructions))\n"
                    "_ = {'start': i.function.source_function.start, "
                    "'class': type(i).__name__, 'address': i.address, 'index': i.instr_index}"
                )
                arguments["address"] = marker["address"]
            else:
                marker = runner.native(
                    f"{{'start': {il}.source_function.start, 'class': type({il}).__name__}}"
                )
        runner.verify(
            "plugin.execute",
            "native-" + kind,
            arguments,
            lambda p, k=kind, expected=marker: (
                p["executed"] is True
                and runner.native(f"bv.query_metadata('cli.fixture.{k}')") == expected
            ),
            "Native callback receives the exact selected function/IL/address context",
        )
    global_marker = special.user_directory / "global-command-executed"
    global_marker.unlink(missing_ok=True)
    runner.verify(
        "plugin.execute",
        "native-global",
        {"session_id": sid, "name": COMMANDS["global"], "perform": True},
        lambda p: p["executed"] and global_marker.read_text() == "executed",
        "Global native callback creates a new private marker without a view argument",
    )


def _run_project_command(runner) -> None:
    """Open a project-backed file through the existing path-based session API."""
    created = runner.tool(
        "project.create",
        path=str(runner.output / "native-plugin-project.bnpr"),
        name="Native project command fixture",
    )
    project_id = created["project"]["project_id"]
    old_sid = runner.session_id
    project_sid = None
    try:
        file = runner.tool(
            "project.create_file",
            project_id=project_id,
            name=runner.fixture.name,
            data_base64=base64.b64encode(runner.fixture.read_bytes()).decode("ascii"),
        )["file"]
        project_sid = runner.tool(
            "session.open",
            path=file["path_on_disk"],
            read_only=False,
            options={"analysis.debugInfo.internal": False, "analysis.debugInfo.external": False},
        )["session_id"]
        runner.session_id = project_sid
        runner.record(
            "session.open",
            "native-project-context",
            runner.native("bv.project is not None and bv.project_file is not None"),
            "Opening a known project file path naturally retains its native project association",
        )
        runner.verify(
            "plugin.execute",
            "native-project",
            {"session_id": project_sid, "name": COMMANDS["project"], "perform": True},
            lambda p: (
                p["executed"]
                and runner.native(
                    "bv.project.query_metadata('cli.fixture.project') == bv.project.id"
                )
            ),
            "Native project callback receives the session's actual owning project",
        )
    finally:
        runner.session_id = old_sid
        if project_sid is not None:
            runner.tool("session.close", session_id=project_sid)
        runner.tool("project.close", project_id=project_id)


def _run_separate_debug(runner, special: SpecialFixtures, dwarf: str) -> None:
    """Recover real DWARF from a separate file into a stripped native view."""
    case = special.root / "analysis" / (runner.fixture.name + "-separate-debug")
    case.mkdir(parents=True, exist_ok=True)
    stripped = case / (runner.fixture.name + ".stripped")
    debug = case / (runner.fixture.name + ".debug")
    # All outputs remain in the case workspace; the original fixture is unchanged.
    commands = [
        ["objcopy", "--only-keep-debug", str(runner.fixture), str(debug)],
        ["objcopy", "--strip-all", str(runner.fixture), str(stripped)],
    ]
    for command in commands:
        subprocess.run(command, check=True, capture_output=True, text=True)
    identity = {
        "source": str(runner.fixture),
        "source_sha256": hashlib.sha256(runner.fixture.read_bytes()).hexdigest(),
        "stripped": str(stripped),
        "stripped_sha256": hashlib.sha256(stripped.read_bytes()).hexdigest(),
        "debug": str(debug),
        "debug_sha256": hashlib.sha256(debug.read_bytes()).hexdigest(),
        "commands": commands,
    }
    (case / "identity.json").write_text(json.dumps(identity, indent=2))
    (case / "README.md").write_text(
        "# Separate DWARF fixture\n\nObjective: prove explicit debug_path recovers native types "
        "and symbols absent from a stripped binary. Input hashes and reproduction commands: "
        "[identity.json](identity.json). Original source fixture is preserved.\n"
    )
    old_sid = runner.session_id
    separate_sid = None
    try:
        separate_sid = runner.tool(
            "session.open",
            path=str(stripped),
            read_only=False,
            options={"analysis.debugInfo.internal": False, "analysis.debugInfo.external": False},
        )["session_id"]
        runner.session_id = separate_sid
        runner.record(
            "debug.parse_and_apply",
            "separate-debug-before-apply",
            runner.native(
                "bv.get_type_by_name('cli_pair') is None "
                "and not any(f.name == 'cli_add' for f in bv.functions)"
            ),
            "Stripped target has neither the fixture structure nor the local function name",
        )
        runner.verify(
            "debug.parse_and_apply",
            "native-separate-debug",
            {"session_id": separate_sid, "parser_name": dwarf, "debug_path": str(debug)},
            lambda p: (
                p["applied"]
                and p["function_count"] > 0
                and runner.native(
                    "bv.get_type_by_name('cli_pair') is not None "
                    "and any(f.name == 'cli_add' for f in bv.functions)"
                )
            ),
            "Explicit external DWARF restores named native types and functions in stripped target",
        )
    finally:
        runner.session_id = old_sid
        if separate_sid is not None:
            runner.tool("session.close", session_id=separate_sid)


def run_special(runner, special: SpecialFixtures) -> None:
    """Run semantic checks through an all-tool verifier's transport-neutral API."""
    sid = runner.session_id
    _run_plugin_contexts(runner, special)
    runner.native("bv.store_metadata('cli.fixture.debug.enabled', True)")
    runner.verify(
        "debug.parsers",
        "native-registered",
        {"session_id": sid},
        lambda p: PARSER in {item["name"] for item in p["items"]},
        "Registered native parser is valid for marked view",
    )
    runner.verify(
        "debug.parse_and_apply",
        "native-registered",
        {
            "session_id": sid,
            "parser_name": PARSER,
        },
        lambda p: (
            p["applied"]
            and runner.native("bv.get_type_by_name('CLI_NATIVE_DEBUG_TYPE') is not None")
        ),
        "Registered parser creates an independently visible native type",
    )
    # Actual DWARF parser in addition to deterministic registration. The caller
    # compiles its controlled fixture with -g and opens it with debugInfo disabled.
    parsers = runner.tool("debug.parsers", session_id=sid)
    dwarf = next(
        (item["name"] for item in parsers["items"] if "dwarf" in item["name"].lower()), None
    )
    if dwarf is None:
        raise AssertionError("The live debug fixture has no native DWARF parser")
    runner.record(
        "debug.parse_and_apply",
        "dwarf-before-apply",
        runner.native("bv.get_type_by_name('cli_pair') is None"),
        "Automatic debug loading disabled; fixture structure absent before DWARF",
    )
    runner.verify(
        "debug.parse_and_apply",
        "native-dwarf",
        {
            "session_id": sid,
            "parser_name": dwarf,
        },
        lambda p: (
            p["applied"]
            and p["function_count"] > 0
            and runner.native(
                "any(f.name == 'cli_add' for f in bv.functions) "
                "and bv.get_type_by_name('cli_pair') is not None"
            )
        ),
        "Native DWARF parser supplies function records and expected fixture names",
    )
    _run_separate_debug(runner, special, dwarf)
    runner.verify(
        "plugin_repo.check_updates",
        "native-localhost",
        {"perform": True},
        lambda p: (
            p["checked"]
            and not p["dry_run"]
            and any("plugins.json" in path for path in special.requests)
        ),
        "Native repository manager fetched controlled localhost metadata",
    )
    runner.verify(
        "plugin_repo.status",
        "native-localhost",
        {},
        lambda p: any(
            repo["path"] == REPOSITORY
            and any(plugin["path"] == PLUGIN for plugin in repo["plugins"])
            for repo in p["repositories"]
        ),
        "Native repository contains the fixture extension",
    )
    state_code = (
        f"p = bn.RepositoryManager()[{REPOSITORY!r}][{PLUGIN!r}]\n"
        "_ = {'installed': p.installed, 'enabled': p.enabled, "
        "'disable_pending': p.disable_pending, 'delete_pending': p.delete_pending}"
    )
    for action in ("install", "enable", "disable", "uninstall"):

        def effect(payload, action=action):
            state = runner.native(state_code)
            if not payload["changed"]:
                return False
            if action == "install":
                return state["installed"] and any(
                    "fixture.zip" in path for path in special.requests
                )
            if action == "enable":
                return (
                    state["enabled"]
                    and (special.user_directory / "installed-fixture-loaded").is_file()
                )
            if action == "disable":
                return not state["enabled"] and state["disable_pending"]
            return state["delete_pending"] or not state["installed"]

        runner.verify(
            "plugin_repo.plugin_action",
            "native-" + action,
            {
                "repository_path": REPOSITORY,
                "plugin_path": PLUGIN,
                "action": action,
            },
            effect,
            "Native extension state and downloaded/loaded payload reflect " + action,
        )
        if action in {"disable", "uninstall"}:
            state = special.restart_state()
            passed = not state["enabled"] and not state["disable_pending"]
            if action == "uninstall":
                passed = passed and not state["installed"] and not state["delete_pending"]
            runner.record(
                "plugin_repo.plugin_action",
                "restart-after-" + action,
                passed,
                "Deferred native change survives a fresh core process",
                state,
            )

    _run_project_command(runner)
