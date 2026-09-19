"""Behavioral tests for the standalone CLI, independently of a native license."""

from __future__ import annotations

import io
import json
import socket
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest
from binary_ninja_headless_mcp import binja_cli as cli
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.fake_binja import make_fake_module
from binary_ninja_headless_mcp.server import SimpleMcpServer


@pytest.fixture
def server():
    backend = BinjaBackend(make_fake_module())
    yield SimpleMcpServer(backend)
    backend.shutdown()


def spec(properties):
    return {"properties": properties}


@pytest.mark.parametrize(
    "raw,expected", [("09", 9), ("0xff", 255), ("-0x10", -16), ("+0b10", 2), ("0o10", 8)]
)
def test_integer(raw, expected):
    assert cli._parse_int(raw) == expected


@pytest.mark.parametrize("raw", ["", "x", "0x", "1.2"])
def test_invalid_integer(raw):
    with pytest.raises(cli.CliUsageError):
        cli._parse_int(raw)


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "1e999"])
def test_nonfinite(raw):
    with pytest.raises(cli.CliUsageError):
        cli._parse_float(raw)


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, True),
        ("TRUE", True),
        ("yes", True),
        ("on", True),
        ("1", True),
        ("false", False),
        ("NO", False),
        ("off", False),
        ("0", False),
    ],
)
def test_boolean(raw, expected):
    assert cli._parse_bool(raw) is expected


def test_grammar_and_sources(tmp_path, monkeypatch):
    value = tmp_path / "value.txt"
    value.write_text("line 1\nline 2", encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO('{"unknown":7,"name":"base"}'))
    cli._STDIN_CACHE.clear()
    result = cli.parse_tool_rest(
        [
            "--json-stdin",
            "--name=--literal",
            "--text",
            "@" + str(value),
            "--active",
            "--count",
            "-0x10",
            "--items",
            "1",
            "--items",
            "2",
            "--data:json",
            '{"nested":[1,false,null]}',
            "--unset:null",
        ],
        spec(
            {
                "name": {"type": "string"},
                "text": {"type": "string"},
                "active": {"type": "boolean"},
                "count": {"type": "integer"},
                "items": {"type": "array", "items": {"type": "integer"}},
                "data": {},
                "unset": {},
            }
        ),
    )
    assert result == {
        "unknown": 7,
        "name": "--literal",
        "text": "line 1\nline 2",
        "active": True,
        "count": -16,
        "items": [1, 2],
        "data": {"nested": [1, False, None]},
        "unset": None,
    }


def test_array_union_and_exact_json():
    tool = cli.SPECS["workflow.insert"]
    assert cli.parse_tool_rest(["--activities", "a"], tool)["activities"] == "a"
    assert cli.parse_tool_rest(["--activities", "a", "--activities", "b"], tool)["activities"] == [
        "a",
        "b",
    ]
    assert cli.parse_tool_rest(["--activities:json", '["a","b"]'], tool)["activities"] == ["a", "b"]


def test_native_addresses_and_untyped_values():
    assert cli.parse_tool_rest(["--address", "100"], cli.SPECS["memory.read"])["address"] == "100"
    assert (
        cli.parse_tool_rest(["--address", "0x100"], cli.SPECS["loader.rebase"])["address"]
        == "0x100"
    )
    assert (
        cli.parse_tool_rest(["--value", "false"], cli.SPECS["metadata.store"])["value"] == "false"
    )
    assert (
        cli.parse_tool_rest(["--value:bool", "false"], cli.SPECS["metadata.store"])["value"]
        is False
    )


@pytest.mark.parametrize(
    "rest",
    [
        ["--wat", "x"],
        ["positional"],
        ["--path"],
        ["--json", "[]"],
        ["--json", '{"x":NaN}'],
        ["--json-stdin=yes"],
        ["--path:wat", "x"],
        ["--read-only", "maybe"],
    ],
)
def test_invalid_grammar(rest):
    with pytest.raises(cli.CliUsageError):
        cli.parse_tool_rest(rest, cli.SPECS["session.open"])


def test_json_overrides_independent_of_order():
    tool = cli.SPECS["memory.read"]
    for flags in [
        ["--length", "8", "--json", '{"length":4}'],
        ["--json", '{"length":4}', "--length", "8"],
    ]:
        assert cli.parse_tool_rest(flags, tool)["length"] == 8


def test_required_checked_before_backend_start(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_make_transport", lambda *_a, **_kw: pytest.fail("started backend"))
    assert cli.main(["call", "session.open"]) == 2
    assert "--path" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [[], ["--raw"], ["--quiet"], ["--field", "status"]])
def test_output_modes(flags, server, capsys):
    assert cli.main([*flags, "call", "health.ping"], server=server) == 0
    out = capsys.readouterr().out.strip()
    if flags == ["--raw"]:
        assert json.loads(out)["structuredContent"]["status"] == "ok"
    elif flags == ["--quiet"]:
        assert "ok" in out
    elif flags:
        assert out == "ok"
    else:
        assert json.loads(out)["status"] == "ok"


def test_tool_error(server, capsys):
    assert cli.main(["call", "binary.summary", "--session-id", "missing"], server=server) == 1
    assert "error" in json.loads(capsys.readouterr().out)


def test_field_list_index_and_missing():
    assert cli._extract_path({"a": [{"b": 4}]}, "a.0.b") == 4
    for key in ["a.1.b", "a.x", "missing", "a.-1"]:
        with pytest.raises(cli.CliUsageError):
            cli._extract_path({"a": [{"b": 4}]}, key)


@pytest.mark.parametrize("value", ["host", "host:abc", "host:0", "host:65536", "::1:8766"])
def test_invalid_connect_address(value):
    with pytest.raises(cli.CliUsageError):
        cli._parse_hostport(value)


def test_ipv6_connect_address():
    assert cli._parse_hostport("[::1]:8766") == ("::1", 8766)


def test_transport_selection(monkeypatch):
    args = cli.build_cli_parser().parse_args(
        ["--connect", "localhost:8766", "--in-process", "call", "health.ping"]
    )
    with pytest.raises(cli.CliUsageError):
        cli._make_transport(args)
    monkeypatch.setenv("BINJA_CLI_CONNECT", "localhost:1234")
    monkeypatch.setattr(cli, "_build_inprocess", lambda _args: "local")
    args = cli.build_cli_parser().parse_args(["--in-process", "call", "health.ping"])
    assert cli._make_transport(args) == "local"


@pytest.mark.parametrize("raw", ["0", "-1", "nan", "inf"])
def test_invalid_timeout(raw):
    with pytest.raises(SystemExit) as exc:
        cli.build_cli_parser().parse_args(["--timeout=" + raw, "call", "health.ping"])
    assert exc.value.code == 2


def test_raw_shutdown_guard_before_backend(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_make_transport", lambda *_a, **_kw: pytest.fail("started backend"))
    assert cli.main(["raw", "shutdown"]) == 2
    assert "--yes" in capsys.readouterr().err


def test_raw_rpc_errors_and_notifications(server, capsys):
    assert cli.main(["raw", "missing"], server=server) == 2
    assert "-32601" in capsys.readouterr().err
    assert cli.main(["raw", "notifications/initialized"], server=server) == 0
    assert json.loads(capsys.readouterr().out) == {}


class BatchTransport:
    def __init__(self):
        self.calls = []
        self.session_counter = 0
        self.fail_cleanup = False

    def dispatch(self, _method, params):
        self.calls.append(params)
        name = params["name"]
        payload = {}
        if name in cli._OPEN_TOOLS:
            self.session_counter += 1
            payload["session_id"] = f"s{self.session_counter}"
        if name == "session.close" and self.fail_cleanup:
            return {"isError": True, "structuredContent": {"error": "close failed"}}
        return {"isError": False, "structuredContent": payload}


def batch_args(*flags):
    return cli.build_cli_parser().parse_args(["batch", *flags])


def test_batch_autosession_and_close_after(capsys):
    transport = BatchTransport()
    stream = io.StringIO(
        '\n{"tool":"session.open","args":{"path":"x"}}\n{"name":"binary.summary"}\n'
    )
    assert cli._run_batch_lines(stream, batch_args("--close-after"), transport) == 0
    assert transport.calls[1]["arguments"] == {"session_id": "s1"}
    assert transport.calls[2] == {"name": "session.close", "arguments": {"session_id": "s1"}}
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_batch_no_autosession_still_closes():
    transport = BatchTransport()
    stream = io.StringIO(
        '{"tool":"session.open","args":{"path":"x"}}\n{"tool":"binary.summary","args":{"session_id":"external"}}\n'
    )
    assert (
        cli._run_batch_lines(stream, batch_args("--close-after", "--no-autosession"), transport)
        == 0
    )
    assert transport.calls[-1]["arguments"] == {"session_id": "s1"}
    assert transport.calls[1]["arguments"] == {"session_id": "external"}


@pytest.mark.parametrize(
    "invalid",
    ["not json", "[]", '{"tool":[]}', '{"tool":"health.ping","args":[]}', '{"tool":"missing"}'],
)
def test_batch_parse_errors_continue(invalid, capsys):
    stream = io.StringIO(invalid + '\n{"tool":"health.ping"}\n')
    transport = BatchTransport()
    assert cli._run_batch_lines(stream, batch_args("--continue-on-error"), transport) == 2
    lines = [json.loads(x) for x in capsys.readouterr().out.splitlines()]
    assert "error" in lines[0]
    assert lines[1]["tool"] == "health.ping"


def test_batch_parse_error_cleanup():
    stream = io.StringIO('{"tool":"session.open","args":{"path":"x"}}\nnot json\n')
    transport = BatchTransport()
    assert cli._run_batch_lines(stream, batch_args("--close-after"), transport) == 2
    assert transport.calls[-1]["name"] == "session.close"


def test_batch_close_clears_default_and_avoids_duplicate(capsys):
    stream = io.StringIO(
        '{"tool":"session.open","args":{"path":"x"}}\n{"tool":"session.close"}\n{"tool":"binary.summary"}\n'
    )
    transport = BatchTransport()
    assert cli._run_batch_lines(stream, batch_args("--close-after"), transport) == 2
    assert [x["name"] for x in transport.calls] == ["session.open", "session.close"]
    assert "missing required" in capsys.readouterr().out


def test_batch_cleanup_error_nonzero(capsys):
    transport = BatchTransport()
    transport.fail_cleanup = True
    stream = io.StringIO('{"tool":"session.open","args":{"path":"x"}}\n')
    assert cli._run_batch_lines(stream, batch_args("--close-after"), transport) == 1
    assert "cleanup failed" in capsys.readouterr().err


def test_batch_interruption_closes_session():
    transport = BatchTransport()

    def lines():
        yield '{"tool":"session.open","args":{"path":"x"}}\n'
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        cli._run_batch_lines(lines(), batch_args("--close-after"), transport)
    assert transport.calls[-1]["name"] == "session.close"


@contextmanager
def rpc_peer(response):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    errors = []

    def serve():
        try:
            conn, _ = listener.accept()
            with conn, conn.makefile("rb") as stream:
                request = json.loads(stream.readline())
                body = response(request)
                if body is not None:
                    conn.sendall(body)
        except Exception as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert not errors


def test_remote_large_response():
    body = {"large": "x" * 200000}
    with rpc_peer(
        lambda r: (json.dumps({"jsonrpc": "2.0", "id": r["id"], "result": body}) + "\n").encode()
    ) as port:
        transport = cli.RemoteTransport("127.0.0.1", port, read_timeout=1)
        try:
            assert transport.dispatch("ping", {}) == body
        finally:
            transport.close()


@pytest.mark.parametrize(
    "response",
    [
        b"not json\n",
        b"[]\n",
        b'{"jsonrpc":"2.0","id":3,"result":{}}\n',
        b'{"jsonrpc":"2.0","id":true,"result":{}}\n',
        b'{"jsonrpc":"2.0","id":1,"result":{},"error":{}}\n',
        b'{"jsonrpc":"2.0","id":1,"error":{}}\n',
        b'{"jsonrpc":"2.0","id":1,"result":[]}\n',
        None,
    ],
)
def test_remote_invalid_response(response):
    with rpc_peer(lambda _r: response) as port:
        transport = cli.RemoteTransport("127.0.0.1", port, read_timeout=1)
        try:
            with pytest.raises(ConnectionError):
                transport.dispatch("ping", {})
        finally:
            transport.close()


def test_remote_notification_does_not_wait():
    def respond(request):
        assert "id" not in request

    with rpc_peer(respond) as port:
        transport = cli.RemoteTransport("127.0.0.1", port, read_timeout=1)
        try:
            assert transport.dispatch("notifications/initialized", {}) == {}
        finally:
            transport.close()


def test_remote_wrong_server_rejected():
    result = {"serverInfo": {"name": "ghidra_headless_mcp", "version": "0.2.0"}}
    with (
        rpc_peer(
            lambda r: (
                json.dumps({"jsonrpc": "2.0", "id": r["id"], "result": result}) + "\n"
            ).encode()
        ) as port,
        pytest.raises(cli.CliUsageError, match="not a Binary Ninja"),
    ):
        cli._connect_remote("127.0.0.1", port, version_check=True)


def test_injected_server_not_shutdown(server, capsys):
    assert cli.main(["call", "session.open", "--path", str(Path(__file__))], server=server) == 0
    session_id = json.loads(capsys.readouterr().out)["session_id"]
    assert cli.main(["call", "binary.summary", "--session-id", session_id], server=server) == 0


def test_backend_prints_do_not_contaminate_json(server, capsys):
    def noisy_handler(_arguments):
        print("native plugin diagnostic")
        return {"status": "ok"}

    server._tool_handlers["health.ping"] = noisy_handler
    assert cli.main(["call", "health.ping"], server=server) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"status": "ok"}
    assert "native plugin diagnostic" in captured.err


def test_backend_startup_and_shutdown_prints_go_to_stderr(monkeypatch, capsys):
    original = cli.load_binja_module

    def noisy_loader(fake):
        print("backend startup diagnostic")
        return original(fake)

    monkeypatch.setattr(cli, "load_binja_module", noisy_loader)
    assert cli.main(["--fake-backend", "call", "health.ping"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["status"] == "ok"
    assert "backend startup diagnostic" in captured.err
