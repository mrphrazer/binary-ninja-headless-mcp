from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_single_command_stdio_mode(sample_binary_path: str) -> None:
    sample_path = Path(sample_binary_path)

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "session.open",
                "arguments": {"path": str(sample_path), "update_analysis": False},
            },
        },
    ]
    input_data = "\n".join(json.dumps(req) for req in requests) + "\n"

    process = subprocess.Popen(
        [sys.executable, "binary_ninja_headless_mcp.py"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout_text, stderr_text = process.communicate(input=input_data, timeout=60)
    assert process.returncode == 0, stderr_text

    lines = [line for line in stdout_text.splitlines() if line.strip()]
    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["result"]["serverInfo"]["name"] == "binary_ninja_headless_mcp"
    assert second["result"]["structuredContent"]["filename"] == str(sample_path)
    assert isinstance(second["result"]["structuredContent"]["arch"], str)
    assert second["result"]["structuredContent"]["arch"]


def test_stdio_mode_background_server(sample_binary_path: str) -> None:
    sample_path = Path(sample_binary_path)

    process = subprocess.Popen(
        [sys.executable, "binary_ninja_headless_mcp.py"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        text=True,
    )

    try:
        assert process.stdin is not None
        assert process.stdout is not None

        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        open_session = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "session.open",
                "arguments": {"path": str(sample_path), "update_analysis": False},
            },
        }
        ping = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "health.ping", "arguments": {}},
        }

        for request in (initialize, open_session, ping):
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()

        initialize_response = json.loads(process.stdout.readline().strip())
        open_response = json.loads(process.stdout.readline().strip())
        ping_response = json.loads(process.stdout.readline().strip())

        assert initialize_response["result"]["serverInfo"]["name"] == "binary_ninja_headless_mcp"
        assert open_response["result"]["structuredContent"]["filename"] == str(sample_path)
        assert ping_response["result"]["structuredContent"]["message"] == "pong"
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=60)


def test_stdio_binja_eval_print_does_not_corrupt_json_stream(sample_binary_path: str) -> None:
    sample_path = Path(sample_binary_path)

    process = subprocess.Popen(
        [sys.executable, "binary_ninja_headless_mcp.py"],
        cwd=ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        text=True,
    )
    try:
        assert process.stdin is not None
        assert process.stdout is not None

        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "session.open",
                    "arguments": {
                        "path": str(sample_path),
                        "update_analysis": False,
                        "read_only": False,
                    },
                },
            },
        ]
        for request in requests:
            process.stdin.write(json.dumps(request) + "\n")
            process.stdin.flush()

        _ = json.loads(process.stdout.readline().strip())
        open_response = json.loads(process.stdout.readline().strip())
        session_id = open_response["result"]["structuredContent"]["session_id"]

        eval_request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "binja.eval",
                "arguments": {
                    "session_id": session_id,
                    "code": "print('hello from eval') or 1",
                },
            },
        }
        process.stdin.write(json.dumps(eval_request) + "\n")
        process.stdin.flush()

        eval_response_line = process.stdout.readline().strip()
        eval_response = json.loads(eval_response_line)
        structured = eval_response["result"]["structuredContent"]
        assert structured["result"] == 1
        assert structured["stdout"] == "hello from eval\n"
    finally:
        if process.stdin is not None:
            process.stdin.close()
        process.wait(timeout=60)
