"""Reproducible lifecycle checks against a real MCP subprocess (or the test double).

Every transition has an oracle; unexpected tool errors, hangs, invalid terminal
results, and unclean EOF shutdown fail the run. Inputs are only read. Native
analysis databases and incremental JSONL evidence live in --output-dir.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import queue
import random
import shutil
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter
from pathlib import Path
from typing import Any

TERMINAL = {"completed", "failed", "cancelled"}


class WireClient:
    """Line-delimited stdio client with a response watchdog and durable trace."""

    def __init__(self, output: Path, *, fake: bool = False, timeout: float = 300):
        output.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self.trace = (output / "trace.jsonl").open("w", encoding="utf-8")
        self.stderr = (output / "stderr.txt").open("w", encoding="utf-8")
        self.responses: queue.Queue[str | None] = queue.Queue()
        self.request_id = 0
        command = [sys.executable, "-m", "binary_ninja_headless_mcp"]
        if fake:
            command.append("--fake-backend")
        env = dict(os.environ)
        # Always exercise this source checkout, even if another version is installed.
        env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
        if not fake:
            env.pop("BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND", None)
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            text=True,
            env=env,
        )

        def read() -> None:
            for line in self.process.stdout:
                self.responses.put(line)
            self.responses.put(None)

        self.reader = threading.Thread(target=read, daemon=True)
        self.reader.start()

    def record(self, event: dict[str, Any]) -> None:
        self.trace.write(json.dumps({"time": time.time(), **event}, sort_keys=True) + "\n")
        self.trace.flush()

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self.request_id,
            "method": method,
            "params": params or {},
        }
        self.record({"request": request})
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        try:
            line = self.responses.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise TimeoutError(f"MCP response timeout: {method} {params}") from exc
        if line is None:
            raise RuntimeError(f"MCP exited before responding: {self.process.poll()}")
        response = json.loads(line)
        self.record({"response": response})
        assert response.get("id") == self.request_id, response
        assert "error" not in response, response
        return response["result"]

    def tool(self, name: str, *, expected_error: str | None = None, **arguments: Any) -> dict:
        response = self.call("tools/call", {"name": name, "arguments": arguments})
        payload = response["structuredContent"]
        if expected_error is not None:
            assert response["isError"] is True, (name, response)
            assert expected_error in payload["error"], (name, response)
        else:
            assert response["isError"] is False, (name, arguments, response)
        return payload

    def close(self) -> None:
        """EOF must drain sessions/tasks and exit successfully without shutdown RPC."""
        try:
            self.process.stdin.close()
            code = self.process.wait(timeout=min(self.timeout, 45))
            assert code == 0, f"MCP exited with {code}; see stderr.txt"
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=10)
            self.reader.join(timeout=5)
            self.process.stdout.close()
            self.stderr.close()
            self.trace.close()


class LifecycleFuzzer:
    """Stateful sequences over sessions, analysis runs, and immutable old tasks."""

    ACTIONS = (
        "async",
        "alias",
        "sync",
        "cancel",
        "old_cancel",
        "status",
        "read",
        "search",
        "invalid",
        "reopen",
        "existing",
        "close_active",
        "overlap",
        "abort",
    )

    def __init__(
        self,
        client: WireClient,
        binary: Path,
        output: Path,
        seed: int,
        analysis_database: Path | None = None,
        *,
        load_options: dict[str, Any] | None = None,
    ):
        self.client = client
        self.binary = binary
        self.output = output
        self.rng = random.Random(seed)
        self.sid = ""
        self.pending: dict[str, bool] = {}
        self.terminal: dict[str, str] = {}
        self.counts: Counter[str] = Counter()
        self.database = output / "checkpoint.bndb"
        self.analysis_database = analysis_database
        self.load_options = dict(load_options or {})
        self.steps = 0

    def tool(self, name: str, **arguments: Any) -> dict:
        return self.client.tool(name, session_id=self.sid, **arguments)

    def settle(self, task_id: str, *, allow_cancel: bool = False) -> dict:
        deadline = time.monotonic() + self.client.timeout
        while True:
            state = self.client.tool("task.status", task_id=task_id)
            if state["status"] in TERMINAL:
                break
            assert not state["result_ready"], state
            if time.monotonic() >= deadline:
                raise TimeoutError(f"task did not terminate: {task_id}")
            time.sleep(0.01)
        assert state["result_ready"], state
        result = self.client.tool("task.result", task_id=task_id)
        assert result["status"] == state["status"], result
        expected = {"completed", "cancelled"} if allow_cancel else {"completed"}
        assert result["status"] in expected, result
        previous = self.terminal.setdefault(task_id, result["status"])
        assert previous == result["status"], (previous, result)
        self.pending.pop(task_id, None)
        return result

    def drain(self) -> None:
        for task_id, allow_cancel in list(self.pending.items()):
            self.settle(task_id, allow_cancel=allow_cancel)

    def start(self, name: str = "analysis.update") -> str:
        payload = self.tool(name)
        task_id = payload["task_id"]
        assert payload["session_id"] == self.sid
        assert payload["status"] in {"queued", "running", "completed"}, payload
        self.pending[task_id] = False
        return task_id

    def check_status(self) -> dict:
        status = self.tool("analysis.status")
        assert {
            "status",
            "state",
            "progress",
            "info",
            "is_aborted",
            "has_log",
            "last_analysis_started_at",
            "last_analysis_completed_at",
            "last_analysis_task_id",
            "last_analysis_error",
        } <= status.keys(), status
        assert status["has_log"] is False
        if status["status"] == "completed":
            assert status["last_analysis_error"] is None
            assert status["last_analysis_completed_at"] >= status["last_analysis_started_at"]
        return status

    def open(self, path: Path, *, analyze: bool) -> None:
        payload = self.client.tool(
            "session.open",
            path=str(path),
            update_analysis=analyze,
            read_only=False,
            options=self.load_options,
        )
        self.sid = payload["session_id"]
        assert "task_id" not in payload and "wait_completed" not in payload, payload
        status = self.check_status()
        assert status["status"] == ("completed" if analyze else "idle"), status

    def initialize(self) -> dict:
        self.client.call("initialize")
        info = self.client.tool("binja.info")
        if self.analysis_database is None:
            self.open(self.binary, analyze=True)
            assert self.tool("database.create_bndb", path=str(self.database))["created"]
        else:
            shutil.copy2(self.analysis_database, self.database)
            self.open(self.database, analyze=True)
        # Exercise the bytes loader and temporary-file cleanup on the full input.
        data = base64.b64encode(self.binary.read_bytes()).decode("ascii")
        extra = self.client.tool(
            "session.open_bytes", data_base64=data, filename=self.binary.name, update_analysis=False
        )
        child = self.client.tool(
            "session.open_existing",
            source_session_id=extra["session_id"],
            update_analysis=False,
            options=self.load_options,
        )
        self.client.tool("session.close", session_id=extra["session_id"])
        grandchild = self.client.tool(
            "session.open_existing",
            source_session_id=child["session_id"],
            update_analysis=False,
            options=self.load_options,
        )
        self.client.tool("session.close", session_id=child["session_id"])
        self.client.tool("session.close", session_id=grandchild["session_id"])
        return info

    def transition(self, action: str) -> None:  # noqa: PLR0912, PLR0915
        self.client.record({"transition": self.steps, "action": action, "session_id": self.sid})
        if action not in {"status", "read", "old_cancel", "invalid"}:
            self.drain()
        if action in {"async", "alias"}:
            self.start("analysis.update" if action == "async" else "task.analysis_update")
        elif action == "sync":
            assert self.tool("analysis.update_and_wait")["status"] == "completed"
        elif action == "status":
            self.check_status()
        elif action == "cancel":
            tid = self.start()
            self.client.tool("task.cancel", task_id=tid)
            self.pending[tid] = True
            self.settle(tid, allow_cancel=True)
            assert self.tool("analysis.update_and_wait")["status"] == "completed"
            assert self.check_status()["is_aborted"] is False
        elif action == "abort":
            tid = self.start()
            self.tool("analysis.abort")
            self.pending[tid] = True
            self.settle(tid, allow_cancel=True)
            assert self.tool("analysis.update_and_wait")["status"] == "completed"
            assert self.check_status()["is_aborted"] is False
        elif action == "old_cancel":
            if self.terminal:
                tid = self.rng.choice(sorted(self.terminal))
                before = self.client.tool("task.status", task_id=tid)
                self.client.tool("task.cancel", task_id=tid)
                after = self.client.tool("task.status", task_id=tid)
                assert before == after, (before, after)
                self.settle(tid, allow_cancel=True)
        elif action == "search":
            task = self.tool("task.search_text", query="main", limit=5)
            self.settle(task["task_id"])
        elif action == "read":
            summary = self.tool("binary.summary")
            self.tool("memory.read", address=summary["start"], length=16)
            functions = self.tool("binary.functions", offset=0, limit=5)["items"]
            assert functions, "completed analysis should discover functions in this corpus"
            address = self.rng.choice(functions)["start"]
            self.tool("binary.get_function_disassembly_at", address=address)
            self.tool("binary.get_function_il_at", address=address, level="llil")
        elif action == "invalid":
            self.client.tool(
                "task.status", task_id="missing-task", expected_error="unknown task_id"
            )
            self.client.tool(
                "analysis.update", session_id="missing-session", expected_error="unknown session_id"
            )
        elif action == "reopen":
            self.tool("session.close")
            self.open(self.database, analyze=self.rng.choice([True, False]))
        elif action == "existing":
            opened = self.client.tool(
                "session.open_existing",
                source_session_id=self.sid,
                update_analysis=True,
                options=self.load_options,
            )
            self.client.tool("session.close", session_id=opened["session_id"])
        elif action == "close_active":
            tid = self.start()
            old_sid = self.sid
            self.tool("session.close")
            self.settle(tid, allow_cancel=True)
            self.client.tool(
                "binary.summary", session_id=old_sid, expected_error="unknown session_id"
            )
            self.open(self.database, analyze=False)
        elif action == "overlap":
            first = self.start()
            response = self.client.call(
                "tools/call",
                {"name": "task.analysis_update", "arguments": {"session_id": self.sid}},
            )
            if response["isError"]:
                assert "already running" in response["structuredContent"]["error"], response
            else:
                # A small native job may finish between consecutive wire requests.
                assert self.client.tool("task.status", task_id=first)["status"] == "completed"
                self.pending[response["structuredContent"]["task_id"]] = False
            self.drain()
        else:
            raise AssertionError(action)
        self.counts[action] += 1
        self.steps += 1
        (self.output / "progress.json").write_text(
            json.dumps(
                {
                    "completed_transitions": self.steps,
                    "actions": self.counts,
                    "session_id": self.sid,
                    "pending": self.pending,
                },
                indent=2,
            )
            + "\n"
        )

    def run(self, transitions: int) -> dict:
        info = self.initialize()
        actions = list(self.ACTIONS)
        self.rng.shuffle(actions)
        for index in range(transitions):
            self.transition(
                actions[index] if index < len(actions) else self.rng.choice(self.ACTIONS)
            )
        self.drain()
        # Leave one active task for the EOF cleanup path; driver.close verifies exit.
        self.start()
        return {
            "engine": info,
            "transitions": self.steps,
            "actions": dict(self.counts),
            "terminal_tasks": len(self.terminal),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--analysis-database",
        type=Path,
        help="Reuse a completed checkpoint for this binary; copied before use",
    )
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument(
        "--load-options",
        type=json.loads,
        default={},
        help="JSON object of explicit Binary Ninja load/analysis options",
    )
    parser.add_argument("--transitions", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--fake-backend", action="store_true")
    args = parser.parse_args(argv)
    if not isinstance(args.load_options, dict):
        parser.error("--load-options must be a JSON object")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve()
    identity = hashlib.sha256(binary.read_bytes()).hexdigest()
    source = Path(__file__).resolve().parent
    source_hashes = {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(source.glob("*.py"))
    }
    report = {
        "source_hashes": source_hashes,
        "load_options": args.load_options,
        "binary": str(binary),
        "sha256": identity,
        "seed": args.seed,
        "requested_transitions": args.transitions,
        "passed": False,
        "started_at": time.time(),
    }
    client = WireClient(output, fake=args.fake_backend, timeout=args.timeout)
    try:
        try:
            if args.analysis_database:
                report["analysis_database"] = str(args.analysis_database.resolve())
                report["analysis_database_sha256"] = hashlib.sha256(
                    args.analysis_database.read_bytes()
                ).hexdigest()
            report.update(
                LifecycleFuzzer(
                    client,
                    binary,
                    output,
                    args.seed,
                    args.analysis_database,
                    load_options=args.load_options,
                ).run(args.transitions)
            )
        finally:
            client.close()
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == identity, "input was modified"
        report["passed"] = True
    except Exception:
        report["error"] = traceback.format_exc()
    report["finished_at"] = time.time()
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
