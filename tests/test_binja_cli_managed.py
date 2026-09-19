"""Real subprocess tests for managed worker ownership and cleanup."""

import argparse
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from binary_ninja_headless_mcp import managed_cli as managed


class ManagedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(
            os.environ,
            {"BINJA_CLI_HOME": self.tmp.name, "BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND": "0"},
        )
        self.env.start()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.args = argparse.Namespace(
            action="start", host="127.0.0.1", port=self.port, fake_backend=True
        )

    def tearDown(self):
        with contextlib.suppress(RuntimeError):
            self.run_action("stop")
        self.env.stop()
        self.tmp.cleanup()

    def run_action(self, action):
        self.args.action = action
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(managed.command(self.args), 0)
        return json.loads(out.getvalue())

    def test_start_status_rpc_stop_and_port_release(self):
        start = self.run_action("start")
        self.assertTrue(start["started"])
        self.assertNotIn("token", start)
        self.assertTrue(start["fake_backend"])
        state = managed.live_state()
        self.assertEqual(managed._rpc(state, "ping"), {"status": "ok"})
        self.assertEqual(self.run_action("status")["pid"], start["pid"])
        self.assertFalse(self.run_action("start")["started"])
        self.assertTrue(self.run_action("stop")["stopped"])
        self.assertIsNone(managed.live_state())
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))

    def test_restart_replaces_process(self):
        before = self.run_action("start")
        after = self.run_action("restart")
        self.assertNotEqual(before["pid"], after["pid"])
        self.assertIsNone(managed._identity(before["pid"]))

    def test_inherited_fake_environment_is_recorded(self):
        self.args.fake_backend = False
        with patch.dict(os.environ, {"BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND": "1"}):
            self.assertTrue(self.run_action("start")["fake_backend"])

    def test_occupied_port_does_not_become_managed(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            with self.assertRaisesRegex(RuntimeError, "exited"):
                self.run_action("start")
        self.assertFalse((Path(self.tmp.name) / "server.json").exists())

    def test_corrupt_state_is_preserved(self):
        path = Path(self.tmp.name) / "server.json"
        path.write_text("not json")
        for action in ("start", "stop", "status", "restart"):
            with self.assertRaisesRegex(RuntimeError, "preserved"):
                self.run_action(action)
        self.assertEqual(path.read_text(), "not json")
        path.unlink()

    def test_reused_pid_is_not_signalled(self):
        state = {
            "pid": os.getpid(),
            "process_identity": "different-boot:1",
            "host": "127.0.0.1",
            "port": self.port,
            "fake_backend": True,
            "token": "x" * 64,
        }
        managed._write_state(Path(self.tmp.name), state)
        self.assertFalse(self.run_action("stop")["stopped"])
        self.assertIsNotNone(managed._identity(os.getpid()))

    def test_wrong_token_preserves_live_state(self):
        self.run_action("start")
        path = Path(self.tmp.name) / "server.json"
        original = path.read_text()
        state = json.loads(original)
        state["token"] = "bad" * 32
        managed._write_state(Path(self.tmp.name), state)
        try:
            with self.assertRaisesRegex(RuntimeError, "preserved"):
                self.run_action("stop")
            self.assertEqual(json.loads(path.read_text())["token"], state["token"])
        finally:
            path.write_text(original)

    def test_concurrent_start_launches_only_one_worker(self):
        code = (
            "from binary_ninja_headless_mcp.managed_cli import command; import argparse; "
            "command(argparse.Namespace(action='start', host='127.0.0.1', "
            f"port={self.port}, fake_backend=True))"
        )
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", code],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for _ in range(3)
        ]
        results = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=40)
            self.assertEqual(process.returncode, 0, stderr)
            results.append(json.loads(stdout))
        self.assertEqual(len({item["pid"] for item in results}), 1)
        self.assertEqual(sum(item["started"] for item in results), 1)

    def test_shutdown_rpc_exits_worker(self):
        self.run_action("start")
        state = managed.live_state()
        self.assertTrue(managed._rpc(state, "shutdown")["ok"])
        import time

        deadline = time.monotonic() + 5
        while managed._identity(state["pid"]) and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertIsNone(managed._identity(state["pid"]))
        with contextlib.suppress(ChildProcessError):
            os.waitpid(state["pid"], os.WNOHANG)

    def test_control_rejects_invalid_json_rpc_response(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()

            def respond():
                conn, _ = listener.accept()
                with conn:
                    conn.recv(8192)
                    conn.sendall(b'{"jsonrpc":"2.0","id":2,"result":{}}\n')

            thread = threading.Thread(target=respond)
            thread.start()
            try:
                with self.assertRaisesRegex(RuntimeError, "invalid control response"):
                    managed._rpc(
                        {"host": "127.0.0.1", "port": self.port, "token": "x"}, "initialize"
                    )
            finally:
                thread.join(timeout=5)

    def test_invalid_requests_do_not_terminate_connection(self):
        self.run_action("start")
        with (
            socket.create_connection(("127.0.0.1", self.port), 2) as conn,
            conn.makefile("rb") as stream,
        ):
            for invalid in (b"not-json\n", b"[]\n", b"null\n"):
                conn.sendall(invalid)
                self.assertIn("error", json.loads(stream.readline()))
            conn.sendall(b'{"jsonrpc":"2.0","id":4,"method":"ping"}\n')
            self.assertEqual(json.loads(stream.readline())["result"], {"status": "ok"})

    def test_stalled_control_peer_is_bounded(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            done = threading.Event()

            def stall():
                conn, _ = listener.accept()
                with conn:
                    done.wait(2)

            thread = threading.Thread(target=stall)
            thread.start()
            try:
                with self.assertRaises(TimeoutError):
                    managed._rpc(
                        {"host": "127.0.0.1", "port": self.port, "token": "x"},
                        "initialize",
                        timeout=0.1,
                    )
            finally:
                done.set()
                thread.join(timeout=3)

    def test_start_from_unrelated_working_directory(self):
        previous = Path.cwd()
        try:
            os.chdir(self.tmp.name)
            self.assertTrue(self.run_action("start")["started"])
            self.assertTrue(self.run_action("stop")["stopped"])
        finally:
            os.chdir(previous)

    def test_unsupported_platform_has_clear_error(self):
        with (
            patch.object(managed.sys, "platform", "win32"),
            self.assertRaisesRegex(RuntimeError, "require Linux"),
        ):
            self.run_action("start")
        with (
            patch.object(managed, "fcntl", None),
            self.assertRaisesRegex(RuntimeError, "POSIX flock"),
        ):
            self.run_action("status")

    def test_private_state_directory_required(self):
        os.chmod(self.tmp.name, 0o755)
        try:
            with self.assertRaisesRegex(RuntimeError, "private"):
                self.run_action("start")
        finally:
            os.chmod(self.tmp.name, 0o700)


if __name__ == "__main__":
    unittest.main()
