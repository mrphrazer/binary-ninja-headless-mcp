"""Persistent subprocess for real CLI verification calls.

This is a verification accelerator, not another CLI transport: each request calls
``binja_cli.main(argv)`` and creates its ordinary transport. The process and Python
imports are reused, so evidence must identify the worker PID and each invocation
rather than describe each invocation as a separate process launch.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
import traceback
from collections.abc import Mapping
from typing import Any


def _execute(request: Any) -> dict[str, Any]:
    output, errors = io.StringIO(), io.StringIO()
    code = 2
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        try:
            if not isinstance(request, dict) or set(request) - {"argv", "stdin"}:
                raise ValueError("request must be an object containing argv and optional stdin")
            argv, stdin = request.get("argv"), request.get("stdin", "")
            if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv):
                raise ValueError("argv must be a list of strings")
            if not isinstance(stdin, str):
                raise ValueError("stdin must be a string")
            # Import inside capture so stdout remains exclusively the JSONL protocol.
            # Python caches this import; no native Binary Ninja module is loaded here.
            from .binja_cli import main

            previous_stdin = sys.stdin
            try:
                sys.stdin = io.StringIO(stdin)
                code = main(argv)
            finally:
                sys.stdin = previous_stdin
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            if exc.code is not None and not isinstance(exc.code, int):
                print(exc.code, file=sys.stderr)
        except Exception:
            traceback.print_exc()
    return {
        "exit_code": code,
        "stdout": output.getvalue(),
        "stderr": errors.getvalue(),
        "pid": os.getpid(),
    }


def main() -> int:
    """Read requests until EOF; malformed requests do not poison later calls."""
    for line in sys.stdin:
        try:
            response = _execute(json.loads(line))
        except (ValueError, TypeError) as exc:
            response = {
                "exit_code": 2,
                "stdout": "",
                "stderr": f"protocol error: {exc}\n",
                "pid": os.getpid(),
            }
        print(json.dumps(response, ensure_ascii=True), flush=True)
    return 0


class CliWorker:
    """Sequential real CLI calls in one child, with bounded pipe I/O.

    ``env`` is the complete subprocess environment, just as for ``Popen``. Calls
    are intentionally synchronous; callers must not invoke this object concurrently.
    A timeout kills the worker because its next response would be ambiguous.
    """

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self.command = [sys.executable, "-m", "binary_ninja_headless_mcp.cli_verify_worker"]
        # A file avoids unconsumed stderr filling a pipe during startup failures.
        self._errors = tempfile.TemporaryFile(mode="w+b")  # noqa: SIM115 - owned until close()
        try:
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._errors,
                env=env,
            )
        except Exception:
            self._errors.close()
            raise
        self.pid = self.process.pid
        assert self.process.stdin is not None and self.process.stdout is not None
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        self._closed = False

    def invoke(self, argv: list[str], stdin: str = "", timeout: float = 180) -> dict[str, Any]:
        if self._closed or self.process.poll() is not None:
            raise RuntimeError("CLI worker is closed or has exited")
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        data = memoryview((json.dumps({"argv": argv, "stdin": stdin}) + "\n").encode())
        deadline = time.monotonic() + timeout
        output = bytearray()
        assert self.process.stdin is not None and self.process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(self.process.stdin, selectors.EVENT_WRITE)
                selector.register(self.process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError(f"CLI worker {self.pid} timed out after {timeout}s")
                    for key, _mask in selector.select(remaining):
                        if key.fileobj is self.process.stdin:
                            data = data[os.write(key.fd, data) :]
                            if not data:
                                selector.unregister(self.process.stdin)
                        else:
                            chunk = os.read(key.fd, 65536)
                            if not chunk:
                                self._errors.seek(0)
                                errors = self._errors.read().decode(errors="replace")
                                raise RuntimeError(f"CLI worker {self.pid} exited: {errors}")
                            output.extend(chunk)
                            if b"\n" in output:
                                return self._decode(output)
        except Exception:
            self.close(force=True)
            raise

    def _decode(self, output: bytearray) -> dict[str, Any]:
        response = json.loads(output)
        if (
            not isinstance(response, dict)
            or set(response) != {"exit_code", "stdout", "stderr", "pid"}
            or type(response["exit_code"]) is not int
            or response["pid"] != self.pid
            or not isinstance(response["stdout"], str)
            or not isinstance(response["stderr"], str)
        ):
            raise RuntimeError("invalid CLI worker response")
        return response

    def close(self, *, force: bool = False) -> None:
        if self._closed:
            return
        self._closed = True
        assert self.process.stdin is not None and self.process.stdout is not None
        self.process.stdin.close()
        if force and self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process.stdout.close()
            self._errors.close()

    def __enter__(self) -> CliWorker:
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


if __name__ == "__main__":
    raise SystemExit(main())
