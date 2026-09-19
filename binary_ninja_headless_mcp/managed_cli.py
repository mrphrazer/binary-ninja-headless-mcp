"""Owned, persistent TCP workers for ``binja-cli server``.

State and control tokens are private to the current user. TCP analysis itself has
no authentication; bind to loopback unless exposing it is intentional.
"""

from __future__ import annotations

import argparse
import contextlib
import hmac
import json
import os
import secrets
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # Importable on unsupported hosts for a clear CLI diagnostic.
    fcntl = None

DEFAULT_PORT = 8766
START_TIMEOUT = 30.0
STOP_TIMEOUT = 45.0


def _home() -> Path:
    configured = os.environ.get("BINJA_CLI_HOME")
    if configured:
        return Path(configured).expanduser()
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    return Path(runtime) / "binja_cli" if runtime else Path.home() / ".cache" / "binja_cli"


@contextlib.contextmanager
def _locked() -> Iterator[Path]:
    if (
        not sys.platform.startswith("linux")
        or fcntl is None
        or not Path("/proc/sys/kernel/random/boot_id").is_file()
    ):
        raise RuntimeError(
            "Managed servers require Linux with /proc process identity and POSIX flock"
        )
    home = _home()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    if home.stat().st_uid != os.getuid() or home.stat().st_mode & 0o077:
        raise RuntimeError(
            f"Managed state directory must be owned by you and private (chmod 700): {home}"
        )
    with (home / "server.lock").open("a") as lock:
        deadline = time.monotonic() + START_TIMEOUT + STOP_TIMEOUT + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        "Timed out waiting for another managed lifecycle command"
                    ) from exc
                time.sleep(0.05)
        try:
            yield home
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _identity(pid: int) -> str | None:
    """Linux start ticks and boot UUID distinguish recycled PIDs and reboots."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        fields = stat[stat.rindex(")") + 2 :].split()
        if fields[0] == "Z":
            return None
        boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return f"{boot}:{fields[19]}"
    except (OSError, ValueError, IndexError):
        return None


def _read_state(home: Path) -> dict[str, Any] | None:
    path = home / "server.json"
    try:
        state = json.loads(path.read_text())
    except FileNotFoundError:
        return None
    except (ValueError, OSError) as exc:
        raise RuntimeError(
            f"Cannot read managed state {path}; preserved for inspection: {exc}"
        ) from exc
    if (
        not isinstance(state, dict)
        or type(state.get("pid")) is not int
        or state["pid"] <= 0
        or not isinstance(state.get("process_identity"), str)
        or not isinstance(state.get("host"), str)
        or type(state.get("port")) is not int
        or not 0 < state["port"] < 65536
        or not isinstance(state.get("token"), str)
        or len(state["token"]) < 32
        or type(state.get("fake_backend")) is not bool
    ):
        raise RuntimeError(f"Invalid managed state {path}; preserved for inspection")
    return state


def _write_state(home: Path, state: dict[str, Any]) -> None:
    fd, name = tempfile.mkstemp(prefix=".server-", dir=home)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, home / "server.json")
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def _connect_host(host: str) -> str:
    return {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)


def _rpc(state: dict[str, Any], method: str, timeout: float = 1.0) -> dict[str, Any]:
    with socket.create_connection((_connect_host(state["host"]), state["port"]), timeout) as conn:
        conn.settimeout(timeout)
        request = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {"token": state["token"]}}
        conn.sendall((json.dumps(request) + "\n").encode())
        with conn.makefile("rb") as stream:
            raw = stream.readline(65537)
        if len(raw) > 65536 or not raw.endswith(b"\n"):
            raise RuntimeError("Managed worker sent an invalid control response")
        response = json.loads(raw)
        if (
            not isinstance(response, dict)
            or response.get("jsonrpc") != "2.0"
            or type(response.get("id")) is not int
            or response["id"] != 1
            or ("result" in response) == ("error" in response)
        ):
            raise RuntimeError("Managed worker sent an invalid control response")
        if "error" in response:
            raise RuntimeError(f"Managed worker control failed: {response['error']}")
        if not isinstance(response["result"], dict):
            raise RuntimeError("Managed worker sent an invalid control response")
        return response["result"]


def _verify(state: dict[str, Any]) -> None:
    info = _rpc(state, "binja-cli/identity")
    keys = ("pid", "process_identity", "fake_backend", "token")
    if any(info.get(key) != state[key] for key in keys):
        raise RuntimeError("Managed worker identity does not match saved state")
    # Verify the actual protocol independently of the private ownership endpoint.
    init = _rpc(state, "initialize")
    if (
        init.get("protocolVersion") != "2024-11-05"
        or init.get("serverInfo", {}).get("name") != "binary_ninja_headless_mcp"
    ):
        raise RuntimeError("Managed worker did not identify as Binary Ninja MCP")


def _live(home: Path) -> dict[str, Any] | None:
    state = _read_state(home)
    if state is None or _identity(state["pid"]) != state["process_identity"]:
        return None
    try:
        _verify(state)
    except Exception as exc:
        raise RuntimeError(
            f"Managed process is alive but cannot be verified; state preserved: {exc}"
        ) from exc
    return state


def live_state() -> dict[str, Any] | None:
    """Return only a responsive, owned worker; never replace uncertain state."""
    with _locked() as home:
        return _live(home)


def _public(state: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in state.items() if key != "token"}


def _start(home: Path, args: argparse.Namespace) -> dict[str, Any]:
    old = _live(home)
    if old:
        return {"running": True, "started": False, **_public(old)}
    host = args.host or "127.0.0.1"
    port = args.port if args.port is not None else DEFAULT_PORT
    if not 0 < port < 65536:
        raise RuntimeError("Managed port must be between 1 and 65535")
    token = secrets.token_hex(32)
    fake = bool(
        args.fake_backend or os.environ.get("BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND") == "1"
    )
    env = os.environ.copy()
    source_root = str(Path(__file__).resolve().parent.parent)
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        source_root + os.pathsep + existing_pythonpath if existing_pythonpath else source_root
    )
    env["BINJA_CLI_WORKER_TOKEN"] = token
    env["BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND"] = "1" if fake else "0"
    command = [
        sys.executable,
        "-m",
        "binary_ninja_headless_mcp.managed_cli",
        "worker",
        "--host",
        host,
        "--port",
        str(port),
    ]
    if fake:
        command.append("--fake-backend")
    log_path = home / "server.log"
    with log_path.open("ab") as log:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            env=env,
            start_new_session=True,
            close_fds=True,
        )
    identity = _identity(process.pid)
    state = {
        "pid": process.pid,
        "process_identity": identity,
        "host": host,
        "port": port,
        "fake_backend": fake,
        "token": token,
        "log": str(log_path),
    }
    try:
        if identity is None:
            raise RuntimeError("Cannot establish worker process identity (Linux /proc is required)")
        deadline = time.monotonic() + START_TIMEOUT
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(
                    f"Managed worker exited with code {process.returncode}; see {log_path}"
                )
            try:
                _verify(state)
                _write_state(home, state)
                return {"running": True, "started": True, **_public(state)}
            except (OSError, ValueError, RuntimeError) as exc:
                last_error = exc
                time.sleep(0.05)
        raise RuntimeError(f"Managed worker readiness timed out: {last_error}; see {log_path}")
    except BaseException:
        # Popen owns an unreaped child here, so the PID cannot be recycled before wait.
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        raise


def _stop(home: Path) -> dict[str, Any]:
    state = _live(home)
    if state is None:
        with contextlib.suppress(FileNotFoundError):
            (home / "server.json").unlink()
        return {"running": False, "stopped": False}
    try:
        _rpc(state, "binja-cli/stop", timeout=STOP_TIMEOUT)
    except (OSError, ValueError, RuntimeError) as exc:
        raise RuntimeError(f"Managed shutdown failed; state preserved for retry: {exc}") from exc
    deadline = time.monotonic() + STOP_TIMEOUT
    while _identity(state["pid"]) == state["process_identity"]:
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Worker is still draining native operations; state preserved. "
                "Retry server stop/status."
            )
        time.sleep(0.05)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(state["pid"], os.WNOHANG)
    (home / "server.json").unlink()
    return {"running": False, "stopped": True}


def command(args: argparse.Namespace) -> int:
    """Execute start/status/stop/restart; print one JSON result on success."""
    with _locked() as home:
        action = args.action
        if action == "status":
            state = _live(home)
            result = {"running": bool(state), **(_public(state) if state else {})}
        elif action == "start":
            result = _start(home, args)
        elif action == "stop":
            result = _stop(home)
        elif action == "restart":
            _stop(home)
            result = _start(home, args)
        else:
            raise RuntimeError(f"Unknown managed server action: {action}")
    print(json.dumps(result, sort_keys=True))
    return 0


def _worker(args: argparse.Namespace) -> int:
    from .backend import BinjaBackend
    from .cli import load_binja_module
    from .server import JsonRpcError, SimpleMcpServer

    token = os.environ.pop("BINJA_CLI_WORKER_TOKEN", "")
    if not token:
        raise RuntimeError("Private worker requires a launch token")
    backend = BinjaBackend(load_binja_module(args.fake_backend))
    stopping = threading.Event()
    cleaned = threading.Event()
    cleanup_lock = threading.Lock()

    def cleanup() -> None:
        # A failed drain leaves the listener and saved ownership available for retry.
        with cleanup_lock:
            if not cleaned.is_set():
                backend.shutdown()
                cleaned.set()

    class ManagedServer(SimpleMcpServer):
        def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
            if method in ("binja-cli/identity", "binja-cli/stop"):
                supplied = params.get("token", "")
                if not isinstance(supplied, str) or not hmac.compare_digest(token, supplied):
                    raise JsonRpcError(-32602, "Managed worker token mismatch")
                if method == "binja-cli/identity":
                    return {
                        "pid": os.getpid(),
                        "process_identity": _identity(os.getpid()),
                        "fake_backend": args.fake_backend,
                        "token": token,
                    }
                cleanup()
                return {"ok": True}
            if method == "shutdown":
                # Acknowledge only completed cleanup, matching the MCP server contract.
                cleanup()
                return {"ok": True}
            return super()._dispatch(method, params)

    server = ManagedServer(backend)

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            try:
                while not stopping.is_set():
                    raw = self.rfile.readline()
                    if not raw:
                        return
                    response = server.handle_json_line(raw.decode("utf-8"))
                    if response is not None:
                        self.wfile.write(response.encode() + b"\n")
                        self.wfile.flush()
                        if "result" in json.loads(response):
                            request = json.loads(raw)
                            if isinstance(request, dict) and request.get("method") in (
                                "binja-cli/stop",
                                "shutdown",
                            ):
                                stopping.set()
            except (OSError, UnicodeError):
                return

    class TcpServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        address_family = socket.AF_INET6 if ":" in args.host else socket.AF_INET

    def request_stop(_signum: int, _frame: Any) -> None:
        stopping.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        with TcpServer((args.host, args.port), Handler) as tcp:
            tcp.timeout = 0.1
            while not stopping.is_set():
                tcp.handle_request()
    finally:
        cleanup()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Private managed Binja CLI worker")
    parser.add_argument("action", choices=["worker"])
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--fake-backend", action="store_true")
    return _worker(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
