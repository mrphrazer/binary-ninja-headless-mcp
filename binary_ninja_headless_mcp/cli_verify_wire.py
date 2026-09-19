"""Transparent JSONL TCP recorder for independent CLI verification evidence.

No backend is imported or substituted. Requests and responses travel unchanged to
the chosen server. Parsed pairs are flushed before delivering each response, so a
completed CLI call can immediately inspect its recorded wire evidence.
"""

from __future__ import annotations

import contextlib
import copy
import json
import socket
import socketserver
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any


def _decode(line: bytes) -> Any:
    try:
        return json.loads(line)
    except (ValueError, UnicodeError):
        return {"_invalid_json": line.decode(errors="replace")}


class _RecorderServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, target: tuple[str, int], output: Any) -> None:
        self.target = target
        self.output = output
        self.lock = threading.Lock()
        self.records: list[dict[str, Any]] = []
        self.connections: set[socket.socket] = set()
        self.workers: set[threading.Thread] = set()
        self.closing = False
        super().__init__(("127.0.0.1", 0), _RecorderHandler)
        self.endpoint = f"127.0.0.1:{self.server_address[1]}"

    @property
    def record_count(self) -> int:
        """Get a cheap cursor for inspecting only a subsequent invocation's traffic."""
        with self.lock:
            return len(self.records)

    def snapshot(self, start: int = 0) -> list[dict[str, Any]]:
        """Return isolated copies of recorded pairs, optionally beginning at a cursor."""
        with self.lock:
            return copy.deepcopy(self.records[start:])

    def record(self, request: Any, response: Any, *, error: str | None = None) -> None:
        item = {"request": request, "response": response}
        if error is not None:
            item["error"] = error
        with self.lock:
            self.output.write(json.dumps(item, ensure_ascii=True) + "\n")
            self.output.flush()
            self.records.append(item)

    def add_connection(self, connection: socket.socket) -> None:
        with self.lock:
            if self.closing:
                connection.close()
                raise ConnectionError("wire recorder is shutting down")
            self.connections.add(connection)

    def stop_connections(self) -> None:
        with self.lock:
            self.closing = True
            connections = list(self.connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()

    def join_workers(self) -> None:
        deadline = time.monotonic() + 5
        with self.lock:
            workers = list(self.workers)
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError("wire recorder handlers did not terminate")


class _RecorderHandler(socketserver.StreamRequestHandler):
    server: _RecorderServer

    def handle(self) -> None:
        current = threading.current_thread()
        upstream = None
        request: Any = None
        with self.server.lock:
            self.server.workers.add(current)
        try:
            self.server.add_connection(self.request)
            self.request.settimeout(180)
            upstream = socket.create_connection(self.server.target, timeout=180)
            self.server.add_connection(upstream)
            with upstream.makefile("rb") as reader:
                while line := self.rfile.readline():
                    request = _decode(line)
                    upstream.sendall(line)
                    notification = (
                        isinstance(request, dict)
                        and isinstance(request.get("method"), str)
                        and "id" not in request
                    )
                    if notification:
                        self.server.record(request, None)
                        request = None
                        continue
                    response = reader.readline()
                    if not response:
                        raise ConnectionError("target closed without a response")
                    self.server.record(request, _decode(response))
                    request = None
                    self.wfile.write(response)
                    self.wfile.flush()
        except (OSError, ValueError) as exc:
            if not self.server.closing:
                self.server.record(request, None, error=f"{type(exc).__name__}: {exc}")
        finally:
            if upstream is not None:
                upstream.close()
            with self.server.lock:
                self.server.connections.discard(self.request)
                if upstream is not None:
                    self.server.connections.discard(upstream)
                self.server.workers.discard(current)


@contextlib.contextmanager
def record_proxy(target_host: str, target_port: int, output_path: str | Path) -> Iterator[Any]:
    """Yield a loopback proxy with ``endpoint`` and ``snapshot()``.

    Evidence is appended as JSONL, one request/response pair per record. A
    notification has ``response: null``. Malformed JSON is forwarded unchanged and
    represented as ``{"_invalid_json": text}`` in the evidence. Connection failures
    retain the pending request and an ``error`` field. No license configuration is
    read; this records only the caller's wire traffic.
    """
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        server = _RecorderServer((target_host, target_port), output)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            server.stop_connections()
            server.server_close()
            thread.join(timeout=5)
            server.join_workers()
