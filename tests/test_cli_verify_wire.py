"""Wire-recorder transport tests; the local echo server is not a native oracle."""

from __future__ import annotations

import contextlib
import json
import socket
import socketserver
import threading
from concurrent.futures import ThreadPoolExecutor

from binary_ninja_headless_mcp.cli_verify_wire import record_proxy


class Echo(socketserver.StreamRequestHandler):
    def handle(self):
        for line in self.rfile:
            self.server.received.append(line)
            try:
                request = json.loads(line)
            except ValueError:
                self.wfile.write(b'{ "jsonrpc": "2.0", "id": null, "error": {} }\n')
                continue
            if "id" not in request:
                continue
            # Deliberate spacing proves the proxy returns original bytes.
            self.wfile.write(b'{ "echo": ' + line.rstrip(b"\r\n") + b" }\n")


@contextlib.contextmanager
def echo_server():
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as server:
        server.daemon_threads = True
        server.received = []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=5)


def connect(proxy):
    host, port = proxy.endpoint.split(":")
    return socket.create_connection((host, int(port)), timeout=5)


def test_preserves_bytes_handshake_notifications_and_multiple_requests(tmp_path):
    evidence = tmp_path / "wire.jsonl"
    with echo_server() as target, record_proxy(*target.server_address, evidence) as proxy:
        with connect(proxy) as client, client.makefile("rb") as reader:
            requests = [
                b'{ "id": 1, "method": "initialize" }\r\n',
                b'{"method":"notifications/initialized"}\n',
                b'{ "id": 2, "method": "tools/call", "params": {"x": 1} }\n',
            ]
            for request in requests:
                client.sendall(request)
                if "id" in json.loads(request):
                    assert reader.readline() == b'{ "echo": ' + request.rstrip(b"\r\n") + b" }\n"
            records = proxy.snapshot()
            assert len(records) == 3
            assert records[1]["response"] is None
            assert records[2]["request"]["params"] == {"x": 1}
            assert proxy.record_count == 3
            assert proxy.snapshot(2) == records[2:]
            assert records == [json.loads(line) for line in evidence.read_text().splitlines()]
            records[0]["request"]["method"] = "changed"
            assert proxy.snapshot()[0]["request"]["method"] == "initialize"
        assert target.received == requests


def test_malformed_input_is_forwarded_to_target(tmp_path):
    with echo_server() as target, record_proxy(*target.server_address, tmp_path / "wire") as proxy:
        with connect(proxy) as client, client.makefile("rb") as reader:
            client.sendall(b"not-json\n")
            assert reader.readline() == b'{ "jsonrpc": "2.0", "id": null, "error": {} }\n'
            assert proxy.snapshot()[0]["request"] == {"_invalid_json": "not-json\n"}
        assert target.received == [b"not-json\n"]


def test_concurrent_connections_record_complete_atomic_pairs(tmp_path):
    evidence = tmp_path / "wire"
    with echo_server() as target, record_proxy(*target.server_address, evidence) as proxy:

        def exchange(number):
            with connect(proxy) as client, client.makefile("rb") as reader:
                request = {"id": number, "method": "echo", "payload": "x" * 10000}
                client.sendall((json.dumps(request) + "\n").encode())
                assert json.loads(reader.readline())["echo"] == request

        with ThreadPoolExecutor(max_workers=4) as workers:
            list(workers.map(exchange, range(12)))
        records = proxy.snapshot()
        assert len(records) == 12
        assert {item["request"]["id"] for item in records} == set(range(12))
        assert records == [json.loads(line) for line in evidence.read_text().splitlines()]


def test_shutdown_closes_idle_connection(tmp_path):
    with echo_server() as target:
        with record_proxy(*target.server_address, tmp_path / "wire") as proxy:
            client = connect(proxy)
            client.sendall(b'{"id":1,"method":"initialize"}\n')
            assert client.recv(4096)
        try:
            assert client.recv(4096) == b""
        finally:
            client.close()
