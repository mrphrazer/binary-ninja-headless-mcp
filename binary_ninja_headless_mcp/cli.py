"""CLI runner for the simple Binary Ninja Headless MCP server."""

from __future__ import annotations

import argparse
import os
import sys
from types import ModuleType

from .backend import BinjaBackend
from .fake_binja import make_fake_module
from .server import SimpleMcpServer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Binary Ninja Headless MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "tcp"],
        default="stdio",
        help="Transport mode. stdio is default for MCP clients.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host when using TCP transport")
    parser.add_argument("--port", type=int, default=8765, help="Port when using TCP transport")
    parser.add_argument(
        "--fake-backend",
        action="store_true",
        help="Use a local fake Binja backend (for tests/dev without Binary Ninja).",
    )
    return parser


def load_binja_module(use_fake: bool) -> ModuleType:
    if use_fake or os.environ.get("BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND") == "1":
        return make_fake_module()  # type: ignore[return-value]

    try:
        import binaryninja as bn  # pylint: disable=import-outside-toplevel
    except ImportError as exc:  # pragma: no cover - depends on system environment
        raise RuntimeError(
            "binaryninja module is not available. Install/configure Binary Ninja Python API, "
            "or run with --fake-backend for test mode."
        ) from exc

    return bn


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    bn_module = load_binja_module(args.fake_backend)
    backend = BinjaBackend(bn_module)
    server = SimpleMcpServer(backend)

    try:
        if args.transport == "tcp":
            print(
                f"binary_ninja_headless_mcp listening on tcp://{args.host}:{args.port}",
                file=sys.stderr,
                flush=True,
            )
            server.serve_tcp(args.host, args.port)
        else:
            server.serve_stdio()
        return 0
    finally:
        backend.shutdown()
