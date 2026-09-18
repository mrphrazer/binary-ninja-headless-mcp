"""Regressions for unbounded allocations found during native catalog sweeps."""

from __future__ import annotations

import weakref

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule


@pytest.mark.parametrize("offset,limit", [(0, 3), (300, 5), (1000, 20)])
def test_linear_disassembly_streams_exact_total_without_retaining_lines(offset, limit):
    backend = BinjaBackend(FakeBinaryNinjaModule())
    sid = backend.open_session("fixture")["session_id"]
    live = weakref.WeakSet()

    class NativeLine:
        def __init__(self, number):
            self.contents = f"line {number}"
            live.add(self)

    def lines():
        for number in range(1000):
            assert len(live) <= 2, "paged disassembly retained the entire native listing"
            yield NativeLine(number)

    backend._get_view(sid).linear_disassembly = lines()
    try:
        result = backend.disasm_linear(sid, offset=offset, limit=limit)
        assert result["total"] == 1000
        assert [item["text"] for item in result["items"]] == [
            f"line {i}" for i in range(offset, min(offset + limit, 1000))
        ]
        assert not live
    finally:
        backend.shutdown()


@pytest.mark.parametrize("legacy", [False, True])
def test_search_limit_bounds_native_iterator_consumption(legacy):
    backend = BinjaBackend(FakeBinaryNinjaModule())
    sid = backend.open_session("fixture")["session_id"]

    def matches():
        for index in range(1000):
            assert index < 5, "search consumed matches after the requested limit"
            yield (0x1000 + index, b"match")

    def modern(_query, **_kwargs):
        return matches()

    def old(_query):
        return matches()

    backend._get_view(sid).search = old if legacy else modern
    try:
        result = backend.search_text(sid, "match", limit=5)
        assert result["count"] == 5
        assert len(result["items"]) == 5
    finally:
        backend.shutdown()
