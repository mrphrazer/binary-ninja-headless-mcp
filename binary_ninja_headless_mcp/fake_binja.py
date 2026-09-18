"""Small fake Binary Ninja module for tests and local smoke runs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any


@dataclass
class FakeSymbol:
    full_name: str


@dataclass
class FakeFunction:
    start: int
    name: str

    @property
    def llil(self):
        return SimpleNamespace(instructions=[])

    @property
    def symbol(self) -> FakeSymbol:
        return FakeSymbol(full_name=self.name)


@dataclass
class FakeStringRef:
    start: int
    length: int
    value: str
    type: str = "AsciiString"


class FakeFile:
    def __init__(self, filename: str):
        self.filename = filename
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeBinaryView:
    def __init__(self, filename: str):
        self.file = FakeFile(filename)
        self.arch = type("Arch", (), {"name": "x86_64"})()
        self.view_type = "ELF"
        self.start = 0x1000
        self.end = 0x2000
        self.entry_point = 0x1010
        self.functions = [
            FakeFunction(start=0x1010, name="entry"),
            FakeFunction(start=0x1050, name="main"),
        ]
        self.strings = [
            FakeStringRef(start=0x1800, length=5, value="hello"),
            FakeStringRef(start=0x1810, length=5, value="world"),
        ]
        self.analysis_state = "IdleState"
        self.analysis_is_aborted = False
        self.workflow = SimpleNamespace(machine=SimpleNamespace(enable=self._enable_analysis))

    def _enable_analysis(self) -> None:
        self.analysis_is_aborted = False

    def update_analysis_and_wait(self) -> None:
        self.analysis_is_aborted = False

    def update_analysis(self) -> None:
        self.update_analysis_and_wait()

    def abort_analysis(self) -> None:
        self.analysis_is_aborted = True

    def search(self, pattern: str, raw: bool = False, limit: int = 50) -> list[tuple[int, bytes]]:  # noqa: ARG002
        if pattern == "hello":
            return [(0x1800, b"hello")][:limit]
        if pattern == "world":
            return [(0x1810, b"world")][:limit]
        return []

    def create_database(self, path: str) -> bool:
        Path(path).write_bytes(b"fake-database")
        return True

    def read(self, address: int, length: int) -> bytes:
        if not self.start <= address < self.end:
            return b""
        return bytes(min(length, self.end - address))

    def get_function_at(self, address: int) -> FakeFunction | None:
        return next((f for f in self.functions if f.start == address), None)

    def get_functions_containing(self, address: int) -> list[FakeFunction]:
        return [f for f in self.functions if f.start <= address < f.start + 0x10]

    def save(self, dest: str) -> bool:
        _ = dest
        return True


class FakeBinaryNinjaModule:
    __version__ = "fake-1.0"

    @staticmethod
    def core_version() -> str:
        return "fake-1.0"

    @staticmethod
    def get_install_directory() -> str:
        return "/fake/binja"

    @staticmethod
    def load(
        path: str,
        update_analysis: bool = True,
        options: dict[str, Any] | None = None,
    ) -> FakeBinaryView:
        _ = (update_analysis, options)
        return FakeBinaryView(filename=path)


def make_fake_module() -> FakeBinaryNinjaModule:
    """Factory used by tests and the CLI `--fake-backend` mode."""

    return FakeBinaryNinjaModule()
