"""Generate the CLI tool reference from the shared catalog without a BN runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .catalog import TOOL_DEFAULTS, TOOL_DEFINITIONS

START = "<!-- BEGIN GENERATED TOOL REFERENCE -->"
END = "<!-- END GENERATED TOOL REFERENCE -->"


def render_reference() -> str:
    """Return deterministic Markdown containing every schema and effective default."""
    groups = sorted({tool["name"].split(".", 1)[0] for tool in TOOL_DEFINITIONS})
    lines = [
        START,
        f"The catalog contains **{len(TOOL_DEFINITIONS)} tools across {len(groups)} groups**.",
        "",
        "Every entry is callable with `binja_cli call TOOL`. The full JSON schema below",
        "preserves unions, enums, required fields, and additional schema constraints.",
        "Effective defaults describe server behavior when a property is omitted; the CLI",
        "does not inject these values. An omitted property absent from the defaults map",
        "has no cataloged default. JSON `null` in a defaults map describes omission behavior",
        "and does not imply that explicit null is accepted by the property's schema.",
        "",
        "Groups: " + " · ".join(f"[{group}](#{group}-tools)" for group in groups),
    ]
    for group in groups:
        lines.extend(["", f"### {group} tools", ""])
        for tool in sorted(TOOL_DEFINITIONS, key=lambda item: item["name"]):
            if tool["name"].split(".", 1)[0] != group:
                continue
            lines.extend(
                [
                    f"#### `{tool['name']}`",
                    "",
                    tool["description"],
                    "",
                    "```json",
                    json.dumps(tool["inputSchema"], indent=2, sort_keys=True),
                    "```",
                    "",
                    "Effective defaults: `"
                    + json.dumps(TOOL_DEFAULTS.get(tool["name"], {}), sort_keys=True)
                    + "`.",
                    "",
                ]
            )
    lines.append(END)
    return "\n".join(lines)


def update_document(document: str) -> str:
    """Replace exactly one generated region, preserving the handwritten guide."""
    if document.count(START) != 1 or document.count(END) != 1:
        raise ValueError("document must contain exactly one generated reference region")
    before, rest = document.split(START, 1)
    _, after = rest.split(END, 1)
    return before + render_reference() + after


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", type=Path, default=Path("BINJA_CLI.md"))
    parser.add_argument("--check", action="store_true", help="Fail if the reference is stale.")
    args = parser.parse_args(argv)
    try:
        current = args.path.read_text(encoding="utf-8")
        updated = update_document(current)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"error: {exc}\n")
    if args.check:
        if current != updated:
            parser.exit(1, f"Stale CLI reference: {args.path}; regenerate with cli_docs.\n")
    else:
        args.path.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
