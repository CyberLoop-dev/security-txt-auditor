#!/usr/bin/env python3
"""Read-only RFC 9116 security.txt checker."""
from __future__ import annotations
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

KNOWN = {"contact", "expires", "encryption", "acknowledgments", "policy",
         "hiring", "preferred-languages", "canonical"}
REQUIRED = {"contact", "expires"}
SINGLETON = {"expires"}

def parse_document(source: str, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    fields: dict[str, list[str]] = {}
    findings: list[dict] = []
    def add(level: str, line: int, message: str) -> None:
        findings.append({"level": level, "line": line, "message": message})
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            add("error", number, "Expected a field name followed by ':' and a value.")
            continue
        name, value = line.split(":", 1)
        key, value = name.strip().lower(), value.strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", name.strip()):
            add("error", number, "Field name contains invalid characters.")
            continue
        if not value:
            add("error", number, f"{name.strip()} has an empty value.")
            continue
        fields.setdefault(key, []).append(value)
        if key not in KNOWN:
            add("warning", number, f"Unknown field '{name.strip()}'; check the RFC or extension definition.")
    for required in sorted(REQUIRED):
        if required not in fields:
            add("error", 0, f"Required field '{required.title()}' is missing.")
    for key in SINGLETON:
        if len(fields.get(key, [])) > 1:
            add("error", 0, f"Field '{key.title()}' must appear only once.")
    for value in fields.get("contact", []):
        scheme = urlparse(value).scheme.lower()
        if scheme not in {"https", "mailto"}:
            add("error", 0, f"Contact URI must use https or mailto: {value}")
    for value in fields.get("canonical", []):
        if urlparse(value).scheme.lower() != "https":
            add("warning", 0, f"Canonical URI should use https: {value}")
    for value in fields.get("expires", []):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                add("error", 0, "Expires must include a timezone offset.")
            elif parsed.astimezone(timezone.utc) < now:
                add("warning", 0, "The security.txt Expires timestamp is in the past.")
        except ValueError:
            add("error", 0, f"Expires is not a valid ISO 8601 date-time: {value}")
    return {"fields": fields, "findings": findings,
            "errors": sum(x["level"] == "error" for x in findings),
            "warnings": sum(x["level"] == "warning" for x in findings)}

def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a local RFC 9116 security.txt file.")
    parser.add_argument("path", nargs="?", default=".well-known/security.txt")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    args = parser.parse_args()
    path = Path(args.path)
    try:
        report = parse_document(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        print(f"error: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    report["file"] = str(path)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"security.txt audit: {path}")
        print(f"{len(report['fields'])} field types | {report['errors']} errors | {report['warnings']} warnings")
        for item in report["findings"]:
            where = f"line {item['line']}: " if item["line"] else ""
            print(f"[{item['level'].upper()}] {where}{item['message']}")
        if not report["findings"]:
            print("No issues found.")
    return 1 if report["errors"] else 0

if __name__ == "__main__":
    raise SystemExit(main())
