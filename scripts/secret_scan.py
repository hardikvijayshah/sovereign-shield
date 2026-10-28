"""Scan the source tree for committed credentials (plan.md section 9.3).

High-signal patterns only (AWS keys, private keys, common service tokens), so
a finding is worth stopping a release for. Generated and third-party
directories are skipped. Exit status is 1 when anything is found.

Usage:
    python scripts/secret_scan.py [root]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PATTERNS = {
    "AWS access key ID": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    "AWS secret access key": re.compile(
        r"(?i)aws_?secret_?access_?key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}\b"
    ),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Generic bearer credential": re.compile(
        r"(?i)\b(?:api[_-]?key|client[_-]?secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{24,}['\"]"
    ),
}
SKIP_DIRECTORIES = {
    ".git", "node_modules", "dist", "release", "cdk.out", ".tmp", "__pycache__", "lib", "visualizations",
    ".venv", "venv", ".pytest_cache",
}
SKIP_SUFFIXES = {".zip", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pptx", ".pdf", ".woff", ".woff2", ".pyc"}
# Documented, non-secret example values (AWS documentation's canonical example key).
ALLOWED_VALUES = {"AKIAIOSFODNN7EXAMPLE"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def scan(root: Path) -> list[tuple[Path, int, str]]:
    findings: list[tuple[Path, int, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        parts = path.relative_to(root).parts
        if any(part in SKIP_DIRECTORIES or part.startswith("pytest-cache-files-") for part in parts):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            for label, pattern in PATTERNS.items():
                match = pattern.search(line)
                if match and match.group(0) not in ALLOWED_VALUES:
                    findings.append((path.relative_to(root), line_number, label))
    return findings


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent)
    findings = scan(root)
    for path, line_number, label in findings:
        # The matched value itself is never printed.
        print(f"{path}:{line_number}: possible {label}")
    print(f"secret scan: {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
