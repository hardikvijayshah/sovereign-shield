"""The release gate's secret scanner must catch credentials and skip generated directories."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "secret_scan", Path(__file__).resolve().parent.parent / "scripts" / "secret_scan.py"
)
secret_scan = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(secret_scan)

# Assembled at runtime so this file never contains a credential-shaped literal.
FAKE_ACCESS_KEY = "AKIA" + "Q" * 16
FAKE_SECRET = "aws_secret_access_key = " + "a" * 40
FAKE_PRIVATE_KEY = "-----BEGIN " + "RSA PRIVATE KEY-----"
FAKE_GITHUB = "ghp_" + "b" * 36


def test_scanner_finds_each_credential_type(tmp_path):
    (tmp_path / "config.py").write_text(
        "\n".join([f"KEY = '{FAKE_ACCESS_KEY}'", FAKE_SECRET, FAKE_PRIVATE_KEY, f"TOKEN = '{FAKE_GITHUB}'"]),
        encoding="utf-8",
    )

    labels = [label for _, _, label in secret_scan.scan(tmp_path)]

    assert labels == ["AWS access key ID", "AWS secret access key", "Private key", "GitHub token"]


def test_scanner_skips_generated_directories_and_documented_examples(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "pkg.js").write_text(f"'{FAKE_ACCESS_KEY}'", encoding="utf-8")
    (tmp_path / "docs.md").write_text("Example: AKIAIOSFODNN7EXAMPLE", encoding="utf-8")

    assert secret_scan.scan(tmp_path) == []


def test_scanner_reports_locations_without_the_secret(tmp_path, capsys, monkeypatch):
    (tmp_path / "leak.txt").write_text(FAKE_ACCESS_KEY, encoding="utf-8")
    monkeypatch.setattr("sys.argv", ["secret_scan.py", str(tmp_path)])

    assert secret_scan.main() == 1
    output = capsys.readouterr().out
    assert "leak.txt:1: possible AWS access key ID" in output
    assert FAKE_ACCESS_KEY not in output
