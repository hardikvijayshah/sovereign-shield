"""The deployed deterministic runtime must work without the agent SDK installed."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

_PROBE = """
import importlib.abc, json, sys

class _BlockAgentSdk(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "strands" or name.startswith("strands."):
            raise ImportError("agent SDK is not part of the deployed runtime")
        return None

sys.meta_path.insert(0, _BlockAgentSdk())

import sovereign_shield.lambda_handler
import sovereign_shield.workflow_handler
from sovereign_shield.models.contracts import ScanRequest
from sovereign_shield.services import execute_scan

def scanner(region, account_id):
    return json.dumps({"resources": [], "flows": []})

result = execute_scan(
    ScanRequest(scan_regions=["eu-central-1"], services=["s3"], regulations=["gdpr"]),
    account_id="111111111111",
    scanners={"s3": scanner},
)
assert not any(name == "strands" or name.startswith("strands.") for name in sys.modules)
print(result.status.value)
"""


def test_deployed_handlers_import_and_scan_without_strands():
    completed = subprocess.run(
        [sys.executable, "-c", _PROBE],
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "complete"
