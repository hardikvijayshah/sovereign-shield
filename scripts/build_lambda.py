"""Build the deployed deterministic Lambda package.

Creates a reproducible zip containing:
  - the sovereign_shield package from src/, without the agent experience
    (`agents/`, `cli.py`), which the deployed API and workflow never import;
  - the pinned dependency closure in scripts/lambda-requirements.txt, built
    for the Lambda runtime used by the stack (Python 3.12, ARM64).

Usage:
    python scripts/build_lambda.py

Output:
    dist/lambda_package.zip
    dist/lambda_package.manifest.json  (dependency versions and SHA-256)
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_PACKAGE = PROJECT_ROOT / "src" / "sovereign_shield"
REQUIREMENTS = PROJECT_ROOT / "scripts" / "lambda-requirements.txt"
DIST_DIR = PROJECT_ROOT / "dist"
OUTPUT_ZIP = DIST_DIR / "lambda_package.zip"
MANIFEST = DIST_DIR / "lambda_package.manifest.json"

PYTHON_VERSION = "3.12"
PLATFORM = "manylinux2014_aarch64"
EXCLUDED_SOURCE = {"agents", "cli.py"}
# Fixed timestamp so identical inputs produce an identical zip.
ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
UNZIPPED_LIMIT_MB = 250


def main() -> int:
    print("=== Sovereign Shield Lambda Build ===\n")

    # Stage outside the project tree: sync clients such as OneDrive lock newly
    # written directories, which breaks cleanup of an in-tree staging folder.
    with tempfile.TemporaryDirectory(prefix="sovereign-shield-lambda-") as staging:
        return _build(Path(staging))


def _build(build_dir: Path) -> int:
    print(f"1. Installing pinned dependencies for Python {PYTHON_VERSION} / {PLATFORM}...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "--quiet",
        "--target", str(build_dir),
        "--platform", PLATFORM,
        "--implementation", "cp",
        "--python-version", PYTHON_VERSION,
        "--only-binary=:all:",
        "--no-deps",
        "--no-compile",
        "--requirement", str(REQUIREMENTS),
    ])

    print("2. Copying deterministic runtime source...")
    shutil.copytree(
        SRC_PACKAGE,
        build_dir / "sovereign_shield",
        ignore=lambda directory, names: [
            name for name in names
            if name == "__pycache__" or (Path(directory) == SRC_PACKAGE and name in EXCLUDED_SOURCE)
        ],
    )

    print("3. Removing bytecode caches...")
    for cache in sorted(build_dir.rglob("__pycache__"), reverse=True):
        shutil.rmtree(cache)

    print("4. Creating reproducible zip...")
    DIST_DIR.mkdir(exist_ok=True)
    files = sorted(path for path in build_dir.rglob("*") if path.is_file())
    unzipped_bytes = 0
    with zipfile.ZipFile(OUTPUT_ZIP, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(build_dir).as_posix(), date_time=ZIP_TIMESTAMP)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            data = path.read_bytes()
            unzipped_bytes += len(data)
            archive.writestr(info, data)

    digest = hashlib.sha256(OUTPUT_ZIP.read_bytes()).hexdigest()
    distributions = sorted(
        (dist.metadata["Name"], dist.version)
        for dist in importlib.metadata.distributions(path=[str(build_dir)])
    )
    MANIFEST.write_text(
        json.dumps(
            {
                "artifact": OUTPUT_ZIP.name,
                "sha256": digest,
                "pythonVersion": PYTHON_VERSION,
                "platform": PLATFORM,
                "unzippedBytes": unzipped_bytes,
                "dependencies": [{"name": name, "version": version} for name, version in distributions],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    zipped_mb = OUTPUT_ZIP.stat().st_size / (1024 * 1024)
    unzipped_mb = unzipped_bytes / (1024 * 1024)
    print(f"\nBuild complete: {OUTPUT_ZIP}")
    print(f"  zipped {zipped_mb:.1f} MB, unzipped {unzipped_mb:.1f} MB, sha256 {digest}")
    if unzipped_mb > UNZIPPED_LIMIT_MB:
        print(f"ERROR: unzipped size exceeds the {UNZIPPED_LIMIT_MB} MB Lambda limit.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
