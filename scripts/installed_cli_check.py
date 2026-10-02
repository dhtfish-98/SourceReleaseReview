"""Run real console/module CLI from an independent fresh installed wheel."""

import json
import os
import subprocess
import sys
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


root = Path(__file__).resolve().parents[1]
console = Path(sys.executable).parent / "source-release-review"
trusted = root / "examples/release-manifest.json"
cases = [
    ("sample-source.tar.gz", "PASS", 0),
    ("sample-source.zip", "PASS", 0),
    ("sample-extra.zip", "FAIL", 1),
    ("sample-corrupt.zip", "OPEN", 2),
    ("PRIVATE_MISSING.zip", "OPEN", 2),
]
environment = dict(os.environ)
environment.pop("PYTHONPATH", None)
for filename, status, code in cases:
    output = subprocess.run(
        [str(console), str(trusted), str(root / "examples" / filename)],
        cwd=Path(sys.prefix),
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    require(
        output.returncode == code and json.loads(output.stdout)["status"] == status,
        "installed console result",
    )
    require(
        not output.stderr
        and "PRIVATE_MISSING" not in output.stdout
        and str(root) not in output.stdout,
        "installed console disclosure",
    )
output = subprocess.run(
    [
        sys.executable,
        "-m",
        "source_release_review",
        str(trusted),
        str(root / "examples/sample-source.tar.gz"),
    ],
    cwd=Path(sys.prefix),
    env=environment,
    capture_output=True,
    text=True,
    timeout=10,
    check=False,
)
require(
    output.returncode == 0 and json.loads(output.stdout)["status"] == "PASS" and not output.stderr,
    "installed module result",
)
print(json.dumps({"status": "PASS", "installed_cli_cases": len(cases) + 1}, sort_keys=True))
