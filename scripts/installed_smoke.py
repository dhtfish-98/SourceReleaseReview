"""Audit a fresh installed runtime; forbid execution/import/network/process/write events."""

import contextlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path

import source_release_review
from source_release_review import review_bytes
from source_release_review.cli import main


def require(condition, message):
    if not condition:
        raise ValueError(message)


root = Path(__file__).resolve().parents[1]
wheel = Path(sys.argv[1]).resolve()
installed = Path(source_release_review.__file__).resolve().parent
require(Path(sys.prefix).resolve() in installed.parents, "not independently installed runtime")
count = 0
with zipfile.ZipFile(wheel) as archive:
    for name in archive.namelist():
        if name.startswith("source_release_review/"):
            relative = name.removeprefix("source_release_review/")
            require((installed / relative).read_bytes() == archive.read(name), "installed mismatch")
            count += 1
manifest = (root / "examples/release-manifest.json").read_bytes()
cases = [
    (name, (root / "examples" / name).read_bytes(), status)
    for name, status in [
        ("sample-source.tar.gz", "PASS"),
        ("sample-source.zip", "PASS"),
        ("sample-extra.zip", "FAIL"),
        ("sample-corrupt.zip", "OPEN"),
    ]
]
# Preload standard-library codecs and argparse helpers before denying lazy imports.
for _, data, _ in cases:
    review_bytes(manifest, data)
with contextlib.redirect_stdout(io.StringIO()):
    main([])
seen = {"exec": 0, "import": 0, "socket": 0, "process": 0, "write_open": 0}


def audit(event, arguments):
    kind = None
    if event == "exec":
        kind = "exec"
    elif event == "import":
        kind = "import"
    elif event.startswith("socket."):
        kind = "socket"
    elif event.startswith(("subprocess.", "os.exec", "os.spawn")) or event == "os.system":
        kind = "process"
    elif event == "open" and arguments[2] & (
        os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
    ):
        kind = "write_open"
    if kind:
        seen[kind] += 1
        raise RuntimeError("prohibited runtime event")


sys.addaudithook(audit)
for _, data, expected in cases:
    require(review_bytes(manifest, data).status == expected, "installed audit result")
with contextlib.redirect_stdout(io.StringIO()) as output:
    require(
        main(
            [
                str(root / "examples/release-manifest.json"),
                str(root / "examples/sample-source.tar.gz"),
            ]
        )
        == 0,
        "installed file CLI",
    )
require(json.loads(output.getvalue())["status"] == "PASS", "installed CLI JSON")
require(not any(seen.values()), "prohibited event occurred")
print(
    json.dumps(
        {
            "status": "PASS",
            "audit_cases": len(cases) + 1,
            "installed_runtime_files_verified": count,
            "prohibited_events": seen,
        },
        sort_keys=True,
    )
)
