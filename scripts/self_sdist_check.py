"""Compare the real final sdist against the committed independent source path policy."""

import json
import sys
from pathlib import Path

from source_release_review import review_files

root = Path(__file__).resolve().parents[1]
report = review_files(root / "examples/self-manifest.json", Path(sys.argv[1]))
if report.status != "PASS":
    print(json.dumps(report.to_dict(), sort_keys=True))
    raise SystemExit(1)
print(
    json.dumps(
        {
            "status": "PASS",
            "real_sdist_regular_files": report.regular_files_seen,
            "required_files_missing": report.missing_files,
            "extra_files": report.extra_files,
            "explicit_generated_files": report.generated_files_allowed,
            "manifest_trust_status": report.manifest_trust_status,
            "content_authenticity_status": report.content_authenticity_status,
            "execution_safety_status": report.execution_safety_status,
        },
        sort_keys=True,
    )
)
