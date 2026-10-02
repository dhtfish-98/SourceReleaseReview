import hashlib
import json
from pathlib import Path


def test_complete_original_mit_license_and_frozen_audit_identity():
    root = Path(__file__).resolve().parents[1]
    content = (root / "THIRD_PARTY_LICENSES/check-manifest-MIT.txt").read_bytes()
    assert (
        hashlib.sha256(content).hexdigest()
        == "bf6af43e995943b187d05a56e5f93b17d786b268291286ca9b52349b86b9d8a9"
    )
    audit = json.loads((root / "SOURCE_AUDIT.json").read_text())
    assert audit["commit"] == "5cdb776d4ad547518002ab33528b880b51378b48"
    license_record = next(item for item in audit["files"] if item["path"] == "LICENSE.rst")
    assert license_record["sha256"] == hashlib.sha256(content).hexdigest()
    assert b"Copyright (c) 2013 Marius Gedminas and contributors" in content
    assert b"THE SOFTWARE IS PROVIDED" in content
