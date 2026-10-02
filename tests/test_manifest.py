import json

import pytest
from conftest import manifest, tar_archive

from source_release_review import Limits, review_bytes

ARCHIVE = tar_archive([("sample-1.0/ok.py", "regular", b"abc")])


@pytest.mark.parametrize(
    "data",
    [
        b"",
        None,
        b"{",
        b"\xff",
        b"[]",
        b"{}",
        b'{"schema_version":NaN}',
        b'{"root":"a","root":"b"}',
        b"\xef\xbb\xbf{}",
    ],
)
def test_unreadable_or_duplicate_json_is_open(data):
    assert review_bytes(data, ARCHIVE).status == "OPEN"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("schema_version", 1),
        ("root", "root/sub"),
        ("root", ".."),
        ("root", "CON"),
        ("root", "PRIVATE\0ROOT"),
        ("root", 1),
        ("files", []),
        ("files", ["../a"]),
        ("files", ["/a"]),
        ("files", ["a\\b"]),
        ("files", ["ok.py", "ok.py"]),
        ("files", ["Ａ/a", "A/b"]),
        ("files", ["a", "a/b"]),
        ("files", ["e\u0301.txt"]),
        ("files", ["ok.py", 1]),
        ("allowed_generated", ["ok.py"]),
        ("allowed_generated", ["*.egg-info/*"]),
        ("files", "ok.py"),
    ],
)
def test_manifest_policy_validation_never_normalizes_or_guesses(key, value):
    item = json.loads(manifest())
    item[key] = value
    report = review_bytes(json.dumps(item).encode(), ARCHIVE)
    assert report.status == "OPEN" and not report.findings
    assert "PRIVATE" not in json.dumps(report.to_dict())


def test_manifest_extra_keys_and_path_budget():
    item = json.loads(manifest())
    item["unknown"] = "PRIVATE"
    assert review_bytes(json.dumps(item).encode(), ARCHIVE).status == "OPEN"
    assert (
        review_bytes(
            manifest(files=["ok.py", "other.py"]), ARCHIVE, limits=Limits(max_manifest_paths=1)
        ).status
        == "OPEN"
    )


@pytest.mark.parametrize(
    "limit",
    [
        None,
        Limits(max_archive_bytes=True),
        Limits(max_archive_bytes=16777217),
        Limits(max_report_bytes=100),
        Limits(max_members=0),
        Limits(max_path_components=33),
    ],
)
def test_limits_cannot_raise_caps_or_use_bool(limit):
    assert review_bytes(manifest(), ARCHIVE, limits=limit).status == "OPEN"


@pytest.mark.parametrize(
    "limit",
    [
        Limits(max_manifest_bytes=1),
        Limits(max_archive_bytes=1),
        Limits(max_expanded_bytes=512),
        Limits(max_member_bytes=2),
        Limits(max_name_bytes=8),
        Limits(max_path_components=1),
    ],
)
def test_individual_low_input_budgets_open(limit):
    assert review_bytes(manifest(), ARCHIVE, limits=limit).status == "OPEN"


def test_report_and_finding_budgets_remain_partial_with_violation_ledger():
    rows = [("sample-1.0/ok.py", "regular", b"abc")]
    rows += [(f"sample-1.0/{'a' * 50}{index}.txt", "regular", b"x") for index in range(30)]
    data = tar_archive(rows)
    report = review_bytes(manifest(), data, limits=Limits(max_report_bytes=2048))
    limited = review_bytes(manifest(), data, limits=Limits(max_findings=2))
    assert report.status == limited.status == "OPEN"
    assert report.truncated and limited.truncated
    assert report.extra_files == 30 and report.violations_seen == 30
    assert len(json.dumps(report.to_dict(), ensure_ascii=True).encode()) <= 2048
    assert limited.violations_seen >= 2
