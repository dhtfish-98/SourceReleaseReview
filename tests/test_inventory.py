import json
import warnings

import pytest
from conftest import manifest, tar_archive, zip_archive

from source_release_review import review_bytes

BASE = ("sample-1.0/ok.py", "regular", b"raise RuntimeError('never executed')")


def test_real_archive_match_and_input_unchanged(archive_builder):
    data = archive_builder([("sample-1.0/", "directory", b""), BASE])
    original = data
    report = review_bytes(manifest(), data)
    assert report.status == "PASS"
    assert report.members_seen == 2 and report.regular_files_seen == 1
    assert report.payload_bytes_checked == len(BASE[2])
    assert report.manifest_trust_status == report.content_authenticity_status == "OPEN"
    assert report.execution_safety_status == "OPEN"
    assert original == data
    assert "never executed" not in json.dumps(report.to_dict())


def test_missing_extra_and_exact_generated_policy(archive_builder):
    rows = [
        BASE,
        ("sample-1.0/PKG-INFO", "regular", b"generated"),
        ("sample-1.0/extra.py", "regular", b"extra"),
    ]
    report = review_bytes(
        manifest(files=["ok.py", "missing.py"], generated=["PKG-INFO"]), archive_builder(rows)
    )
    assert report.status == "FAIL"
    assert report.missing_files == report.extra_files == report.generated_files_allowed == 1
    assert {finding.path for finding in report.findings} == {"missing.py", None, "PKG-INFO"}


def test_private_extra_archive_path_is_hash_only(archive_builder):
    report = review_bytes(
        manifest(),
        archive_builder(
            [BASE, ("sample-1.0/PRIVATE_EXTRA_FILENAME.py", "regular", b"PRIVATE_PAYLOAD")]
        ),
    )
    encoded = json.dumps(report.to_dict())
    assert report.status == "FAIL"
    assert "PRIVATE" not in encoded
    extra = next(item for item in report.findings if item.reason == "unexpected_release_file")
    assert extra.path is None and extra.member_index == 2 and len(extra.path_sha256) == 64


def test_no_implicit_generated_exclusions(archive_builder):
    data = archive_builder([BASE, ("sample-1.0/PKG-INFO", "regular", b"text")])
    assert review_bytes(manifest(), data).status == "FAIL"
    allowed = review_bytes(manifest(generated=["PKG-INFO"]), data)
    assert allowed.status == "PASS" and allowed.generated_files_allowed == 1


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "sample-1.0/../escape",
        "sample-1.0//double",
        "sample-1.0/./dot",
        "sample-1.0/a\\b",
        "sample-1.0/a:b",
        "sample-1.0/CON.py",
        "sample-1.0/LPT9",
        "sample-1.0/COM¹.txt",
        "sample-1.0/end.",
        "sample-1.0/end ",
        "sample-1.0/evil\nname",
        "sample-1.0/a\u202eb",
        "sample-1.0/．．/x",
        "sample-1.0/ａ／ｂ",
        "sample-1.0/ａ＼ｂ",
        "sample-1.0/e\u0301.txt",
    ],
)
def test_dangerous_paths_not_normalized_or_printed(path, archive_builder):
    report = review_bytes(manifest(), archive_builder([BASE, (path, "regular", b"x")]))
    assert report.status == "FAIL"
    assert any(item.reason == "dangerous_or_noncanonical_path" for item in report.findings)
    assert path not in json.dumps(report.to_dict(), ensure_ascii=False)


@pytest.mark.parametrize("path", ["other/extra", "loose.py", "sample-1.0"])
def test_wrong_multiple_root_or_loose_member(path, archive_builder):
    report = review_bytes(manifest(), archive_builder([BASE, (path, "regular", b"x")]))
    assert report.status == "FAIL"
    assert any(
        item.reason in {"wrong_archive_root", "root_is_not_directory"} for item in report.findings
    )


def test_duplicate_members_retained_not_set_deduplicated(archive_builder):
    with warnings.catch_warnings(record=True):
        data = archive_builder([BASE, BASE])
    report = review_bytes(manifest(), data)
    assert report.status == "FAIL" and report.members_seen == 2
    assert any(item.reason == "duplicate_member" for item in report.findings)


@pytest.mark.parametrize(
    "pair",
    [
        ("Src/a.py", "src/b.py"),
        ("straße/a.py", "strasse/b.py"),
        ("Ａ/a.py", "A/b.py"),
    ],
)
def test_portable_prefix_unicode_case_collisions(pair, archive_builder):
    rows = [BASE, *(("sample-1.0/" + name, "regular", b"x") for name in pair)]
    report = review_bytes(manifest(), archive_builder(rows))
    assert report.status == "FAIL"
    assert any(item.reason == "portable_unicode_or_case_collision" for item in report.findings)


def test_file_parent_conflict_and_unexpected_empty_directory(archive_builder):
    rows = [
        BASE,
        ("sample-1.0/src", "regular", b"x"),
        ("sample-1.0/src/a.py", "regular", b"x"),
        ("sample-1.0/unknown/", "directory", b""),
    ]
    report = review_bytes(manifest(), archive_builder(rows))
    reasons = {item.reason for item in report.findings}
    assert report.status == "FAIL"
    assert "file_directory_prefix_conflict" in reasons
    assert "unexpected_release_directory" in reasons


@pytest.mark.parametrize("kind", ["symbolic", "fifo"])
def test_links_and_special_members_are_rejected(kind, archive_builder):
    data = archive_builder([BASE, ("sample-1.0/link", kind, b"../outside")])
    report = review_bytes(manifest(), data)
    assert report.status == "FAIL"
    assert any(
        item.reason in {"symbolic_or_hard_link_member", "special_or_conflicting_member_type"}
        for item in report.findings
    )


def test_tar_hard_links_are_not_treated_as_source_files():
    data = tar_archive([BASE, ("sample-1.0/required.py", "hard", b"")])
    report = review_bytes(manifest(files=["ok.py", "required.py"]), data)
    assert report.status == "FAIL" and report.missing_files == 1
    assert any(item.reason == "symbolic_or_hard_link_member" for item in report.findings)


def test_valid_nfc_unicode_names_and_pax_long_names(archive_builder):
    names = ["é.txt", "源码.py", "sub/" + "a" * 160 + ".py"]
    rows = [("sample-1.0/" + name, "regular", b"source") for name in names]
    assert review_bytes(manifest(files=names), archive_builder(rows)).status == "PASS"


@pytest.mark.parametrize("factory", [tar_archive, zip_archive])
def test_empty_or_only_directory_archive_is_open(factory):
    assert review_bytes(manifest(), factory([])).status == "OPEN"
    assert review_bytes(manifest(), factory([("sample-1.0/", "directory", b"")])).status == "OPEN"
