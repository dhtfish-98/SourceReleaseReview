import json
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from conftest import manifest, tar_archive

from source_release_review import Limits, review_files
from source_release_review.cli import main


@pytest.fixture
def inputs(tmp_path):
    trusted = tmp_path / "PRIVATE_MANIFEST.json"
    archive = tmp_path / "PRIVATE_ARCHIVE.tar"
    trusted.write_bytes(manifest())
    archive.write_bytes(tar_archive([("sample-1.0/ok.py", "regular", b"text")]))
    return trusted, archive


def test_local_real_paths_read_only_and_path_privacy(inputs):
    trusted, archive = inputs
    before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in inputs]
    report = review_files(trusted, archive)
    assert report.status == "PASS"
    assert [(path.read_bytes(), path.stat().st_mtime_ns) for path in inputs] == before
    assert "PRIVATE_" not in json.dumps(report.to_dict())
    assert str(trusted.parent) not in json.dumps(report.to_dict())


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "directory",
        "leaf_link",
        "parent_link",
        "traversal",
        "nul",
        "empty",
        "fifo",
        "device",
    ],
)
def test_input_rejection_nonblocking_and_sanitized(inputs, tmp_path, kind):
    trusted, archive = inputs
    if kind == "missing":
        path = tmp_path / "PRIVATE_MISSING"
    elif kind == "directory":
        path = tmp_path
    elif kind == "leaf_link":
        path = tmp_path / "link"
        path.symlink_to(archive)
    elif kind == "parent_link":
        alias = tmp_path / "alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        path = alias / archive.name
    elif kind == "traversal":
        path = str(tmp_path / "x/../PRIVATE")
    elif kind == "nul":
        path = "PRIVATE\0PATH"
    elif kind == "empty":
        path = ""
    elif kind == "fifo":
        path = tmp_path / "fifo"
        os.mkfifo(path)
    else:
        path = "/dev/null"
    start = time.monotonic()
    report = review_files(trusted, path)
    assert report.status == "OPEN"
    assert time.monotonic() - start < 1
    assert "PRIVATE" not in json.dumps(report.to_dict())
    assert review_files(path, archive).status == "OPEN"


@pytest.mark.parametrize("field", ["st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"])
def test_detected_file_identity_or_metadata_change_open(inputs, monkeypatch, field):
    original = os.fstat
    seen = 0

    def changed(descriptor):
        nonlocal seen
        seen += 1
        item = original(descriptor)
        values = {
            name: getattr(item, name)
            for name in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        }
        if seen == 2:
            values[field] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(os, "fstat", changed)
    assert review_files(*inputs).status == "OPEN"


def test_length_capabilities_and_low_file_budgets(inputs, monkeypatch):
    assert review_files(*inputs, limits=Limits(max_archive_bytes=1)).status == "OPEN"
    assert review_files(*inputs, limits=Limits(max_manifest_bytes=1)).status == "OPEN"
    with monkeypatch.context() as context:
        context.setattr(os, "read", lambda *args: b"")
        assert review_files(*inputs).status == "OPEN"
    with monkeypatch.context() as context:
        context.setattr(os, "supports_dir_fd", set())
        assert review_files(*inputs).status == "OPEN"
    monkeypatch.delattr(os, "O_NOFOLLOW")
    assert review_files(*inputs).status == "OPEN"


@pytest.mark.parametrize(
    ("files", "exit_code", "status"), [(["ok.py"], 0, "PASS"), (["ok.py", "missing.py"], 1, "FAIL")]
)
def test_cli_json_codes_and_privacy(inputs, files, exit_code, status, capsys):
    trusted, archive = inputs
    trusted.write_bytes(manifest(files=files))
    assert main([str(trusted), str(archive)]) == exit_code
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == status
    assert "PRIVATE_" not in output.out and not output.err


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["PRIVATE"],
        ["PRIVATE", "PRIVATE", "--execute"],
        ["PRIVATE", "PRIVATE", "--format", "exe"],
    ],
)
def test_cli_errors_are_json_open(arguments, capsys):
    assert main(arguments) == 2
    output = capsys.readouterr()
    assert json.loads(output.out)["status"] == "OPEN"
    assert "PRIVATE" not in output.out + output.err


def test_module_cli_existing_archive_and_no_extract(inputs, tmp_path):
    trusted, archive = inputs
    result = subprocess.run(
        [sys.executable, "-m", "source_release_review", str(trusted), str(archive)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "PASS"
    assert not result.stderr
    assert not (tmp_path / "sample-1.0").exists()
