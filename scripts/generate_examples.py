"""Create deterministic synthetic text-only source archives; never run their source."""

import gzip
import io
import json
import struct
import tarfile
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "examples"
manifest = {
    "schema_version": "1",
    "root": "sample-1.0",
    "files": ["README.txt", "setup.py"],
    "allowed_generated": ["PKG-INFO"],
}
(root / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
rows = [
    ("README.txt", b"Synthetic source release example.\n"),
    ("setup.py", b"raise RuntimeError('archived source must never execute')\n"),
    ("PKG-INFO", b"Metadata-Version: 2.4\nName: synthetic-example\nVersion: 1.0\n"),
]
stream = io.BytesIO()
with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
    directory = tarfile.TarInfo("sample-1.0/")
    directory.type = tarfile.DIRTYPE
    archive.addfile(directory)
    for name, content in rows:
        member = tarfile.TarInfo("sample-1.0/" + name)
        member.size = len(content)
        member.mtime = 0
        archive.addfile(member, io.BytesIO(content))
(root / "sample-source.tar.gz").write_bytes(gzip.compress(stream.getvalue(), mtime=0))
for filename, extra in (("sample-source.zip", False), ("sample-extra.zip", True)):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in rows + (
            [("unexpected.py", b"# extra source text\n")] if extra else []
        ):
            info = zipfile.ZipInfo("sample-1.0/" + name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
    (root / filename).write_bytes(stream.getvalue())
data = bytearray((root / "sample-source.zip").read_bytes())
name_length, extra_length = struct.unpack_from("<HH", data, 26)
data[30 + name_length + extra_length] ^= 1
(root / "sample-corrupt.zip").write_bytes(data)
