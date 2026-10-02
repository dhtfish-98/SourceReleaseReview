import gzip
import io
import json
import stat
import struct
import tarfile
import zipfile
import zlib

import pytest


def manifest(files=("ok.py",), generated=(), root="sample-1.0"):
    return json.dumps(
        {
            "schema_version": "1",
            "root": root,
            "files": list(files),
            "allowed_generated": list(generated),
        },
        ensure_ascii=False,
    ).encode()


def tar_archive(rows, compressed=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, kind, content in rows:
            info = tarfile.TarInfo(name)
            info.mtime = 0
            if kind == "directory":
                info.type = tarfile.DIRTYPE
            elif kind == "symbolic":
                info.type = tarfile.SYMTYPE
                info.linkname = "../outside"
            elif kind == "hard":
                info.type = tarfile.LNKTYPE
                info.linkname = "sample-1.0/ok.py"
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
            else:
                info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    data = stream.getvalue()
    return gzip.compress(data, mtime=0) if compressed else data


def zip_archive(rows, compressed=False):
    stream = io.BytesIO()
    with zipfile.ZipFile(
        stream, mode="w", compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
    ) as archive:
        for name, kind, content in rows:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (
                {"symbolic": stat.S_IFLNK, "directory": stat.S_IFDIR, "fifo": stat.S_IFIFO}.get(
                    kind, stat.S_IFREG
                )
                | 0o644
            ) << 16
            info.compress_type = zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED
            archive.writestr(info, content)
    return stream.getvalue()


def raw_zip(
    name=b"sample-1.0/ok.py",
    content=b"abc",
    method=0,
    flags=0,
    payload=None,
    size=None,
    crc=None,
    extra=b"",
    local_name=None,
    descriptor=True,
):
    if payload is None:
        compressor = zlib.compressobj(wbits=-15)
        payload = compressor.compress(content) + compressor.flush() if method == 8 else content
    size = len(content) if size is None else size
    crc = zlib.crc32(content) if crc is None else crc
    local_name = name if local_name is None else local_name
    local_crc, local_compressed, local_size = (0, 0, 0) if flags & 8 else (crc, len(payload), size)
    local = struct.pack(
        "<4s5H3L2H",
        b"PK\x03\x04",
        20,
        flags,
        method,
        0,
        0x5021,
        local_crc,
        local_compressed,
        local_size,
        len(local_name),
        len(extra),
    )
    local += local_name + extra + payload
    if flags & 8 and descriptor:
        local += b"PK\x07\x08" + struct.pack("<3L", crc, len(payload), size)
    central = struct.pack(
        "<4s6H3L5H2L",
        b"PK\x01\x02",
        (3 << 8) | 20,
        20,
        flags,
        method,
        0,
        0x5021,
        crc,
        len(payload),
        size,
        len(name),
        len(extra),
        0,
        0,
        0,
        (stat.S_IFREG | 0o644) << 16,
        0,
    )
    central += name + extra
    end = struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, 1, 1, len(central), len(local), 0)
    return local + central + end


@pytest.fixture(params=["tar", "tar.gz", "zip", "zip.deflate"])
def archive_builder(request):
    kind = request.param

    def build(rows):
        if kind.startswith("tar"):
            return tar_archive(rows, kind == "tar.gz")
        return zip_archive(rows, kind == "zip.deflate")

    return build
