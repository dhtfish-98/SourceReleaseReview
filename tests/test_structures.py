import gzip
import io
import struct
import tarfile
import zlib

import pytest
from conftest import manifest, raw_zip, tar_archive, zip_archive

from source_release_review import Limits, review_bytes

BASE = ("sample-1.0/ok.py", "regular", b"abc")


def checksum(header):
    header[148:156] = b"        "
    header[148:156] = f"{sum(header):06o}\0 ".encode()
    return bytes(header)


@pytest.mark.parametrize(
    "options",
    [
        {},
        {"method": 8},
        {"flags": 8},
        {"flags": 8, "method": 8},
        {"extra": struct.pack("<HHBL", 0x5455, 5, 1, 0)},
    ],
)
def test_independent_raw_zip_structures_and_descriptors(options):
    assert review_bytes(manifest(), raw_zip(**options)).status == "PASS"


def test_unsigned_zip_data_descriptor():
    data = raw_zip(flags=8)
    signature = data.index(b"PK\x07\x08")
    modified = bytearray(data[:signature] + data[signature + 4 :])
    end = modified.rfind(b"PK\x05\x06")
    offset = struct.unpack_from("<L", modified, end + 16)[0]
    struct.pack_into("<L", modified, end + 16, offset - 4)
    assert review_bytes(manifest(), bytes(modified)).status == "PASS"


@pytest.mark.parametrize(
    "options",
    [
        {"flags": 1},
        {"flags": 0x40},
        {"method": 12},
        {"method": 99},
        {"size": 8},
        {"size": 1},
        {"crc": 0},
        {"flags": 8, "descriptor": False},
        {"local_name": b"sample-1.0/no.py"},
        {"method": 8, "payload": b"\xff\x00"},
        {"method": 8, "payload": b"\x03"},
        {"method": 8, "payload": b"\x03\x00junk", "content": b""},
        {"extra": b"bad"},
        {"extra": struct.pack("<HH", 0x0001, 0)},
        {"extra": struct.pack("<HH", 0x7075, 0)},
        {"extra": struct.pack("<HH", 0x000A, 0)},
        {"extra": struct.pack("<HH", 0x5455, 0)},
        {"extra": struct.pack("<HHB", 0x5455, 1, 0xFF)},
        {"name": b"sample-1.0/\xff.py", "flags": 0x800},
    ],
)
def test_malformed_unsupported_raw_zip_never_clean(options):
    report = review_bytes(manifest(), raw_zip(**options))
    assert report.status == "OPEN" and report.truncated


@pytest.mark.parametrize("offset", [4, 6, 8, 10, 12, 16])
def test_end_record_disagreement_and_zip64(offset):
    data = bytearray(raw_zip())
    end = data.rfind(b"PK\x05\x06")
    struct.pack_into(
        "<H" if offset < 12 else "<L", data, end + offset, 0xFFFF if offset < 12 else 0xFFFFFFFF
    )
    assert review_bytes(manifest(), bytes(data)).status == "OPEN"


def test_crc_checks_real_member_payload_not_metadata():
    data = bytearray(raw_zip())
    name_length = struct.unpack_from("<H", data, 26)[0]
    data[30 + name_length] ^= 1
    report = review_bytes(manifest(), bytes(data))
    assert report.status == "OPEN" and report.reason == "zip_payload_crc_or_length"


def test_nul_zip_name_is_detected_despite_library_truncation():
    data = zip_archive([BASE])
    # Preserve length while injecting NUL in both real name records.
    name = b"sample-1.0/ok.py"
    evil = b"sample-1.0/\0k.py"
    data = data.replace(name, evil)
    report = review_bytes(manifest(), data)
    assert report.status == "OPEN" or report.status == "FAIL"
    assert any(item.reason == "dangerous_or_noncanonical_path" for item in report.findings)


@pytest.mark.parametrize(
    "mutation",
    [
        "payload_truncate",
        "one_end_block",
        "header_checksum",
        "trailing_junk",
        "padding",
        "nul_suffix",
        "magic",
    ],
)
def test_tar_physical_layout_and_truncation(mutation):
    data = tar_archive([BASE])
    if mutation == "payload_truncate":
        header = bytearray(data[:512])
        header[124:136] = b"00000010000\0"
        data = checksum(header) + data[512:1024]
    elif mutation == "one_end_block":
        data = data[:1536]
    elif mutation == "header_checksum":
        data = b"X" + data[1:]
    elif mutation == "trailing_junk":
        data = data[:-1] + b"X"
    elif mutation == "padding":
        data = data[:515] + b"X" + data[516:]
    elif mutation == "magic":
        header = bytearray(data[:512])
        header[257:263] = b"abcdef"
        data = checksum(header) + data[512:]
    else:
        header = bytearray(data[:512])
        header[0:100] = b"sample-1.0/ok.py\0PRIVATE_SUFFIX\0".ljust(100, b"\0")
        data = checksum(header) + data[512:]
    report = review_bytes(manifest(), data)
    assert report.status == "OPEN"
    assert "PRIVATE_SUFFIX" not in str(report.to_dict())


def test_tar_regular_gnu_and_ustar_variants():
    for format_kind in (tarfile.GNU_FORMAT, tarfile.USTAR_FORMAT):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=format_kind) as archive:
            info = tarfile.TarInfo(BASE[0])
            info.size = 3
            archive.addfile(info, io.BytesIO(b"abc"))
        assert review_bytes(manifest(), stream.getvalue()).status == "PASS"


@pytest.mark.parametrize(
    "headers",
    [
        {"GNU.sparse.name": "sample-1.0/ok.py"},
        {"size": "9999999"},
        {"unknown": "PRIVATE"},
    ],
)
def test_pax_unknown_or_size_override_is_unimplemented_open(headers):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        info = tarfile.TarInfo(BASE[0])
        info.pax_headers = headers
        info.size = 3
        archive.addfile(info, io.BytesIO(b"abc"))
    assert review_bytes(manifest(), stream.getvalue()).status == "OPEN"


def test_gzip_actual_crc_truncation_and_expansion_limits():
    data = gzip.compress(tar_archive([BASE]), mtime=0)
    bad = bytearray(data)
    bad[-8] ^= 1
    for value in (bytes(bad), data[:-3]):
        assert review_bytes(manifest(), value).status == "OPEN"
    report = review_bytes(manifest(), data, limits=Limits(max_expanded_bytes=1024))
    assert report.status == "OPEN" and report.reason == "expanded_archive_byte_budget"


def test_declared_payload_budgets_and_member_counts():
    rows = [BASE, ("sample-1.0/other.py", "regular", b"abc")]
    for data in (tar_archive(rows), zip_archive(rows)):
        assert review_bytes(manifest(), data, limits=Limits(max_members=1)).status == "OPEN"
    assert (
        review_bytes(manifest(), zip_archive(rows), limits=Limits(max_expanded_bytes=5)).status
        == "OPEN"
    )
    assert (
        review_bytes(manifest(), tar_archive(rows), limits=Limits(max_tar_headers=1)).status
        == "OPEN"
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "truncated",
        "trailing",
        "local_signature",
        "local_flags",
        "local_version",
        "platform",
        "version",
    ],
)
def test_zip_physical_local_central_end_checks(mutation):
    data = bytearray(raw_zip())
    if mutation == "truncated":
        data = data[:-1]
    elif mutation == "trailing":
        data += b"junk"
    elif mutation == "local_signature":
        data[0] = 0
    elif mutation == "local_flags":
        struct.pack_into("<H", data, 6, 2)
    elif mutation == "local_version":
        struct.pack_into("<H", data, 4, 10)
    elif mutation == "platform":
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 4, (99 << 8) | 20)
    else:
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<H", data, central + 6, 45)
    assert review_bytes(manifest(), bytes(data)).status == "OPEN"


def test_mislabeled_dos_and_macos_link_bits_still_rejected():
    for producer in (0, 19):
        data = bytearray(zip_archive([BASE, ("sample-1.0/link", "symbolic", b"target")]))
        second = data.find(b"PK\x01\x02", data.find(b"PK\x01\x02") + 1)
        struct.pack_into("<H", data, second + 4, (producer << 8) | 20)
        report = review_bytes(manifest(), bytes(data))
        assert report.status == "FAIL"
        assert any(item.reason == "symbolic_or_hard_link_member" for item in report.findings)


def test_deflate_bounded_against_lying_size():
    content = b"x" * 200000
    compressor = zlib.compressobj(wbits=-15)
    payload = compressor.compress(content) + compressor.flush()
    data = raw_zip(method=8, payload=payload, size=3)
    assert review_bytes(manifest(), data).status == "OPEN"


def descriptor_signature(data, signed):
    if signed:
        return data
    signature = data.index(b"PK\x07\x08")
    changed = bytearray(data[:signature] + data[signature + 4 :])
    end = changed.rfind(b"PK\x05\x06")
    offset = struct.unpack_from("<L", changed, end + 16)[0]
    struct.pack_into("<L", changed, end + 16, offset - 4)
    return bytes(changed)


@pytest.mark.parametrize("signed", [True, False])
@pytest.mark.parametrize("offset", [14, 18, 22])
def test_descriptor_contradictory_nonzero_local_fields_open(signed, offset):
    data = bytearray(descriptor_signature(raw_zip(flags=8, method=8), signed))
    struct.pack_into("<L", data, offset, 123456)
    report = review_bytes(manifest(), bytes(data))
    assert report.status == "OPEN"
    assert report.reason == "zip_descriptor_local_crc_or_size_disagreement"


@pytest.mark.parametrize("signed", [True, False])
def test_descriptor_matching_backfilled_local_fields_profile(signed):
    data = bytearray(descriptor_signature(raw_zip(flags=8, method=8), signed))
    central = data.find(b"PK\x01\x02")
    data[14:26] = data[central + 16 : central + 28]
    assert review_bytes(manifest(), bytes(data)).status == "PASS"


def test_deflate_with_version_needed_below20_is_open():
    data = bytearray(raw_zip(method=8))
    central = data.find(b"PK\x01\x02")
    struct.pack_into("<H", data, 4, 10)
    struct.pack_into("<H", data, central + 6, 10)
    report = review_bytes(manifest(), bytes(data))
    assert report.status == "OPEN" and report.reason == "zip_deflate_version_disagreement"
