# SPDX-License-Identifier: MIT
# New implementation by dhtfish98; no check-manifest runtime reused.
"""Read bounded real tar/ZIP structures and compare with a caller-trusted manifest.

No extraction, source execution, VCS discovery, target import or build is performed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import stat
import struct
import tarfile
import unicodedata
import zipfile
import zlib
from dataclasses import asdict, dataclass, field

from .files import read_regular


@dataclass(frozen=True)
class Limits:
    max_archive_bytes: int = 16777216
    max_expanded_bytes: int = 67108864
    max_member_bytes: int = 8388608
    max_members: int = 2048
    max_tar_headers: int = 4096
    max_manifest_bytes: int = 262144
    max_manifest_paths: int = 2048
    max_name_bytes: int = 1024
    max_path_components: int = 32
    max_findings: int = 512
    max_report_bytes: int = 262144

    def valid(self):
        return (
            all(
                type(value) is int and 1 <= value <= cap
                for value, cap in zip(
                    asdict(self).values(),
                    (16777216, 67108864, 8388608, 2048, 4096, 262144, 2048, 1024, 32, 512, 262144),
                    strict=True,
                )
            )
            and self.max_report_bytes >= 2048
        )


DEFAULT_LIMITS = Limits()


class _Stop(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise _Stop(reason)


def safe_path(name, limits):
    if not isinstance(name, str) or not name:
        return False
    try:
        if len(name.encode("utf-8")) > limits.max_name_bytes:
            return False
    except UnicodeError:
        return False
    if unicodedata.normalize("NFC", name) != name:
        return False
    if len(name.split("/")) > limits.max_path_components:
        return False
    if any(unicodedata.category(char).startswith("C") for char in name):
        return False
    for part in name.split("/"):
        normalized = unicodedata.normalize("NFKC", part)
        if not part or part in {".", ".."} or part.endswith((".", " ")):
            return False
        if normalized in {".", ".."} or any(char in normalized for char in '/\\:<>"|?*'):
            return False
        if normalized.endswith((".", " ")):
            return False
        stem = normalized.split(".", 1)[0].upper()
        if stem in {"CON", "PRN", "AUX", "NUL"} or stem in {
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            return False
    return True


def prefixes(path):
    parts = path.split("/")
    return ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]


def portable_key(path):
    return unicodedata.normalize("NFKC", path).casefold()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "manifest_duplicate_key")
        result[key] = value
    return result


def invalid_constant(value):
    raise _Stop("manifest_nonfinite_number")


@dataclass(frozen=True)
class Manifest:
    root: str
    files: frozenset[str]
    allowed_generated: frozenset[str]

    @classmethod
    def parse(cls, data, limits):
        require(
            isinstance(data, bytes) and 0 < len(data) <= limits.max_manifest_bytes,
            "manifest_byte_budget_or_type",
        )
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=no_duplicate_keys,
            parse_constant=invalid_constant,
        )
        require(
            isinstance(value, dict)
            and set(value) == {"schema_version", "root", "files", "allowed_generated"},
            "manifest_schema",
        )
        require(value["schema_version"] == "1", "manifest_schema_version")
        require(safe_path(value["root"], limits) and "/" not in value["root"], "manifest_root")
        require(
            isinstance(value["files"], list)
            and isinstance(value["allowed_generated"], list)
            and 0 < len(value["files"]) <= limits.max_manifest_paths
            and len(value["files"]) + len(value["allowed_generated"]) <= limits.max_manifest_paths,
            "manifest_path_budget_or_type",
        )
        rows = value["files"] + value["allowed_generated"]
        require(
            all(safe_path(value["root"] + "/" + name, limits) for name in rows), "manifest_path"
        )
        require(len(rows) == len(set(rows)), "manifest_duplicate_or_policy_overlap")
        tree = {}
        for name in rows:
            for prefix in prefixes(name):
                key = portable_key(prefix)
                require(key not in tree or tree[key] == prefix, "manifest_portable_collision")
                tree[key] = prefix
        all_files = set(rows)
        require(
            not any(prefix in all_files for name in rows for prefix in prefixes(name)[:-1]),
            "manifest_file_directory_conflict",
        )
        return cls(value["root"], frozenset(value["files"]), frozenset(value["allowed_generated"]))


@dataclass(frozen=True)
class Finding:
    kind: str
    reason: str
    member_index: int | None = None
    path: str | None = None
    path_sha256: str | None = None


@dataclass(frozen=True)
class Report:
    status: str
    reason: str
    findings: tuple[Finding, ...] = ()
    archive_sha256: str | None = None
    manifest_sha256: str | None = None
    archive_format: str | None = None
    members_seen: int = 0
    regular_files_seen: int = 0
    payload_bytes_checked: int = 0
    generated_files_allowed: int = 0
    missing_files: int = 0
    extra_files: int = 0
    violations_seen: int = 0
    truncated: bool = False
    coverage_status: str = "NOT_ANALYZED"
    schema_version: str = "1.0"
    manifest_trust_status: str = "OPEN"
    content_authenticity_status: str = "OPEN"
    execution_safety_status: str = "OPEN"
    scope: str = "existing source archive path inventory under a caller-trusted manifest"

    def to_dict(self):
        return asdict(self)


@dataclass
class Review:
    manifest: Manifest
    limits: Limits
    findings: list[Finding] = field(default_factory=list)
    members: int = 0
    regular: int = 0
    payload: int = 0
    generated: int = 0
    missing: int = 0
    extra: int = 0
    violations: int = 0
    raw_names: set[str] = field(default_factory=set)
    paths: dict[str, str] = field(default_factory=dict)
    portable: dict[str, str] = field(default_factory=dict)
    inventory: set[str] = field(default_factory=set)
    inventory_index: dict[str, int] = field(default_factory=dict)

    def emit(self, reason, index=None, path=None, raw=None, kind="FAIL"):
        if kind == "FAIL":
            self.violations += 1
        require(len(self.findings) < self.limits.max_findings, "finding_budget")
        digest = hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest() if raw else None
        self.findings.append(Finding(kind, reason, index, path, digest))

    def member(self, name, kind, size):
        self.members += 1
        require(self.members <= self.limits.max_members, "member_budget")
        index = self.members
        require(
            type(size) is int and 0 <= size <= self.limits.max_member_bytes, "member_size_budget"
        )
        require(len(name.encode("utf-8")) <= self.limits.max_name_bytes, "member_name_byte_budget")
        if kind == "link":
            self.emit("symbolic_or_hard_link_member", index, raw=name)
        elif kind == "special":
            self.emit("special_or_conflicting_member_type", index, raw=name)
        if name in self.raw_names:
            self.emit("duplicate_member", index, raw=name)
        self.raw_names.add(name)
        canonical = name[:-1] if kind == "directory" and name.endswith("/") else name
        if not safe_path(canonical, self.limits):
            self.emit("dangerous_or_noncanonical_path", index, raw=name)
            return
        relative = canonical.removeprefix(self.manifest.root + "/")
        if canonical != self.manifest.root and relative == canonical:
            self.emit("wrong_archive_root", index, raw=name)
        if canonical == self.manifest.root and kind != "directory":
            self.emit("root_is_not_directory", index, raw=name)
        if canonical in self.paths:
            self.emit("same_path_multiple_entries", index, raw=name)
        self.paths[canonical] = kind
        for prefix in prefixes(canonical):
            key = portable_key(prefix)
            if key in self.portable and self.portable[key] != prefix:
                self.emit("portable_unicode_or_case_collision", index, raw=name)
            self.portable[key] = prefix
        if kind == "directory":
            if size:
                self.emit("directory_has_payload", index, raw=name)
        elif kind == "regular":
            self.regular += 1
            if canonical.startswith(self.manifest.root + "/"):
                self.inventory.add(relative)
                self.inventory_index.setdefault(relative, index)
        elif kind not in {"link", "special"}:
            self.emit("unsupported_member_type", index, raw=name)

    def comparison(self):
        require(self.regular > 0, "archive_has_no_regular_files")
        file_keys = {portable_key(name) for name, kind in self.paths.items() if kind != "directory"}
        directories = {self.manifest.root}
        for name in self.manifest.files | self.manifest.allowed_generated:
            directories.update(prefixes(self.manifest.root + "/" + name)[:-1])
        for path, kind in sorted(self.paths.items()):
            if kind == "directory" and path not in directories:
                self.emit("unexpected_release_directory", raw=path)
            for parent in prefixes(path)[:-1]:
                if portable_key(parent) in file_keys:
                    self.emit("file_directory_prefix_conflict", raw=path)
                    break
        missing = self.manifest.files - self.inventory
        extras = self.inventory - self.manifest.files - self.manifest.allowed_generated
        allowed = self.inventory & self.manifest.allowed_generated
        self.missing, self.extra, self.generated = len(missing), len(extras), len(allowed)
        for name in sorted(missing):
            self.emit("required_source_missing", path=name)
        for name in sorted(extras):
            self.emit(
                "unexpected_release_file",
                self.inventory_index[name],
                raw=self.manifest.root + "/" + name,
            )
        for name in sorted(allowed):
            self.emit("explicit_generated_path_allowed", path=name, kind="INFO")


def expanded_gzip(data, limit):
    result = []
    size = 0
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
        while size <= limit:
            chunk = stream.read(min(65536, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, "expanded_archive_byte_budget")
            result.append(chunk)
    return b"".join(result)


def parse_pax(data):
    result = {}
    position = 0
    while position < len(data):
        space = data.find(b" ", position, position + 20)
        require(space > position and data[position:space].isdigit(), "pax_record_length")
        length = int(data[position:space])
        end = position + length
        require(
            end <= len(data) and end > space + 2 and data[end - 1 : end] == b"\n",
            "pax_record_length",
        )
        pair = data[space + 1 : end - 1].decode("utf-8")
        require("=" in pair, "pax_record_shape")
        key, value = pair.split("=", 1)
        require(key in {"path", "linkpath", "mtime", "atime", "ctime"}, "pax_field_unimplemented")
        require(key not in result and "\0" not in value, "pax_duplicate_or_nul")
        result[key] = value
        position = end
    return result


def read_tar(data, review):
    require(
        0 < len(data) <= review.limits.max_expanded_bytes and len(data) % 512 == 0,
        "tar_length_or_expanded_budget",
    )
    offset = 0
    headers = 0
    pending = None
    ended = False
    while offset < len(data):
        block = data[offset : offset + 512]
        if block == b"\0" * 512:
            require(
                pending is None and len(data) - offset >= 1024 and not any(data[offset:]),
                "tar_end_markers_or_trailing_data",
            )
            ended = True
            break
        headers += 1
        require(headers <= review.limits.max_tar_headers, "tar_header_budget")
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        magic = block[257:263]
        require(magic in {b"ustar\0", b"ustar ", b"\0" * 6}, "tar_format_unimplemented")
        string_fields = [(0, 100), (157, 257)]
        if magic == b"ustar\0":
            string_fields.append((345, 500))
        for start, end in string_fields:
            text = block[start:end]
            marker = text.find(b"\0")
            require(marker < 0 or not any(text[marker:]), "tar_noncanonical_string_field")
        require(0 <= info.size <= review.limits.max_member_bytes, "member_size_budget")
        payload_start = offset + 512
        payload_end = payload_start + info.size
        padded_end = payload_start + ((info.size + 511) // 512) * 512
        require(padded_end <= len(data), "tar_truncated_payload")
        require(not any(data[payload_end:padded_end]), "tar_nonzero_payload_padding")
        if info.type == tarfile.XHDTYPE:
            require(pending is None and info.size <= 65536, "pax_header_budget_or_overlap")
            pending = parse_pax(data[payload_start:payload_end])
        else:
            require(
                info.type
                not in {
                    tarfile.XGLTYPE,
                    tarfile.GNUTYPE_LONGNAME,
                    tarfile.GNUTYPE_LONGLINK,
                    tarfile.GNUTYPE_SPARSE,
                },
                "tar_extension_unimplemented",
            )
            name = pending.get("path", info.name) if pending is not None else info.name
            pending = None
            kind = (
                "regular"
                if info.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
                else "directory"
                if info.type == tarfile.DIRTYPE
                else "link"
                if info.type in {tarfile.SYMTYPE, tarfile.LNKTYPE}
                else "special"
            )
            review.member(name, kind, info.size)
            review.payload += info.size
            require(review.payload <= review.limits.max_expanded_bytes, "payload_byte_budget")
        offset = padded_end
    require(ended, "tar_missing_end_markers")


def extra_fields(data):
    position = 0
    while position < len(data):
        require(position + 4 <= len(data), "zip_extra_field_truncated")
        key, size = struct.unpack_from("<HH", data, position)
        position += 4
        require(position + size <= len(data), "zip_extra_field_truncated")
        require(key == 0x5455, "zip_extra_field_unimplemented")
        require(
            size in {1, 5, 9, 13} and not data[position] & ~7,
            "zip_timestamp_extra_field_unimplemented",
        )
        position += size


def zip_headers(data, limits):
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    require(end >= 0 and end + 22 <= len(data), "zip_end_record_missing")
    fields = struct.unpack_from("<4s4H2LH", data, end)
    require(end + 22 + fields[7] == len(data), "zip_truncated_or_trailing_data")
    require(fields[1] == fields[2] == 0 and fields[3] == fields[4], "zip_multidisk_unimplemented")
    require(
        fields[4] != 0xFFFF and fields[5] != 0xFFFFFFFF and fields[6] != 0xFFFFFFFF,
        "zip64_unimplemented",
    )
    require(0 < fields[4] <= limits.max_members, "zip_member_budget_or_empty")
    central_size, central_offset = fields[5:7]
    require(central_offset + central_size == end, "zip_central_directory_span")
    rows = []
    position = central_offset
    while position < end:
        require(position + 46 <= end, "zip_central_record_truncated")
        row = struct.unpack_from("<4s6H3L5H2L", data, position)
        require(row[0] == b"PK\x01\x02", "zip_central_signature")
        require(
            10 <= row[2] <= 20 and row[1] >> 8 in {0, 3, 19},
            "zip_version_or_platform_unimplemented",
        )
        require(
            row[13] == 0
            and row[8] != 0xFFFFFFFF
            and row[9] != 0xFFFFFFFF
            and row[16] != 0xFFFFFFFF,
            "zip64_or_multidisk_unimplemented",
        )
        name_end = position + 46 + row[10]
        next_position = name_end + row[11] + row[12]
        require(next_position <= end, "zip_central_record_truncated")
        extra_fields(data[name_end : name_end + row[11]])
        raw_name = data[position + 46 : name_end]
        require(0 < len(raw_name) <= limits.max_name_bytes, "zip_name_byte_budget")
        name = raw_name.decode("utf-8" if row[3] & 0x800 else "cp437")
        require(not row[3] & ~0x80E, "zip_flags_unimplemented")
        require(row[4] in {0, 8}, "zip_compression_unimplemented")
        require(row[4] != 8 or row[2] >= 20, "zip_deflate_version_disagreement")
        require(row[9] <= limits.max_member_bytes, "member_size_budget")
        rows.append((row, name, raw_name))
        require(len(rows) <= limits.max_members, "zip_member_budget")
        position = next_position
    require(position == end and len(rows) == fields[4], "zip_entry_count_disagreement")
    return rows, central_offset


def zip_payload(data, start, compressed_size, method, expected_size, expected_crc):
    crc = 0
    size = 0
    decoder = zlib.decompressobj(-15) if method == 8 else None
    for offset in range(start, start + compressed_size, 65536):
        block = data[offset : min(offset + 65536, start + compressed_size)]
        content = decoder.decompress(block, expected_size - size + 1) if decoder else block
        size += len(content)
        require(size <= expected_size, "zip_uncompressed_length_disagreement")
        crc = zlib.crc32(content, crc)
        if decoder:
            require(
                not decoder.unconsumed_tail and not decoder.unused_data,
                "zip_deflate_extra_or_oversized_data",
            )
    if decoder:
        require(decoder.eof, "zip_deflate_truncated")
    require(size == expected_size and crc == expected_crc, "zip_payload_crc_or_length")
    return size


def read_zip(data, review):
    rows, central_offset = zip_headers(data, review.limits)
    # Mature central metadata parser is independently cross-checked against the
    # bounded raw central/local records before any member payload is consumed.
    with zipfile.ZipFile(io.BytesIO(data), mode="r") as archive:
        infos = archive.infolist()
        require(len(infos) == len(rows), "zip_metadata_count_disagreement")
        spans = []
        for (row, name, raw_name), info in zip(rows, infos, strict=True):
            require(
                info.orig_filename == name
                and info.header_offset == row[16]
                and info.CRC == row[7]
                and info.compress_size == row[8]
                and info.file_size == row[9]
                and info.external_attr == row[15]
                and info.flag_bits == row[3]
                and info.compress_type == row[4]
                and info.create_system == row[1] >> 8,
                "zip_metadata_disagreement",
            )
            local_offset = row[16]
            require(
                0 <= local_offset and local_offset + 30 <= central_offset, "zip_local_header_span"
            )
            local = struct.unpack_from("<4s5H3L2H", data, local_offset)
            require(
                local[0] == b"PK\x03\x04"
                and local[1] == row[2]
                and local[2] == row[3]
                and local[3] == row[4],
                "zip_local_central_header_disagreement",
            )
            name_start = local_offset + 30
            name_end = name_start + local[9]
            start = name_end + local[10]
            require(
                start <= central_offset and data[name_start:name_end] == raw_name,
                "zip_local_central_name_disagreement",
            )
            extra_fields(data[name_end:start])
            finish = start + row[8]
            require(finish <= central_offset, "zip_truncated_payload")
            if row[3] & 8:
                require(
                    local[6:9] in {(0, 0, 0), row[7:10]},
                    "zip_descriptor_local_crc_or_size_disagreement",
                )
                descriptor = finish
                if data[descriptor : descriptor + 4] == b"PK\x07\x08":
                    descriptor += 4
                require(descriptor + 12 <= central_offset, "zip_descriptor_truncated")
                require(
                    struct.unpack_from("<3L", data, descriptor) == row[7:10],
                    "zip_descriptor_disagreement",
                )
                finish = descriptor + 12
            else:
                require(local[6:9] == row[7:10], "zip_local_crc_or_size_disagreement")
            # Reject Unix link bits even with a mismatched producer host marker.
            mode = stat.S_IFMT(info.external_attr >> 16)
            kind = (
                "link"
                if mode == stat.S_IFLNK
                else "directory"
                if info.is_dir() or mode == stat.S_IFDIR or info.external_attr & 0x10
                else "regular"
            )
            if mode not in {0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
                kind = "special"
            if mode == stat.S_IFREG and info.is_dir():
                kind = "special"
            if kind == "directory" and not name.endswith("/"):
                kind = "special"
            review.member(name, kind, row[9])
            require(
                review.payload + row[9] <= review.limits.max_expanded_bytes, "payload_byte_budget"
            )
            review.payload += zip_payload(data, start, row[8], row[4], row[9], row[7])
            spans.append((local_offset, finish))
        position = 0
        for start, finish in sorted(spans):
            require(start == position and finish >= start, "zip_overlap_gap_or_preamble")
            position = finish
        require(position == central_offset, "zip_unclaimed_local_bytes")


def finish(review, archive_digest, manifest_digest, archive_format, reason=None):
    findings = tuple(review.findings)
    report = Report(
        "OPEN" if reason else "FAIL" if review.violations else "PASS",
        reason or ("release_path_mismatch" if review.violations else "release_paths_match"),
        findings,
        archive_digest,
        manifest_digest,
        archive_format,
        review.members,
        review.regular,
        review.payload,
        review.generated,
        review.missing,
        review.extra,
        review.violations,
        bool(reason),
        "PARTIAL" if reason else "DECLARED_SUBSET",
    )
    while (
        len(json.dumps(report.to_dict(), ensure_ascii=True).encode())
        > review.limits.max_report_bytes
    ):
        findings = findings[:-1]
        report = Report(
            "OPEN",
            "report_byte_budget",
            findings,
            archive_digest,
            manifest_digest,
            archive_format,
            review.members,
            review.regular,
            review.payload,
            review.generated,
            review.missing,
            review.extra,
            review.violations,
            True,
            "PARTIAL",
        )
    return report


def review_bytes(
    manifest_data: bytes,
    archive_data: bytes,
    *,
    archive_format="auto",
    limits: Limits = DEFAULT_LIMITS,
) -> Report:
    """Read one caller-trusted JSON manifest and archive bytes; never extract/run."""
    review = None
    try:
        require(isinstance(limits, Limits) and limits.valid(), "invalid_limits")
        require(
            isinstance(archive_data, bytes) and 0 < len(archive_data) <= limits.max_archive_bytes,
            "archive_byte_budget_or_type",
        )
        require(archive_format in {"auto", "tar", "tar.gz", "zip"}, "archive_format_unsupported")
        manifest = Manifest.parse(manifest_data, limits)
        archive_digest = hashlib.sha256(archive_data).hexdigest()
        manifest_digest = hashlib.sha256(manifest_data).hexdigest()
        review = Review(manifest, limits)
        if archive_format == "auto":
            archive_format = (
                "zip"
                if archive_data.startswith(b"PK")
                else "tar.gz"
                if archive_data.startswith(b"\x1f\x8b")
                else "tar"
            )
        if archive_format == "zip":
            read_zip(archive_data, review)
        else:
            expanded = (
                expanded_gzip(archive_data, limits.max_expanded_bytes)
                if archive_format == "tar.gz"
                else archive_data
            )
            read_tar(expanded, review)
        review.comparison()
        return finish(review, archive_digest, manifest_digest, archive_format)
    except _Stop as error:
        reason = str(error)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        reason = "manifest_or_archive_encoding_syntax"
    except Exception:
        reason = "archive_or_input_unreadable"
    if review is not None:
        return finish(review, archive_digest, manifest_digest, archive_format, reason)
    return Report("OPEN", reason)


def review_files(
    manifest_path, archive_path, *, archive_format="auto", limits: Limits = DEFAULT_LIMITS
) -> Report:
    """Bounded regular files only; no paths or raw exception messages in output."""
    try:
        require(isinstance(limits, Limits) and limits.valid(), "invalid_limits")
        manifest = read_regular(manifest_path, limits.max_manifest_bytes)
        archive = read_regular(archive_path, limits.max_archive_bytes)
    except _Stop as error:
        return Report("OPEN", str(error))
    except Exception:
        return Report("OPEN", "file_read_rejected")
    return review_bytes(manifest, archive, archive_format=archive_format, limits=limits)
