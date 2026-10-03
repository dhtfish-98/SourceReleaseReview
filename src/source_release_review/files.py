"""Bounded local regular-file reading; every component refuses symlinks."""

import os
import stat


def read_regular(path, limit):
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
    directory_capabilities = getattr(os, "supports_dir_fd", None)
    directory_relative_open = (
        isinstance(directory_capabilities, (set, frozenset)) and os.open in directory_capabilities
    )
    if os.name != "posix" or any(
        type(getattr(os, flag, None)) is not int or getattr(os, flag) <= 0 for flag in required
    ):
        raise ValueError("safe_open_unsupported")
    if not directory_relative_open:
        raise ValueError("directory_relative_open_unsupported")
    text = os.fspath(path)
    if not isinstance(text, str) or not text or len(text) > 4096 or "\0" in text:
        raise ValueError("invalid_path")
    if ".." in text.split(os.sep):
        raise ValueError("parent_traversal")
    parts = os.path.abspath(text).split(os.sep)[1:]
    directory = os.open(os.sep, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[:-1]:
            child = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("regular_file_or_byte_budget")
            chunks = []
            length = 0
            while length <= limit:
                block = os.read(descriptor, min(65536, limit + 1 - length))
                if not block:
                    break
                chunks.append(block)
                length += len(block)
            after = os.fstat(descriptor)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if (
                length > limit
                or length != after.st_size
                or any(getattr(before, field) != getattr(after, field) for field in fields)
            ):
                raise ValueError("changed_or_byte_budget")
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
