"""JSON-only comparison of a local trusted manifest and existing archive."""

import argparse
import json

from . import __version__
from .review import Report, review_files


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_cli_arguments")


def main(argv=None):
    parser = _Parser(description="Read-only source release path review; manifest trust is assumed.")
    parser.add_argument("manifest", help="caller-trusted JSON manifest, regular file")
    parser.add_argument("archive", help="existing tar, tar.gz or ZIP, regular file")
    parser.add_argument("--format", choices=["auto", "tar", "tar.gz", "zip"], default="auto")
    parser.add_argument("--version", action="version", version=__version__)
    try:
        args = parser.parse_args(argv)
        report = review_files(args.manifest, args.archive, archive_format=args.format)
    except ValueError:
        report = Report("OPEN", "invalid_cli_arguments")
    print(json.dumps(report.to_dict(), ensure_ascii=True, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report.status]
