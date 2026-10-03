> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# SourceReleaseReview


New implementation author: **dhtfish98**. Current project version: **0.1.2**.

Compare an existing local source-release archive with an independently trusted path manifest. The new implementation reads actual tar or ZIP records and payload spans, preserves duplicate/link/path-conflict evidence, and reports required omissions and unapproved extras. It never extracts the archive, executes archived source, discovers VCS files, runs a target build or rewrites a manifest.

```sh
python -m pip install .
source-release-review examples/release-manifest.json examples/sample-source.tar.gz
source-release-review examples/release-manifest.json examples/sample-extra.zip
```

The first returns PASS/exit 0 under the supplied manifest's trust precondition. The second returns FAIL/exit 1 for an extra member. `examples/sample-corrupt.zip` returns OPEN/exit 2. These are synthetic local archives, including an inert `setup.py` source string; the tool never runs that source.

```python
from source_release_review import Limits, review_bytes, review_files

report = review_files("trusted.json", "existing.tar.gz")
print(report.status)
print(report.to_dict())
# In-memory caller-supplied bytes, with lowered budgets:
report = review_bytes(manifest_bytes, archive_bytes, limits=Limits(max_members=256))
```

Python 3.11+ and the standard library suffice. File access requires directory-relative open and `O_DIRECTORY`, `O_NOFOLLOW`, `O_NONBLOCK`; missing facilities produce OPEN. The CLI accepts `--format auto|tar|tar.gz|zip`. Auto selection reads record signatures, rather than trusting filename extensions. JSON is the only ordinary/error output; explicit help/version are informational exceptions.

The trusted JSON schema is exact:

```json
{
  "schema_version": "1",
  "root": "sample-1.0",
  "files": ["README.txt", "setup.py"],
  "allowed_generated": ["PKG-INFO"]
}
```

`files` is a nonempty required relative file list. `allowed_generated` is an exact optional-presence list: each listed path may occur, but is not required. There are no wildcard policies or hidden exclusions. A file cannot be on both lists; duplicate, ambiguous, unsafe or colliding manifest paths yield OPEN. Root is one explicit directory name. Do not derive a trusted manifest or generated-file policy from the archive being reviewed: that would make the comparison circular. Trust in the caller's manifest, file content authenticity and execution safety remain OPEN on every report.

| Status | Meaning | CLI exit |
| --- | --- | --- |
| PASS | Complete path comparison matches the declared subset and policy, assuming manifest trust | 0 |
| FAIL | Known omission, extra, duplicate, link, unsafe path or structural type/name conflict | 1 |
| OPEN | Input/corruption/unsupported-profile/budget failure; inspection is partial | 2 |

OPEN retains observed violations and counters. PASS proves neither authentic source content nor safe code, a reproducible build, an installed package or CVP eligibility. This project complements a digest verifier and a wheel-install namespace review; it does not implement either of those mechanisms.

Reports may show missing/explicitly allowed paths from the caller-trusted manifest. Untrusted archive names, including extras and unsafe names, are represented by SHA-256 and logical member index, never raw text. Indices are one-based and exclude tar PAX metadata headers. Host input paths, payload content, exception strings and archive comments are omitted. Archive/manifest/name hashes and counters remain metadata that should be handled privately.

See [DEFENSIVE_SCOPE.md](<DEFENSIVE_SCOPE.md>) for supported structures and budgets, [ORIGIN.md](<ORIGIN.md>) for the frozen check-manifest source/license and implementation attribution, and [VALIDATION.md](<VALIDATION.md>) for actual validation and open evidence. CVP approval and any future model safety response remain OPEN.

Local-file capability boundary: required OS flags must be exact positive integers. Descriptor walking also requires declared `os.open` directory-relative support. Missing, null, zero, boolean or otherwise invalid required capabilities return a controlled OPEN result before file access. Native Windows local-file reading is outside this POSIX profile.
