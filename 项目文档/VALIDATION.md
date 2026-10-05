## Current release 0.1.3: package and documentation layout sync, 2026-10-05

This patch release binds the current source and package metadata to the centralized 项目文档 and Build layout. Runtime behavior is unchanged from the previous main commit except version identifiers. The complete existing third-party licenses and provenance notices remain in scope. Historical tests below retain their original version and date; exact current build, installed-consumer and hosted-CI results are recorded separately with the release. CVP eligibility and applicant approval remain OPEN.

# Current delivery validation — 0.1.2

New implementation author and maintainer: dhtfish98. This patch removes only source-reference or unbundled-dependency notice copies identified as unused. Licenses/notices associated with redistributed material and specific OPEN applicability questions are retained byte-for-byte. The new own runtime differs only in version metadata; parser and policy behavior are unchanged.

Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (self-digest excluded). Current source, package-install and source-package rebuild checks are recorded in the separate 2026-10-03 license-cleanup delivery evidence. Package inventories, author/version metadata and runtime bytes are checked against this formal source. Installation uses frozen local dependencies; target inputs are never executed. New-commit hosted CI and publication remain pending until the owner publishes this patch.

Engineering results do not establish human contribution, identity, organization, safeguards impact or CVP admission.

## Historical previous delivery evidence

The remaining text describes earlier versions and their original material inventories. It does not describe or validate this patch.

# Current delivery validation — 0.1.1

New implementation author and maintainer: dhtfish98. Current source inventory: `SOURCE_REVIEW_MANIFEST.json` (this manifest excludes its own digest). The 2026-10-03 delivery preserves original upstream license and notice bytes; current runtime additionally validates the required OS capability flags and directory-relative support before local file reads.

The existing suite has 268 passing test cases in the current source and in a fresh consumer of this version. Package verification checks version/author, artifact RECORD or archive inventories, runtime bytes against the formal source, and retained third-party licenses. Consumer installation uses local frozen dependencies and does not run target inputs. Detailed current artifact hashes and execution receipts are kept in the separate delivery evidence.

New-commit hosted CI and publication remain pending until the repository owner publishes this version.

These engineering checks do not establish upstream authorship, independent human review, actual safeguards impact or CVP eligibility.

## Historical delivery evidence

The following sections describe the earlier delivery and retain its original versions and checks. They do not validate a later artifact.

# Validation and open evidence

Every new runtime/CLI/test/script/dependency/package/workflow source was reviewed locally. The root agent also read the complete runtime/reader/CLI and requested targeted privacy/ZIP consistency checks, which were incorporated. This is automated source review and regression evidence, not independent human review or a formal security audit.

Observed local regression result: **264 passed, 0 failed, 0 skipped** on Python 3.14.6/macOS. Tests build real synthetic tar, tar.gz and stored/deflated ZIP inputs with ordinary standard-library writers and independently specified raw ZIP records. Coverage includes actual payload CRC/length/deflate EOF, signed/unsigned descriptors, local/central/version/EOCD contradictions, gzip CRC/truncation/bounded expansion, tar checksum/spans/padding/end records, GNU/USTAR/local-PAX basics, unsupported extensions, required/generated/extra policy, duplicates, links/special files, root/prefix/Unicode/case conflicts, limits, metadata/file-length changes, unsupported safe-open capabilities, special files/symlinks, input immutability and path/content/error privacy. The complete original license hash is verified separately.

The final local verification checks lint/format, dependencies, wheel/sdist build, exact SPDX/license/entrypoint/dependency metadata, all wheel RECORD hashes/lengths, runtime source identity and sdist documentation/policy identity. A committed independent self-manifest is authored from this reviewed source checkout before the build; the resulting real sdist is compared with that manifest. Generated metadata is permitted only by eight explicit paths, never learned from the target archive. A path match still leaves trust/content/execution status OPEN.

A fresh separate environment installs the final wheel offline with no runtime dependencies. Six installed console/module CLI cases cover tar.gz/ZIP PASS, extra-member FAIL, CRC corruption OPEN and missing-file OPEN. Five installed audit cases check that source archive review performs no exec/import/socket/process/write-open event after preloading standard-library helpers; all six installed runtime files are compared byte-for-byte against the final wheel. Builds and audit hooks are observed local evidence, not a proof for arbitrary environments.

Final artifact/install evidence and exact SHA-256 values are recorded in the separate engineering report and ignored `validation-local` directory to avoid a circular artifact self-hash. The committed CI matrix performs the complete suite, lint/format, archive verification, real self-sdist comparison and an independent installed CLI/audit run on Ubuntu/macOS with Python 3.11/3.14. Remote execution remains OPEN until actually observed.

Remaining OPEN: trusted manifest provenance, source content authenticity, safe execution or malware absence, signed provenance/reproducible build/source history, full tar/ZIP feature compatibility, all concurrent-file rewrite races, OS CPU/memory isolation, other Python/platform combinations, formal dependency/security audit, independent human review, remote CI, applicant eligibility, actual safeguard obstacles and CVP approval. A successful path comparison closes none of these.

To reproduce:

```sh
python -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m pytest -q
.venv/bin/ruff check src tests scripts
.venv/bin/ruff format --check src tests scripts
.venv/bin/python -m pip check
.venv/bin/python -m build --no-isolation
.venv/bin/python scripts/verify_package.py dist/source_release_review-0.1.0-py3-none-any.whl dist/source_release_review-0.1.0.tar.gz
.venv/bin/python scripts/self_sdist_check.py dist/source_release_review-0.1.0.tar.gz
python -m venv .install-check
.install-check/bin/python -m pip install --no-index --no-deps dist/source_release_review-0.1.0-py3-none-any.whl
.install-check/bin/python -m pip check
.install-check/bin/python scripts/installed_cli_check.py
.install-check/bin/python scripts/installed_smoke.py dist/source_release_review-0.1.0-py3-none-any.whl
.install-check/bin/python scripts/self_sdist_check.py dist/source_release_review-0.1.0.tar.gz
```
