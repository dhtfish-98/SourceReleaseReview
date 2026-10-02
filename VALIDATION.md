# Validation and open evidence

Every new runtime/CLI/test/script/dependency/package/workflow source was reviewed locally. The root agent also read the complete runtime/reader/CLI and requested targeted privacy/ZIP consistency checks, which were incorporated. This is AI-assisted source review and regression evidence, not independent human review or a formal security audit.

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
