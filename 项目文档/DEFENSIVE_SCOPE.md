# Defensive scope and limits

The review is offline and read-only. Input is a caller-trusted UTF-8 JSON path manifest and one existing archive. Runtime uses no network API, target/module import, subprocess, VCS discovery, build backend, `setup.py` execution, installation, archive extraction or output-file write. Packaging checks build this reviewed tool itself; they do not build any inspected target archive.

## Selected archive profile

Raw tar supports regular files, directories, symbolic/hard links and special-member recognition, basic V7/USTAR/GNU headers, and local PAX metadata limited to `path`, `linkpath`, `mtime`, `atime`, `ctime`. Header checksums are validated with the standard-library TarInfo parser. Physical 512-byte headers, declared payload spans, zero padding, at least two terminal zero blocks and zero-only trailing padding are checked. Unknown magic, global PAX, GNU long-name/long-link/sparse extensions, PAX size overrides and unknown/duplicate PAX keys are OPEN. Directory payload, links and special files are known FAIL boundaries. Links are never followed. Only logical regular-file paths enter the compared inventory.

Tar.gz decoding is bounded and reads to EOF to check gzip length/CRC through the standard-library decoder. Raw tar itself has no per-payload CRC; a valid path inventory does not authenticate its contents. Additional compression wrappers are unimplemented and yield OPEN.

ZIP32 stored/deflate records are checked against bounded raw central/local/EOCD records and standard-library ZipFile metadata. Every supported payload is streamed through stored/deflate processing with declared-length, CRC32 and exact deflate EOF/no-trailing-data checks. Central count/size/offset, local name/flags/version/size/CRC, nonoverlapping contiguous local spans and signed/unsigned data descriptors are checked. With descriptor bit 3, the local CRC/size tuple must be either all zero or exactly equal to central values. Deflate needs version 2.0 in this profile. Versions 1.0-2.0 for stored files and producer markers DOS/Unix/macOS are supported; Unix link-type bits are rejected even under a DOS marker. Extended timestamp extra records have bounded recognized framing; their time values are not interpreted.

ZIP64, split/multidisk, encrypted or unfamiliar flag/compression/version/platform profiles, unknown extra fields including Unicode path alternatives, unclaimed prefix/gap/trailing bytes and archive digital-signature extensions are OPEN. This deliberately conservative subset is not a full validator for every valid tar/ZIP variant. Unsupported is not a claim that an archive is malicious.

## Path and manifest policy

Root must match the explicit trusted directory; extra roots and loose files are FAIL. Required paths must appear as regular files. Optional exact generated paths are recorded INFO; no default `PKG-INFO`, egg-info or setup.cfg exclusion is inherited from check-manifest. Extra directories outside the required/generated parent tree are also FAIL.

Raw absolute, parent/dot/empty components, backslashes, colons/Windows-invalid characters, NUL/control/format/surrogate characters, non-NFC paths, compatibility-normalized separators/dot components, trailing dots/spaces and Windows reserved names are rejected. NFKC+casefold comparisons cover full paths and every prefix to catch portable Unicode/case collisions and file/directory prefix conflicts. Names are not normalized to silently match the manifest. Raw duplicates and multiple type declarations remain evidence; no set conversion suppresses them.

The manifest is a trust precondition, not an archive claim that the tool proves. Names/metadata do not prove source authenticity, origin, execution behavior, reachability, malware absence, package safety or applicant eligibility. Every report keeps `manifest_trust_status`, `content_authenticity_status` and `execution_safety_status` OPEN. The manifest lists paths rather than content digests; signed provenance, repository history, reproducible builds and artifact digest verification are separate tasks.

## Budgets and privacy

Defaults can only be lowered: 16777216 archive bytes; 67108864 expanded tar or total supported ZIP payload bytes; 8388608 bytes per member; 2048 logical members; 4096 physical tar headers; 262144 manifest bytes; 2048 total required/generated paths; 1024 UTF-8 bytes per full member name; 32 full path components including root; 512 findings; 262144 encoded JSON report bytes (minimum 2048). A PAX metadata body has a further 65536-byte cap. Parsing and decompression are bounded by these limits; there is no OS time/memory sandbox or formal CPU/memory proof.

Budget/corruption failures yield partial OPEN; known violations and comparison counts survive report truncation even if rows must be dropped. Path/name/content errors use constant codes. Only relative paths explicitly present in the trusted manifest may appear in reports; untrusted members use name hashes and one-based logical indices. Hashes and counters are still identifying metadata.

Input file reading rejects any symlink component, raw `..`, directories, devices and nonblocking FIFO inputs. Capability guards and before/after device/inode/size/mtime/ctime plus actual read-length checks detect observed changes. This is not a proof against every concurrent rewrite. Contents/mtime are not intentionally changed; filesystem access time may change when read. Unknown, unsupported and malformed input never masquerades as a complete clean result.
