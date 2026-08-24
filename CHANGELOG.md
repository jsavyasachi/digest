# Changelog

## [1.6.0] - 2026-08-24

### Added

- Add a stateful incremental digest/HMAC context API with `update!`, `reset!`, and `finalize!` for processing large streams in caller-controlled chunks.
- Add direct `java.nio.file.Path`, `ByteBuffer`, and `ReadableByteChannel` input support.
- Add a faster streaming implementation that updates `MessageDigest` directly from a 64 KiB buffer instead of an intermediate lazy byte sequence over a 1 KiB buffer, with an opt-in benchmark to keep the improvement measurable.
- Make algorithm resolution provider-aware by querying the JCA provider registry directly, fixing false negatives for valid casing and aliases.
- Add `secure-eq?`, a constant-time digest-comparison helper that decodes hex/Base64 before comparing bytes via `MessageDigest/isEqual`.
- Add HMAC convenience functions for SHA-1, SHA-384, SHA-512, and SHA-3.
- Add public `bytes->hex` and `hex->bytes` conversion utilities.
- Expand the known-answer-vector test suite with NIST/RFC vectors, large-stream parity, and raw byte-array HMAC keys.

## [1.5.4] - 2026-07-12

### Changed

- Migrate the build to deps.edn and tools.build, with Leiningen supported via lein-tools-deps.
