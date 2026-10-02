# Changelog

All notable changes to CppCryptoPrimitives are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> ⚠️ **Educational — NOT for production.** This library is unaudited, unhardened, and
> provides best-effort constant-time behavior only. It MUST NOT be used to protect real data
> or in any production system. Use a vetted, maintained library (libsodium, BoringSSL,
> OpenSSL) for real-world cryptography.

## [Unreleased]

_No unreleased changes._

## [0.1.0] - 2026-10-02

Initial MVP release: a small, from-scratch C++17 library demonstrating constant-time
implementation discipline and side-channel awareness. **Educational, unaudited, and
explicitly not for production use.**

### Added

- **P-1 — Constant-time equality / comparison** (`ctcrypto::ct`): mask helpers
  (`mask_from_bit`, `is_zero`, `is_nonzero`, `eq`), plus the OR-accumulated, single-reduction
  byte-buffer comparison `memcmp_mask` and its boolean wrapper `equal` (no early-out on
  mismatch). Header: `ctcrypto/ct.hpp`.
- **P-2 — Constant-time conditional select & swap** (`ctcrypto::ct`): branchless
  `select(mask, a, b)` and `cswap(mask, a, b)` using the XOR-mask identity. Header:
  `ctcrypto/ct.hpp`.
- **P-3 — SHA-256** (`ctcrypto::Sha256`, `ctcrypto::sha256`): one-shot and streaming
  (init/update/finalize) interfaces; naturally branchless compression with table/schedule
  indexing by the public round counter only. Matches FIPS 180-4 test vectors. Header:
  `ctcrypto/sha256.hpp`.
- **P-4 — HMAC-SHA-256** (`ctcrypto::HmacSha256`, `ctcrypto::hmac_sha256`): one-shot and
  streaming tag computation plus **constant-time tag verification** (`hmac_sha256_verify`)
  routed through `ct::equal`. Matches RFC 4231 test vectors. Header:
  `ctcrypto/hmac_sha256.hpp`.
- **`secure_wipe`** — best-effort, non-guaranteed secret zeroization using a
  volatile-access + compiler-barrier pattern, with a `std::array` convenience overload.
  Header: `ctcrypto/wipe.hpp`.
- **Umbrella header** `ctcrypto/ctcrypto.hpp` carrying the not-for-production disclaimer
  (FR-13).
- **Side-channel notes** (`docs/side-channel/`): project-wide threat-model overview plus a
  per-primitive note for P-1…P-4, satisfying the mandatory SRS deliverable (SCN-1…SCN-3).
- **Build & test:** CMake (≥ 3.16) static library target `ctcrypto::ctcrypto`; GoogleTest
  suite fetched via `FetchContent`; CI (GitHub Actions + GitLab CI) covering GCC/Clang ×
  Debug/Release plus an ASan/UBSan job.
- **Documentation:** SRS, design document, and README with build/usage instructions and the
  prominent educational disclaimer.

### Security / constant-time notes

- Constant-time properties are **best-effort source-level** and **not guaranteed** across
  compilers, optimization levels, or hardware (SCN-2). Evidence basis is **code review plus
  a `-O2` generated-assembly spot-check** of the constant-time helpers and HMAC verify
  (OQ-6) — a spot-check, **not** a formal proof.
- Not mitigated: cache/micro-architectural, speculative, power/EM, fault, and DVFS side
  channels. See [`docs/side-channel/overview.md`](docs/side-channel/overview.md).

### Verification

- 58/58 unit tests passing (known-answer FIPS 180-4 / RFC 4231 vectors plus edge cases).
- Warning-clean under `-Wall -Wextra`; ASan + UBSan clean on GCC 13.3 and Clang 18.1 (Linux).

[Unreleased]: https://github.com/vladiant/CppCryptoPrimitives/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vladiant/CppCryptoPrimitives/releases/tag/v0.1.0
