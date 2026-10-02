# Software Requirements Specification — CppCryptoPrimitives

**Status:** Draft v0.1 (Requirements stage)
**Author:** Requirements Analyst
**Date:** 2026-10-02
**License:** MIT

---

## 1. Purpose & Scope

### 1.1 Purpose
CppCryptoPrimitives is an **educational C++ portfolio project** that implements a small,
focused set of common cryptographic primitives using **constant-time programming
techniques**. Each primitive is accompanied by **side-channel notes** that document its
timing/side-channel considerations and known limitations.

The project exists to **demonstrate the author's understanding of constant-time
implementation discipline and awareness of side-channel pitfalls** — not to ship a
competitive or hardened cryptographic library.

### 1.2 Educational — NOT for production (disclaimer)
> ⚠️ **This code is for learning and demonstration only. It is NOT audited, NOT hardened,
> and MUST NOT be used to protect real data or in any production system.** Use a vetted,
> maintained library (e.g. libsodium, BoringSSL, OpenSSL) for real-world cryptography.

This disclaimer is a hard requirement and must appear in the repository README and in the
top-level header/documentation of the library (see FR-13, NFR-10).

### 1.3 Scope
In scope: constant-time building blocks and a small number of symmetric primitives that
let the author illustrate timing-safe coding patterns, plus per-primitive written analysis
of side-channel exposure. Out-of-scope items are listed in Section 8.

---

## 2. Primitive Selection

The primitives are chosen to maximize learning value per unit of effort and to cover the
canonical constant-time patterns (branchless selection, masked comparison, bitslicing,
and modular arithmetic) while remaining achievable for a single developer.

### 2.1 MVP (must-have, prioritized)
A small, coherent core that demonstrates the key techniques end-to-end:

| ID | Primitive | Why it is in the MVP |
| --- | --- | --- |
| P-1 | **Constant-time memory equality / comparison** (`ct_memcmp`, `ct_equal`) | Foundational; demonstrates masked, branch-free comparison. |
| P-2 | **Constant-time conditional select & swap** (`ct_select`, `ct_cswap`) | Core branchless building block reused by other primitives. |
| P-3 | **SHA-256** | Well-specified, naturally constant-time (no secret-dependent branches/indexing), strong test-vector coverage. |
| P-4 | **HMAC-SHA-256** | Builds on P-1 and P-3; demonstrates constant-time tag verification. |

### 2.2 Stretch (optional, nice-to-have)
Added only after the MVP is complete and tested:

| ID | Primitive | Notes |
| --- | --- | --- |
| P-5 | **Constant-time / bitsliced AES core** (encrypt block; optionally key schedule) | The showcase constant-time primitive (no S-box table lookups). Higher effort/risk. |
| P-6 | **Fixed-width modular / field arithmetic helpers** (e.g. constant-time modular add/sub/mul for a small fixed prime) | Demonstrates constant-time big-integer-style discipline. |
| P-7 | **A simple teaching block cipher core** (e.g. a toy SPN) | Lower-risk alternative to P-5 if bitsliced AES proves too large. |
| P-8 | **Minimal asymmetric example** (e.g. X25519 scalar multiplication) | Only if time allows; showcases constant-time field/ladder work. Explicitly optional. |

### 2.3 Recommendation
Deliver **P-1 through P-4 as the MVP**. Treat **P-5 (bitsliced AES)** as the primary
stretch goal because it is the most illustrative constant-time primitive; fall back to
**P-7 (toy SPN)** if P-5 is too large for the timeframe. P-6 and P-8 are optional.

---

## 3. Functional Requirements

Each requirement is independently testable.

- **FR-1:** The library shall provide a constant-time equality function that compares two
  equal-length byte buffers and returns a boolean/flag result without leaking, via timing
  or branching, which byte(s) differ.
- **FR-2:** The library shall provide a constant-time conditional select that returns one
  of two equal-width values based on a boolean/mask condition, computed branch-free.
- **FR-3:** The library shall provide a constant-time conditional swap that swaps (or
  leaves unchanged) two equal-width values based on a mask condition, computed branch-free.
- **FR-4:** The library shall compute SHA-256 digests for arbitrary-length byte inputs and
  produce 32-byte digests matching published NIST/FIPS 180-4 test vectors.
- **FR-5:** The library shall support incremental (streaming) SHA-256 hashing via an
  init/update/finalize interface in addition to a one-shot interface.
- **FR-6:** The library shall compute HMAC-SHA-256 tags for a given key and message that
  match published RFC 4231 test vectors.
- **FR-7:** The library shall provide a constant-time HMAC tag-verification function that
  compares an expected tag against a computed tag using the FR-1 constant-time comparison.
- **FR-8:** Each primitive shall expose a documented public C++ interface (header) with
  clearly specified input/output buffer sizes and preconditions.
- **FR-9:** Each public primitive shall be covered by unit tests, including known-answer
  tests against published vectors where such vectors exist (FR-4, FR-6).
- **FR-10:** The library shall provide negative/edge-case tests (e.g. empty input,
  one-byte differences, maximal-length within test limits) for each primitive.
- **FR-11 (stretch, P-5/P-7):** If an AES or teaching-cipher core is implemented, it shall
  encrypt a single block and produce output matching the relevant known-answer vectors
  (FIPS-197 for AES) without secret-dependent table lookups or branches.
- **FR-12 (stretch, P-6):** If modular/field arithmetic helpers are implemented, they shall
  produce results matching a reference (non-constant-time) implementation across a
  randomized test range, with no secret-dependent control flow.
- **FR-13:** The library shall surface the "educational — not for production" disclaimer in
  a location a consumer cannot miss (top-level README and a top-level/library header).

---

## 4. Non-Functional Requirements

- **NFR-1 (Constant-time behavior):** All operations that process secret data shall be
  implemented to run in time independent of secret values, within the limits of the C++
  abstract machine and a reasonable optimizing compiler.
- **NFR-2 (No secret-dependent branches):** No conditional branch (`if`, `?:`, loops with
  secret-dependent bounds, short-circuit `&&`/`||`) shall depend on secret data in
  primitive implementations.
- **NFR-3 (No secret-dependent memory access):** No array index or memory-access pattern
  shall depend on secret data (e.g. no secret-indexed S-box table lookups); masked or
  bitsliced techniques shall be used instead.
- **NFR-4 (Language standard):** The code shall target **C++17** as the baseline (C++20 is
  acceptable if a specific feature provides clear value; see Open Questions). It shall
  compile warning-clean under `-Wall -Wextra` (GCC/Clang) at the chosen standard.
- **NFR-5 (Build system):** The project shall build with **CMake** (recommended minimum
  3.16+) and produce a reusable library target plus a test target.
- **NFR-6 (Test framework):** Unit tests shall use **GoogleTest** (recommended) or
  **Catch2** — a single framework chosen for the whole project (see Open Questions).
- **NFR-7 (Portability):** The code shall build and pass tests on **Linux with GCC and
  Clang**. Windows/MSVC support is a desirable secondary target but not required for MVP
  (see Open Questions).
- **NFR-8 (No external crypto dependencies):** MVP primitives shall be implemented from
  scratch with no third-party cryptographic library dependency; only the standard library
  and the chosen test framework are permitted dependencies.
- **NFR-9 (Dependency-free consumption):** The library shall be usable via a simple CMake
  `add_subdirectory`/`FetchContent` or `find_package`-style include without manual steps.
- **NFR-10 (Educational, not production):** The project shall not claim security assurances;
  all documentation shall reinforce that it is unaudited and unsuitable for production use.
- **NFR-11 (Readability as a goal):** Because the project is pedagogical, clarity of the
  constant-time technique takes precedence over micro-optimization; code shall favor
  readable, well-commented branchless patterns.
- **NFR-12 (Reproducible tests):** Any randomized tests shall use a fixed/seedable RNG so
  failures are reproducible.

---

## 5. Side-Channel Notes Requirement

- **SCN-1:** Each primitive shall ship with a written **side-channel notes** document
  (e.g. `docs/side-channel/<primitive>.md`) that covers, at minimum:
  1. The constant-time technique(s) used (e.g. masking, bitslicing, branchless select).
  2. What is claimed to be protected (which inputs are treated as secret).
  3. **Known limitations** — threats explicitly *not* mitigated (e.g. compiler may
     re-introduce branches, CPU micro-architectural leakage, cache/DVFS/power/EM, lack of
     `volatile`/memory-barrier guarantees, non-constant-time standard-library calls).
  4. How the constant-time property was reasoned about or checked (code review, inspection
     of generated assembly, optional tooling) and the limits of that evidence.
- **SCN-2:** The notes shall explicitly state that constant-time behavior is **not
  guaranteed** across all compilers, optimization levels, and hardware, and shall identify
  this as an inherent limitation of a source-level C++ implementation.
- **SCN-3:** A top-level side-channel overview shall summarize the project-wide threat model
  and the shared assumptions/limitations referenced by individual primitive notes.

---

## 6. Out of Scope

The following are explicitly **out of scope** for this project (at least for the current
iteration):

- Production hardening, security auditing, or any claim of production readiness.
- Formal verification or machine-checked constant-time proofs.
- Hardware-specific countermeasures (e.g. power/EM masking, fault-injection resistance,
  secure-enclave integration).
- Guarantees against micro-architectural attacks (cache, speculative execution, DVFS,
  power/EM side channels) beyond documenting them as limitations.
- A broad asymmetric-crypto suite. At most a **single minimal** asymmetric example (P-8)
  may be included as an optional stretch goal; full RSA/ECDSA/key-exchange suites are out.
- Protocol-level constructs (TLS, signatures schemes end-to-end, key management, secure
  storage).
- Performance benchmarking / optimization beyond what is needed to demonstrate technique.
- Cross-language bindings, packaging for distribution (e.g. system packages), or ABI
  stability guarantees.

---

## 7. Assumptions & Constraints

### Assumptions
- **A-1:** Single developer, portfolio timeframe; effort budget favors a small, polished
  MVP over breadth.
- **A-2:** Target reviewers are technical (hiring managers / engineers) who value visible
  constant-time technique and honest limitation disclosure.
- **A-3:** Primary development and CI environment is Linux with modern GCC and Clang.
- **A-4:** Published, freely usable test vectors exist for the MVP primitives (FIPS 180-4,
  RFC 4231) and may be embedded in tests.

### Constraints
- **C-1:** License is MIT (already established in the repository).
- **C-2:** No third-party cryptographic dependencies (NFR-8).
- **C-3:** Must build with CMake and a single chosen unit-test framework.
- **C-4:** Source-level C++ only — constant-time guarantees are best-effort and bounded by
  compiler/hardware behavior.

---

## 8. Open Questions (require stakeholder/PM confirmation before design)

- **OQ-1 (C++ standard):** Default to **C++17**, or adopt **C++20** (e.g. for concepts,
  `std::span`, `std::bit_cast`)? Recommendation: C++17 unless a C++20 feature is clearly
  justified.
- **OQ-2 (Test framework):** **GoogleTest** or **Catch2**? Recommendation: GoogleTest for
  familiarity and tooling, unless header-only Catch2 is preferred for simplicity.
- **OQ-3 (Windows/MSVC support):** Is MSVC/Windows support required for the portfolio, or
  is Linux + GCC/Clang sufficient for MVP? Recommendation: Linux-only for MVP, Windows as
  stretch.
- **OQ-4 (Stretch cipher choice):** If the stretch cipher is pursued, prefer **bitsliced
  AES (P-5)** for impact, or the **toy SPN (P-7)** for lower risk? Recommendation: attempt
  P-5, fall back to P-7.
- **OQ-5 (Asymmetric example):** Include the optional minimal asymmetric example (P-8,
  e.g. X25519) at all, or keep the project strictly symmetric? Recommendation: exclude from
  MVP; reconsider only if time remains.
- **OQ-6 (Constant-time verification tooling):** Is use of tooling (e.g. `dudect`,
  `ctgrind`/Valgrind, or assembly inspection) expected as evidence, or is documented code
  review sufficient? Recommendation: document code review + spot-check generated assembly;
  treat tooling as optional stretch.
- **OQ-7 (Secret-zeroization expectation):** Should primitives attempt best-effort
  zeroization of sensitive buffers (and document its limitations), or is that out of scope?
  Recommendation: include a documented best-effort wipe helper, flagged as non-guaranteed.

---

## 9. Acceptance Criteria

The requirements phase deliverable (this SRS) is accepted when:

- **AC-1:** The MVP primitive set (P-1…P-4) and prioritization are confirmed by the
  stakeholder.
- **AC-2:** Open Questions OQ-1 through OQ-7 are resolved or explicitly deferred.
- **AC-3:** Each MVP functional requirement (FR-1…FR-10, FR-13) is confirmed testable and
  in scope.
- **AC-4:** The non-functional constant-time expectations (NFR-1…NFR-3) and the
  educational-not-production constraint (NFR-10) are agreed as binding.
- **AC-5:** The side-channel notes requirement (SCN-1…SCN-3) is accepted as a mandatory
  deliverable for each primitive.

The project as a whole (for later stages) will be considered to meet requirements when every
MVP primitive compiles under the agreed standard, passes its known-answer and edge-case
tests, and ships with its side-channel notes and the not-for-production disclaimer.
