# Project Status — CppCryptoPrimitives

**Goal:** Constant-time C++ implementations of common crypto primitives, with side-channel
notes. Educational — explicitly **not for production**.

**Project-wide requirements from stakeholder:**
- Commit after each stage using the `semver-commit-description` skill.
- When all work is done, set the version using `semver-version-publish` and create version tags.

## Pipeline (new-project chain)

| Stage | Agent | Status |
| --- | --- | --- |
| 1. Requirements | Requirements Analyst | Done (committed) |
| 2. Design | System Architect | Done (committed) |
| 3. Implementation | Cpp Developer | Done (committed) |
| 4. Verification | QA Engineer | Done (committed) |
| 5. Release | Release Engineer | In progress |
| 6. Documentation | Technical Writer | Pending |

## Running Log

- Project kicked off. Fresh repo (LICENSE + .gitignore + .github scaffolding only).
  Routed to Requirements Analyst to produce a lightweight SRS before any design/code.
- Requirements stage complete: `docs/requirements/SRS.md`. MVP = P-1…P-4.
  Committed via `semver-commit-description` (minor). Routed to System Architect.
- Design stage complete: `docs/design/DESIGN.md`. 4 modules (wipe→ct→sha256→hmac),
  namespace `ctcrypto`, CMake + GoogleTest(FetchContent), scoped to MVP only.
  Committed via `semver-commit-description` (minor). Routed to Cpp Developer.
- Implementation stage complete: headers/src/tests + CMake + README. Built
  warning-clean on GCC 13.3 and Clang 18.1; 40/40 GoogleTest pass. Committed via
  `semver-commit-description` (minor). Routed to QA Engineer.
- QA stage complete: **PASS-WITH-NOTES**. 58/58 tests (18 added), ASan+UBSan clean on
  GCC 13.3 + Clang 18.1, requirements traceability FR-1…FR-13 / NFR-1…NFR-3 covered,
  assembly spot-check (OQ-6) confirms no secret-dependent branches and HMAC verify via
  `ct::equal`. Committed via `semver-commit-description` (patch). Routed to Release Engineer.

## Outstanding Items (tracked across stages)

- **Side-channel notes (SRS SCN-1…SCN-3):** `docs/side-channel/overview.md` + per-primitive
  notes are a mandatory SRS deliverable, NOT yet written (correctly out of implementation
  scope). **Owner: Technical Writer stage.** Must be done before final close-out.
- **Assembly spot-check (OQ-6):** QA to perform `-O2 -S` inspection of `ct::memcmp_mask`,
  `ct::select`, `ct::cswap`, and `hmac_sha256_verify` as constant-time evidence.

## PM Decisions (resolving SRS Open Questions)

- **OQ-1 → C++17** baseline.
- **OQ-2 → GoogleTest** as the single test framework.
- **OQ-3 → Linux + GCC/Clang only** for MVP; Windows/MSVC deferred.
- **OQ-4 → Stretch cipher:** attempt bitsliced/constant-time AES (P-5), fall back to
  toy SPN (P-7). Stretch only — not part of MVP acceptance.
- **OQ-5 → Exclude** the asymmetric example (P-8) from current scope.
- **OQ-6 → Evidence** = documented code review + generated-assembly spot-check;
  constant-time tooling (dudect/ctgrind) optional/stretch.
- **OQ-7 → Include** a documented best-effort secret-zeroization helper, flagged
  as non-guaranteed.
- **MVP scope frozen at P-1…P-4.** P-5…P-8 are post-MVP stretch, pursued only if the
  MVP ships cleanly.

## Open Questions / Blockers

- None open — OQ-1…OQ-7 resolved above.
