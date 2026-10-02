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
| 3. Implementation | Cpp Developer | In progress |
| 4. Verification | QA Engineer | Pending |
| 5. Release | Release Engineer | Pending |
| 6. Documentation | Technical Writer | Pending |

## Running Log

- Project kicked off. Fresh repo (LICENSE + .gitignore + .github scaffolding only).
  Routed to Requirements Analyst to produce a lightweight SRS before any design/code.
- Requirements stage complete: `docs/requirements/SRS.md`. MVP = P-1…P-4.
  Committed via `semver-commit-description` (minor). Routed to System Architect.
- Design stage complete: `docs/design/DESIGN.md`. 4 modules (wipe→ct→sha256→hmac),
  namespace `ctcrypto`, CMake + GoogleTest(FetchContent), scoped to MVP only.
  Committed via `semver-commit-description` (minor). Routed to Cpp Developer.

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
