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
| 5. Release | Release Engineer | Done (committed) |
| 6. Documentation | Technical Writer | Done (committed) |
| 7. Release close-out | PM (semver-version-publish) | Tag v0.1.0 created |

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
- Release stage complete: `.github/workflows/ci.yml` (GCC/Clang × Debug/Release + ASan/UBSan
  job), `.gitlab-ci.yml` equivalent, `VERSION` file at `0.1.0`. Local dry-run 58/58 clean.
  Committed via `semver-commit-description` (patch). Routed to Technical Writer.
- Documentation stage complete: side-channel notes `docs/side-channel/{overview,ct_compare,
  ct_select_swap,sha256,hmac_sha256}.md` (SCN-1…SCN-3 deliverable now satisfied), `CHANGELOG.md`
  (Keep-a-Changelog, `Unreleased`→`0.1.0`), and README polish (verified API, added
  side-channel + changelog links). Docs-only; no code touched. Pending PM commit/version
  close-out.

## Post-release maintenance

- **CI fix (GitLab sanitizer job):** the bare `ubuntu:24.04` image shipped base `clang`
  without Clang's compiler-rt sanitizer static archives, so the ASan/UBSan job failed at
  `project()` configure time (`cannot find libclang_rt.asan*-x86_64.a`). Fixed by installing
  `libclang-rt-18-dev` in the `sanitizers` job. CI-only; no library source/tests/CMake
  changed, so no QA re-run required. GitHub Actions unaffected (hosted runner bundles the
  runtimes). Local sanitizer run still 58/58 clean. Committed via `semver-commit-description`
  (patch).

## Outstanding Items (tracked across stages)

- **Side-channel notes (SRS SCN-1…SCN-3):** DONE — `docs/side-channel/overview.md` + the four
  per-primitive notes written at the Documentation stage. Mandatory SRS deliverable satisfied.
- **Assembly spot-check (OQ-6):** DONE (QA stage) — `-O2 -S` inspection of `ct::memcmp_mask`,
  `ct::select`, `ct::cswap`, and `hmac_sha256_verify` confirmed no secret-dependent branches
  and HMAC verify via `ct::equal`; referenced as the evidence basis in the side-channel notes.
- **Version close-out:** DONE — documentation committed; inaugural release tagged `v0.1.0`
  via `semver-version-publish`. No prior tag existed and `VERSION` was deliberately
  initialized to the intended first-release version `0.1.0`, so the inaugural tag is `v0.1.0`
  (we tag the established first version rather than auto-bumping past it to 0.2.0).
  `CHANGELOG.md` already finalized `0.1.0` (2026-10-02); `Unreleased` is empty. The tag push
  is left to the user's explicit confirmation.

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
