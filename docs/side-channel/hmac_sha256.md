# Side-Channel Notes — P-4: HMAC-SHA-256

**Module:** `ctcrypto::HmacSha256` / `ctcrypto::hmac_sha256` /
`ctcrypto::hmac_sha256_verify` —
[`include/ctcrypto/hmac_sha256.hpp`](../../include/ctcrypto/hmac_sha256.hpp),
[`src/hmac_sha256.cpp`](../../src/hmac_sha256.cpp)
**Satisfies:** FR-6, FR-7, NFR-1…NFR-3, SCN-1/SCN-2
**Status:** Educational — **NOT for production**. Read
[`overview.md`](overview.md) first; it holds the shared threat model and limitations.

---

## 1. Constant-time technique(s) used

HMAC-SHA-256 composes the lower primitives: it runs SHA-256 (P-3) twice (inner/outer) and,
for verification, compares tags through the constant-time equality of P-1.

- **Constant-time tag verification.** `hmac_sha256_verify` recomputes the tag and compares it
  against `expected_tag` via **`ct::equal`** — the OR-accumulated, single-reduction byte
  comparison — **never** `std::memcmp` or a short-circuit loop. Timing is independent of
  *where* a mismatch occurs (FR-7).
- **Public-length key derivation.** The RFC 2104 key schedule (`k0`, `i_key_pad`,
  `o_key_pad_`) is built with loop bounds that depend only on the **public** key length,
  never on key byte values. Long keys (`> 64` bytes) are hashed with SHA-256 then zero-padded;
  short keys are zero-padded — in both cases the control flow keys off the public length.
- **Inherits SHA-256's branch/index-freedom** for the two hash passes (see
  [`sha256.md`](sha256.md)).
- **Best-effort secret hygiene.** `k0`, `i_key_pad`, the hashed-key buffer, the inner digest,
  and the recomputed tag are wiped with `secure_wipe` after use; `o_key_pad_` is wiped in the
  destructor.

### A note on the length check in `verify`

`hmac_sha256_verify` first checks `tag_len != 32` with an ordinary branch and returns
`false` early if so. This is **intentional and safe**: `tag_len` is **public** (a structural
property of the caller's buffer, not a secret value), so branching on it leaks nothing about
the key or the tag contents. The secret-sensitive comparison — the 32 tag bytes — is the part
routed through `ct::equal`.

## 2. What is treated as secret

- The **HMAC key** bytes, and all key-derived material: `k0`, `i_key_pad`, `o_key_pad_`, the
  inner hash state, the inner digest, and the recomputed tag.
- In `verify`, the **contents** of `expected_tag` are treated as secret for the comparison.

What is **public**:

- The key length, message length, and tag length (and therefore all loop bounds).
- The final verify boolean (match / no-match) — the function's intended return value. Only
  the *position* of a mismatch is hidden, not the yes/no result.

## 3. Known limitations / threats NOT mitigated

In addition to everything in [`overview.md §2.3 and §3`](overview.md):

- **Key length is not hidden.** A key longer than the 64-byte block triggers an extra
  SHA-256 pass, so the *key length class* (≤ block vs. > block) is observable via timing.
  Key length is public by contract; the key *bytes* are not leaked.
- **Message/tag length are public** and affect timing; these are not concealed.
- **Caller must not re-branch on secret equality.** `verify` returns a public boolean; a
  caller that derives further secret-dependent behavior from it reintroduces a side channel
  outside this primitive's control.
- **`secure_wipe` is best-effort** — key pads and state copies may survive in registers,
  spills, or swap; see the overview.
- **No cache / micro-architectural / power / EM / fault protection** — see the overview.
- **Compiler variance.** Constant-time behavior is not guaranteed across compilers,
  optimization levels, and hardware (SCN-2).

## 4. How it was reasoned about / checked

- **Code review** confirmed: verification routed through `ct::equal` (no `memcmp`, no
  short-circuit), key schedule bounded by public length only, and best-effort wiping of all
  key-derived buffers (NFR-2/NFR-3, FR-7).
- **QA verification:** 58/58 GoogleTest pass including HMAC-SHA-256 RFC 4231 known-answer
  vectors and verify edge cases; ASan+UBSan clean on GCC 13.3 and Clang 18.1.
- **QA generated-assembly spot-check (OQ-6):** `hmac_sha256_verify` was inspected at
  `-O2 -S` and confirmed to route the tag comparison through `ct::equal` with no
  secret-dependent branch.

**Limits of this evidence:** spot-check at a single optimization level on two compilers plus
known-answer/sanitizer coverage — not a formal proof, and not checked across other
toolchains/targets. See [`overview.md §4.1`](overview.md).
