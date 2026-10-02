# Side-Channel Notes — P-1: Constant-Time Equality / Comparison

**Module:** `ctcrypto::ct` — [`include/ctcrypto/ct.hpp`](../../include/ctcrypto/ct.hpp)
**Primitives:** `ct::eq`, `ct::is_zero`, `ct::is_nonzero`, `ct::mask_from_bit`,
`ct::memcmp_mask`, `ct::equal`
**Satisfies:** FR-1, NFR-1…NFR-3, SCN-1/SCN-2
**Status:** Educational — **NOT for production**. Read
[`overview.md`](overview.md) first; it holds the shared threat model and limitations.

---

## 1. Constant-time technique(s) used

Conditions are represented as **masks** — full-width unsigned integers that are either
all-zero (`0`) or all-one (`~0`) — so a condition can be folded into the data path with
bitwise operators instead of a branch.

- **`mask_from_bit(bit)`** turns a `0`/`1` bit into a `0`/all-ones mask using modular
  unsigned subtraction: `0 - (bit & 1)`. No branch.
- **`is_nonzero(x)`** collapses any non-zero value to all-ones via `(x | -x) >> (width-1)`
  (the sign/top bit is set iff `x != 0`), then expands that bit to a full mask.
  `is_zero(x)` is its bitwise complement.
- **`eq(a, b)`** computes `is_zero(a ^ b)` — all-ones iff the operands are equal.
- **`memcmp_mask(a, b, len)`** (the byte-buffer comparison, P-1) **OR-accumulates** every
  byte difference `a[i] ^ b[i]` into a single running `diff` byte and reduces it to a mask
  with `is_zero` **exactly once at the end**. There is **no early exit** on the first
  mismatching byte, so the loop always runs `len` iterations.
- **`equal(a, b, len)`** is the boolean wrapper: `memcmp_mask(...) != 0`.

The loop in `memcmp_mask` is bounded only by `len`, which is **public**.

## 2. What is treated as secret

- The **contents** of both buffers (`a[i]`, `b[i]`) are secret. The implementation never
  branches on them nor uses them as indices.
- For the scalar helpers, the operand values and any condition bit are secret.

What is **public**:

- The buffer length `len` (and therefore the loop trip count).
- The final match / no-match answer — this is the function's intended return value. It is
  *where* a mismatch occurs that is not leaked, not the yes/no result itself.

## 3. Known limitations / threats NOT mitigated

In addition to everything in [`overview.md §2.3 and §3`](overview.md):

- **Compiler reintroduction of branches.** Nothing in the C++ standard prevents an optimizer
  from compiling the masked reduction into a conditional. The spot-check (below) found no
  such branch at `-O2` on the CI compilers, but this is not guaranteed elsewhere.
- **The public result is, by design, observable.** A caller that itself branches on the
  returned bool can leak the match/no-match decision — that is expected and in-scope as a
  public output, but callers comparing *secret-derived* equality should keep the result in
  masked form (`memcmp_mask`) and avoid branching on it.
- **No cache / micro-architectural / power / EM / fault protection** — see the overview.
- `len` is public by contract; this primitive does **not** hide the length of the compared
  buffers.

## 4. How it was reasoned about / checked

- **Code review** confirmed: mask-only idioms, OR-accumulation with a single final
  reduction, no early-out, loop bound = public `len` (NFR-2/NFR-3).
- **QA generated-assembly spot-check (OQ-6):** `ct::memcmp_mask` was inspected at `-O2 -S`
  on GCC 13.3 and Clang 18.1; no secret-dependent branch was emitted and the accumulate-then-
  reduce shape was preserved.

**Limits of this evidence:** spot-check at a single optimization level on two compilers —
not a proof, and not checked across other toolchains/targets. See
[`overview.md §4.1`](overview.md).
