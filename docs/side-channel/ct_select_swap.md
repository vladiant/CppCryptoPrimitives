# Side-Channel Notes — P-2: Constant-Time Conditional Select & Swap

**Module:** `ctcrypto::ct` — [`include/ctcrypto/ct.hpp`](../../include/ctcrypto/ct.hpp)
**Primitives:** `ct::select`, `ct::cswap`
**Satisfies:** FR-2, FR-3, NFR-1…NFR-3, SCN-1/SCN-2
**Status:** Educational — **NOT for production**. Read
[`overview.md`](overview.md) first; it holds the shared threat model and limitations.

---

## 1. Constant-time technique(s) used

Both primitives take a **mask** (all-ones or all-zeros, as produced by the P-1 helpers) and
fold the choice into the data path with bitwise XOR — never a branch.

- **`select(mask, a, b)`** uses the XOR-mask identity
  `b ^ (mask & (a ^ b))`:
  - `mask` all-ones → the term is `a ^ b`, so the result is `b ^ (a ^ b) = a`.
  - `mask` all-zeros → the term is `0`, so the result is `b`.
  Both inputs `a` and `b` are always evaluated and touched; the computation is identical
  regardless of the mask value.
- **`cswap(mask, a, b)`** computes `t = mask & (a ^ b)` and then `a ^= t; b ^= t`:
  - `mask` all-ones → `t = a ^ b`, which exchanges the two values.
  - `mask` all-zeros → `t = 0`, leaving both unchanged.
  The same three operations execute every time; there is no conditional move of memory and
  no branch.

Both are `constexpr`, templated on an unsigned type, and perform no memory indexing.

## 2. What is treated as secret

- The **mask / condition** and **both operand values** (`a`, `b`) are secret. The code never
  branches on them and never uses them as an index.

What is **public**:

- The operand width (the template type `U`) and the fact that a select/swap happened. The
  *direction* of the choice is not leaked by control flow.

## 3. Known limitations / threats NOT mitigated

In addition to everything in [`overview.md §2.3 and §3`](overview.md):

- **Caller contract on the mask.** `select`/`cswap` assume `mask` is strictly all-ones or
  all-zeros. Passing a partial mask yields a bit-mixed result; always derive the mask from
  the P-1 helpers (`mask_from_bit`, `eq`, `is_zero`, …) rather than a raw `0/1` or `bool`.
- **Compiler reintroduction of branches / `cmov` vs. branch.** The optimizer may lower the
  masked form to a conditional move or, in principle, a predicted branch. The spot-check
  (below) found branchless code at `-O2` on the CI compilers; this is not guaranteed on
  other toolchains.
- **No cache / micro-architectural / power / EM / fault protection** — see the overview.
  `cswap` operates on values/registers, not secret-indexed memory, so it avoids
  secret-dependent *addressing*, but it does not defend against power/EM analysis of the
  data itself.

## 4. How it was reasoned about / checked

- **Code review** confirmed the XOR-mask identities, unconditional evaluation of both
  operands, and the absence of any branch or secret-dependent index (NFR-2/NFR-3).
- **QA generated-assembly spot-check (OQ-6):** `ct::select` and `ct::cswap` were inspected
  at `-O2 -S` on GCC 13.3 and Clang 18.1; branchless code was emitted (no secret-dependent
  conditional jump).

**Limits of this evidence:** spot-check at a single optimization level on two compilers —
not a proof, and not checked across other toolchains/targets. See
[`overview.md §4.1`](overview.md).
