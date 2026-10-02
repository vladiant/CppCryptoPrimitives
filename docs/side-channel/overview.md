# Side-Channel Notes — Project Overview

**Scope:** CppCryptoPrimitives (MVP: P-1…P-4 + `secure_wipe`)
**Status:** Educational — **NOT for production**
**Satisfies:** SRS §5 (SCN-1…SCN-3)

> ⚠️ **This library is unaudited, unhardened, and not for production use.** The
> constant-time properties described here are *best-effort source-level* properties.
> They are **not guaranteed** across all compilers, optimization levels, or hardware,
> and they have **not** been formally verified. Use a vetted, maintained library
> (libsodium, BoringSSL, OpenSSL) for anything real.

This document is the project-wide threat model and the shared set of assumptions and
limitations referenced by the per-primitive notes (SCN-3). Each primitive ships with its
own note that builds on this baseline:

- [`ct_compare.md`](ct_compare.md) — P-1, constant-time equality / comparison
- [`ct_select_swap.md`](ct_select_swap.md) — P-2, constant-time conditional select & swap
- [`sha256.md`](sha256.md) — P-3, SHA-256
- [`hmac_sha256.md`](hmac_sha256.md) — P-4, HMAC-SHA-256 and constant-time tag verify

---

## 1. What this project tries to achieve

The goal is to demonstrate **constant-time implementation discipline**: operations that
process secret data are written so their execution time and memory-access pattern do not
depend on secret values, *within the limits of the C++ abstract machine and a reasonable
optimizing compiler* (NFR-1…NFR-3).

Concretely, across the MVP primitives we aim for:

- **No secret-dependent branches** — no `if`, `?:`, short-circuit `&&`/`||`, or
  secret-bounded loop depends on secret data (NFR-2).
- **No secret-dependent memory access** — no array index or memory-access pattern depends
  on secret data (e.g. no secret-indexed table lookups) (NFR-3).
- **OR-accumulated comparison** — equality checks fold all byte differences together and
  reduce **once** at the end, with no early-out on first mismatch.

## 2. Threat model

### 2.1 What is treated as secret

| Primitive | Secret inputs | Public inputs / values |
| --- | --- | --- |
| P-1 `ct::memcmp_mask` / `ct::equal` | the **contents** of both buffers | buffer length, the final match/no-match answer |
| P-1/P-2 scalar helpers (`eq`, `select`, `cswap`, …) | the operand values and the condition/mask | the operand width |
| P-3 SHA-256 | the message bytes, where the caller treats them as secret | the message length, the digest, the padding |
| P-4 HMAC-SHA-256 | the **key** and the internal key pads/state; the `expected_tag` contents in `verify` | key length, message length, tag length, the final verify boolean |

Lengths are **always public** in this library. Loop bounds are derived only from public
lengths. The *decision output* of a comparison (match vs. no-match) is also public — it is
the function's intended return value — but *where* a mismatch occurs is not leaked.

### 2.2 What is in scope (mitigated, best-effort)

- **Timing attacks arising from secret-dependent control flow** at the C++ source level —
  branches and short-circuit evaluation that would otherwise depend on secret bytes.
- **Timing attacks arising from secret-dependent memory indexing** at the source level —
  e.g. SHA-256 indexes its round-constant table only by the public round counter, never by
  message content.

### 2.3 What is explicitly NOT mitigated (out of scope)

These are documented as limitations, not defended against (SRS §6, SCN-1.3):

- **Cache / micro-architectural leakage** — data- and instruction-cache timing, TLB effects,
  prefetcher behavior.
- **Speculative / transient-execution attacks** — Spectre-class and related.
- **Power and electromagnetic (EM) side channels.**
- **Fault-injection attacks.**
- **DVFS / frequency-scaling leakage** (e.g. Hertzbleed-class).
- **Any hardware-specific countermeasure** — no masking against power analysis, no
  enclave/TEE integration.
- **Formal / machine-checked constant-time proofs** — none are provided.

## 3. Inherent limits of source-level C++ constant-time

Constant-time behavior written in portable C++ is **best-effort** and bounded by the
toolchain and hardware (SRS §7 C-4, SCN-2). In particular:

- **The compiler may reintroduce branches.** An optimizer is free to turn a branchless
  masked expression back into a conditional (e.g. a `cmov` *or* a predicted branch), or to
  short-circuit arithmetic it can prove is redundant. The C++ standard gives **no
  constant-time guarantee**.
- **No portable `volatile`/barrier guarantee across the board.** We use a volatile-access +
  compiler-barrier pattern to resist dead-store elimination in `secure_wipe`, but the data
  path of the primitives relies on ordinary arithmetic the compiler may still transform.
- **Stack spills and register pressure.** Secret values may be spilled to the stack; copies
  may linger in registers, caller-saved slots, or spill slots beyond our control.
- **Swap / paging.** Secret-bearing pages may be written to swap by the OS.
- **Standard-library calls.** `std::memcpy` / `std::memset` are used only on **public-length,
  non-secret-position** data (buffer filling, padding, key-pad setup); they are not used to
  make secret-dependent decisions. Their own timing is not assumed constant-time.
- **Compiler/opt-level/hardware variance.** Changing the compiler, its version, the
  optimization level, or the target CPU can change the generated code and therefore the
  timing characteristics. **Constant-time is not guaranteed across these dimensions.**

## 4. Evidence basis — how the property was checked

The constant-time properties were reasoned about and checked by **two methods**, as decided
in the project's resolution of OQ-6 (code review + generated-assembly spot-check; dedicated
tooling such as `dudect`/`ctgrind` was treated as optional and was **not** used):

1. **Code review.** Each primitive was reviewed against NFR-2/NFR-3: no secret-dependent
   branch, no secret-dependent index, equality folded with OR and reduced once.
2. **Generated-assembly spot-check (QA).** QA performed a `-O2 -S` inspection of the
   hot constant-time paths — `ct::memcmp_mask`, `ct::select`, `ct::cswap`, and
   `hmac_sha256_verify` — and confirmed no secret-dependent branches were emitted and that
   HMAC verification routes through `ct::equal`.

### 4.1 Limits of this evidence

This is **spot-check evidence, not a formal proof**:

- It covered specific functions at **one optimization level (`-O2`)** on the project's CI
  compilers (GCC 13.3 and Clang 18.1 on Linux). Other compilers, versions, flags, or targets
  were not inspected and may differ.
- Assembly inspection shows what *that* build emitted; it does not prove the source is
  constant-time for *all* conceivable builds.
- No micro-architectural, statistical-timing, or power/EM measurement was performed.

Treat the "constant-time" claims in this project as **demonstrated intent and inspected
best-effort**, not as an assurance.
