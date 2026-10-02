#pragma once

// ctcrypto::ct — constant-time branchless building blocks (P-1, P-2).
//
// *** NOT FOR PRODUCTION *** See include/ctcrypto/ctcrypto.hpp for the full disclaimer.
//
// A "mask" is a full-width unsigned integer whose bits are either all-zero (0)
// or all-one (~0). Conditions are represented as masks (not bool) so they can be
// combined with the data path using bitwise ops, with no secret-dependent branch.
//
// All helpers here are header-inline/templated so the optimizer can see the
// branchless idioms and so they are usable in constexpr contexts (DESIGN.md D-4).

#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace ctcrypto::ct {

/// The canonical 32-bit mask/condition type.
using mask32_t = std::uint32_t;

// --- mask construction (branchless) -------------------------------------------------

/// `bit` must be 0 or 1. Returns 0 for 0, all-ones for 1.
template <class U>
constexpr U mask_from_bit(U bit) noexcept {
    static_assert(std::is_unsigned<U>::value, "ct helpers require an unsigned type");
    // 0 - 0 == 0 ; 0 - 1 == all-ones (modular unsigned arithmetic).
    return static_cast<U>(U(0) - (bit & U(1)));
}

/// x != 0 -> all-ones ; x == 0 -> 0.
template <class U>
constexpr U is_nonzero(U x) noexcept {
    static_assert(std::is_unsigned<U>::value, "ct helpers require an unsigned type");
    // (x | -x) has its top bit set iff x != 0; shift it down to a 0/1 bit.
    constexpr unsigned shift = sizeof(U) * 8 - 1;
    const U top = static_cast<U>((x | static_cast<U>(U(0) - x)) >> shift);
    return mask_from_bit<U>(top);
}

/// x == 0 -> all-ones ; x != 0 -> 0.
template <class U>
constexpr U is_zero(U x) noexcept {
    return static_cast<U>(~is_nonzero(x));
}

/// a == b -> all-ones ; a != b -> 0 (scalar constant-time equality, P-1).
template <class U>
constexpr U eq(U a, U b) noexcept {
    return is_zero<U>(static_cast<U>(a ^ b));
}

// --- branchless select / swap (P-2) -------------------------------------------------

/// `mask` must be all-ones or all-zeros. Returns `a` when mask is all-ones, else `b`.
/// Uses the XOR-mask identity: b ^ (mask & (a ^ b)) (DESIGN.md §5.1).
template <class U>
constexpr U select(U mask, U a, U b) noexcept {
    static_assert(std::is_unsigned<U>::value, "ct helpers require an unsigned type");
    return static_cast<U>(b ^ (mask & static_cast<U>(a ^ b)));
}

/// Swap `a` and `b` iff `mask` is all-ones; leave unchanged iff all-zeros. Branch-free.
template <class U>
constexpr void cswap(U mask, U& a, U& b) noexcept {
    static_assert(std::is_unsigned<U>::value, "ct helpers require an unsigned type");
    const U t = static_cast<U>(mask & static_cast<U>(a ^ b));
    a = static_cast<U>(a ^ t);
    b = static_cast<U>(b ^ t);
}

// --- byte-buffer comparison (P-1) ---------------------------------------------------

/// Compares two buffers of equal length `len`. Returns all-ones if every byte
/// matches, 0 otherwise. Timing depends ONLY on `len` (public), never on byte
/// values. Contents of `a` and `b` are treated as SECRET.
///
/// Differences are OR-accumulated across all bytes and reduced to a mask exactly
/// once at the end — there is NO early exit on first mismatch (DESIGN.md §5.1).
inline mask32_t memcmp_mask(const unsigned char* a,
                            const unsigned char* b,
                            std::size_t len) noexcept {
    unsigned char diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff = static_cast<unsigned char>(diff | static_cast<unsigned char>(a[i] ^ b[i]));
    }
    return is_zero<mask32_t>(static_cast<mask32_t>(diff));
}

/// Convenience boolean wrapper around `memcmp_mask`. The returned bool is the
/// intended PUBLIC output (match / no-match); no early exit occurs internally.
inline bool equal(const unsigned char* a,
                  const unsigned char* b,
                  std::size_t len) noexcept {
    return memcmp_mask(a, b, len) != 0;
}

} // namespace ctcrypto::ct
