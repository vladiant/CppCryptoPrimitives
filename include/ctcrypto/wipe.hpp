#pragma once

// ctcrypto::secure_wipe — best-effort, NON-GUARANTEED secret zeroization.
//
// *** NOT FOR PRODUCTION *** See include/ctcrypto/ctcrypto.hpp for the full disclaimer.

#include <array>
#include <cstddef>

namespace ctcrypto {

/// Best-effort, NON-GUARANTEED secret zeroization. Writes zero bytes to
/// [data, data+len) in a way intended to resist dead-store elimination
/// (volatile access + compiler memory barrier).
///
/// This is NOT a security guarantee: copies left in registers, stack spills,
/// swapped-out pages, etc. are outside the control of a source-level C++
/// implementation. See docs/side-channel/overview.md for the limitations.
///
/// @param data pointer to the buffer to clear (may be null iff len == 0)
/// @param len  number of bytes to clear (public)
void secure_wipe(void* data, std::size_t len) noexcept;

/// Convenience overload: wipe the storage backing a std::array.
template <class T, std::size_t N>
inline void secure_wipe(std::array<T, N>& a) noexcept {
    secure_wipe(a.data(), a.size() * sizeof(T));
}

} // namespace ctcrypto
