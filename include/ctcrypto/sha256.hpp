#pragma once

// ctcrypto::Sha256 / ctcrypto::sha256 — SHA-256 (P-3, FR-4/FR-5).
//
// *** NOT FOR PRODUCTION *** See include/ctcrypto/ctcrypto.hpp for the full disclaimer.

#include <array>
#include <cstddef>
#include <cstdint>

namespace ctcrypto {

inline constexpr std::size_t sha256_digest_size = 32; // bytes
inline constexpr std::size_t sha256_block_size  = 64; // bytes

using sha256_digest = std::array<unsigned char, sha256_digest_size>;

/// Incremental (streaming) SHA-256 — FR-5. Move-only (DESIGN.md D-5).
class Sha256 {
public:
    Sha256() noexcept;          ///< init to the FIPS 180-4 IV
    void reset() noexcept;      ///< re-init for reuse

    /// Absorb `len` message bytes. May be called repeatedly. `data` may be null
    /// iff `len == 0`. Loop bounds depend only on the public length.
    void update(const unsigned char* data, std::size_t len) noexcept;

    /// Produce the 32-byte digest. `out` must point to >= 32 writable bytes.
    /// After finalize the object must be reset() before reuse.
    void finalize(unsigned char out[sha256_digest_size]) noexcept;
    sha256_digest finalize() noexcept;

    ~Sha256(); ///< secure_wipe internal state

    // Movable but not copyable (holds mutable hashing state).
    Sha256(Sha256&&) noexcept = default;
    Sha256& operator=(Sha256&&) noexcept = default;
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;

private:
    void compress(const unsigned char block[sha256_block_size]) noexcept;

    std::uint32_t state_[8];                  // H0..H7
    unsigned char buffer_[sha256_block_size]; // partial block
    std::uint64_t total_len_;                 // total message length in bytes
    std::size_t   buffer_len_;                // bytes currently in buffer_
};

/// One-shot SHA-256 — FR-4.
sha256_digest sha256(const unsigned char* data, std::size_t len) noexcept;
void          sha256(const unsigned char* data, std::size_t len,
                     unsigned char out[sha256_digest_size]) noexcept;

} // namespace ctcrypto
