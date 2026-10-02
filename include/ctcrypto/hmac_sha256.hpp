#pragma once

// ctcrypto::HmacSha256 / ctcrypto::hmac_sha256 — HMAC-SHA-256 (P-4, FR-6/FR-7).
//
// *** NOT FOR PRODUCTION *** See include/ctcrypto/ctcrypto.hpp for the full disclaimer.

#include "ctcrypto/sha256.hpp"

#include <array>
#include <cstddef>

namespace ctcrypto {

inline constexpr std::size_t hmac_sha256_tag_size = sha256_digest_size; // 32
using hmac_sha256_tag = std::array<unsigned char, hmac_sha256_tag_size>;

/// Streaming HMAC-SHA-256 — FR-6. Move-only (DESIGN.md D-5).
class HmacSha256 {
public:
    /// key/key_len: the HMAC key. Key BYTES are SECRET; key_len is public. Any
    /// key length is accepted (keys longer than the block are hashed; shorter
    /// keys are zero-padded), per RFC 2104. `key` may be null iff key_len == 0.
    HmacSha256(const unsigned char* key, std::size_t key_len) noexcept;
    void reset(const unsigned char* key, std::size_t key_len) noexcept;

    void update(const unsigned char* data, std::size_t len) noexcept; // message bytes
    void finalize(unsigned char out[hmac_sha256_tag_size]) noexcept;
    hmac_sha256_tag finalize() noexcept;

    ~HmacSha256(); ///< secure_wipe key pads + inner state

    HmacSha256(HmacSha256&&) noexcept = default;
    HmacSha256& operator=(HmacSha256&&) noexcept = default;
    HmacSha256(const HmacSha256&) = delete;
    HmacSha256& operator=(const HmacSha256&) = delete;

private:
    Sha256        inner_;                        // seeded with ipad
    unsigned char o_key_pad_[sha256_block_size]; // SECRET (key ^ opad)
};

/// One-shot HMAC-SHA-256 tag computation — FR-6.
hmac_sha256_tag hmac_sha256(const unsigned char* key, std::size_t key_len,
                            const unsigned char* msg, std::size_t msg_len) noexcept;
void            hmac_sha256(const unsigned char* key, std::size_t key_len,
                            const unsigned char* msg, std::size_t msg_len,
                            unsigned char out[hmac_sha256_tag_size]) noexcept;

/// Constant-time tag verification — FR-7. Recomputes the tag and compares it
/// against `expected_tag` using ctcrypto::ct::equal. Returns true iff
/// tag_len == 32 AND the tags match. Timing is independent of WHERE a mismatch
/// occurs. `expected_tag` contents are treated as secret; tag_len is public.
bool hmac_sha256_verify(const unsigned char* key, std::size_t key_len,
                        const unsigned char* msg, std::size_t msg_len,
                        const unsigned char* expected_tag,
                        std::size_t tag_len) noexcept;

} // namespace ctcrypto
