#include "ctcrypto/hmac_sha256.hpp"

#include "ctcrypto/ct.hpp"
#include "ctcrypto/wipe.hpp"

#include <cstring>

namespace ctcrypto {

HmacSha256::HmacSha256(const unsigned char* key, std::size_t key_len) noexcept
    : inner_() {
    reset(key, key_len);
}

void HmacSha256::reset(const unsigned char* key, std::size_t key_len) noexcept {
    // Derive the block-sized key K0 (RFC 2104). Loop bounds depend only on the
    // public key length, never on key byte values.
    unsigned char k0[sha256_block_size];
    std::memset(k0, 0, sizeof(k0));

    if (key_len > sha256_block_size) {
        // Keys longer than the block are hashed to 32 bytes, then zero-padded.
        unsigned char hk[sha256_digest_size];
        sha256(key, key_len, hk);
        std::memcpy(k0, hk, sha256_digest_size);
        secure_wipe(hk, sizeof(hk));
    } else if (key_len > 0) {
        std::memcpy(k0, key, key_len);
    }

    unsigned char i_key_pad[sha256_block_size];
    for (std::size_t i = 0; i < sha256_block_size; ++i) {
        i_key_pad[i] = static_cast<unsigned char>(k0[i] ^ 0x36u);
        o_key_pad_[i] = static_cast<unsigned char>(k0[i] ^ 0x5cu);
    }

    inner_.reset();
    inner_.update(i_key_pad, sha256_block_size);

    secure_wipe(k0, sizeof(k0));
    secure_wipe(i_key_pad, sizeof(i_key_pad));
}

void HmacSha256::update(const unsigned char* data, std::size_t len) noexcept {
    inner_.update(data, len);
}

void HmacSha256::finalize(unsigned char out[hmac_sha256_tag_size]) noexcept {
    unsigned char inner_digest[sha256_digest_size];
    inner_.finalize(inner_digest);

    // outer = SHA-256(o_key_pad || inner_digest)
    Sha256 outer;
    outer.update(o_key_pad_, sha256_block_size);
    outer.update(inner_digest, sha256_digest_size);
    outer.finalize(out);

    secure_wipe(inner_digest, sizeof(inner_digest));
}

hmac_sha256_tag HmacSha256::finalize() noexcept {
    hmac_sha256_tag tag{};
    finalize(tag.data());
    return tag;
}

HmacSha256::~HmacSha256() {
    secure_wipe(o_key_pad_, sizeof(o_key_pad_));
}

hmac_sha256_tag hmac_sha256(const unsigned char* key, std::size_t key_len,
                            const unsigned char* msg, std::size_t msg_len) noexcept {
    HmacSha256 h(key, key_len);
    h.update(msg, msg_len);
    return h.finalize();
}

void hmac_sha256(const unsigned char* key, std::size_t key_len,
                 const unsigned char* msg, std::size_t msg_len,
                 unsigned char out[hmac_sha256_tag_size]) noexcept {
    HmacSha256 h(key, key_len);
    h.update(msg, msg_len);
    h.finalize(out);
}

bool hmac_sha256_verify(const unsigned char* key, std::size_t key_len,
                        const unsigned char* msg, std::size_t msg_len,
                        const unsigned char* expected_tag,
                        std::size_t tag_len) noexcept {
    // The length check is on public data, so a normal branch is fine (FR-7).
    if (tag_len != hmac_sha256_tag_size) {
        return false;
    }

    unsigned char computed[hmac_sha256_tag_size];
    hmac_sha256(key, key_len, msg, msg_len, computed);

    // The value comparison of the 32 tag bytes MUST route through ct::equal —
    // never std::memcmp or a short-circuit loop (FR-7, DESIGN.md §4.4).
    const bool ok = ct::equal(computed, expected_tag, hmac_sha256_tag_size);

    secure_wipe(computed, sizeof(computed));
    return ok;
}

} // namespace ctcrypto
