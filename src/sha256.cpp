#include "ctcrypto/sha256.hpp"

#include "ctcrypto/wipe.hpp"

#include <cstring>

namespace ctcrypto {
namespace detail {

// SHA-256 round constants (FIPS 180-4 §4.2.2). Indexed only by the public round
// counter t, never by secret data (DESIGN.md §5.2).
static const std::uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

static inline std::uint32_t rotr(std::uint32_t x, unsigned n) noexcept {
    return (x >> n) | (x << (32 - n));
}

// Load a big-endian 32-bit word from four bytes via explicit shift/mask assembly
// (no reinterpret_cast / memcpy punning — DESIGN.md §5.5).
static inline std::uint32_t load_be32(const unsigned char* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           (static_cast<std::uint32_t>(p[3]));
}

// Store a 32-bit word big-endian into four bytes.
static inline void store_be32(unsigned char* p, std::uint32_t v) noexcept {
    p[0] = static_cast<unsigned char>((v >> 24) & 0xffu);
    p[1] = static_cast<unsigned char>((v >> 16) & 0xffu);
    p[2] = static_cast<unsigned char>((v >> 8) & 0xffu);
    p[3] = static_cast<unsigned char>(v & 0xffu);
}

} // namespace detail

Sha256::Sha256() noexcept { reset(); }

void Sha256::reset() noexcept {
    // FIPS 180-4 §5.3.3 initial hash value.
    state_[0] = 0x6a09e667u;
    state_[1] = 0xbb67ae85u;
    state_[2] = 0x3c6ef372u;
    state_[3] = 0xa54ff53au;
    state_[4] = 0x510e527fu;
    state_[5] = 0x9b05688cu;
    state_[6] = 0x1f83d9abu;
    state_[7] = 0x5be0cd19u;
    total_len_ = 0;
    buffer_len_ = 0;
    std::memset(buffer_, 0, sizeof(buffer_));
}

void Sha256::compress(const unsigned char block[sha256_block_size]) noexcept {
    using detail::K;
    using detail::load_be32;
    using detail::rotr;

    std::uint32_t w[64];
    for (unsigned t = 0; t < 16; ++t) {
        w[t] = load_be32(block + t * 4);
    }
    for (unsigned t = 16; t < 64; ++t) {
        const std::uint32_t s0 =
            rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const std::uint32_t s1 =
            rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (unsigned t = 0; t < 64; ++t) {
        const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (static_cast<std::uint32_t>(~e) & g);
        const std::uint32_t temp1 = h + S1 + ch + K[t] + w[t];
        const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;

    // Wipe the per-block schedule which is derived from the message.
    secure_wipe(w, sizeof(w));
}

void Sha256::update(const unsigned char* data, std::size_t len) noexcept {
    if (len == 0) {
        return;
    }

    total_len_ += len;

    // Fill an existing partial block first.
    if (buffer_len_ > 0) {
        const std::size_t need = sha256_block_size - buffer_len_;
        const std::size_t take = (len < need) ? len : need;
        std::memcpy(buffer_ + buffer_len_, data, take);
        buffer_len_ += take;
        data += take;
        len -= take;
        if (buffer_len_ == sha256_block_size) {
            compress(buffer_);
            buffer_len_ = 0;
        }
    }

    // Consume whole blocks directly from the input.
    while (len >= sha256_block_size) {
        compress(data);
        data += sha256_block_size;
        len -= sha256_block_size;
    }

    // Stash the remainder.
    if (len > 0) {
        std::memcpy(buffer_, data, len);
        buffer_len_ = len;
    }
}

void Sha256::finalize(unsigned char out[sha256_digest_size]) noexcept {
    // Message bit length before padding (FIPS 180-4 §5.1.1).
    const std::uint64_t bit_len = total_len_ * 8u;

    // Append the 0x80 padding byte.
    unsigned char pad = 0x80;
    update(&pad, 1);

    // Append zero bytes until the buffer length is 56 mod 64, leaving room for
    // the 64-bit length field.
    unsigned char zero = 0x00;
    while (buffer_len_ != sha256_block_size - 8) {
        update(&zero, 1);
    }

    // Append the 64-bit big-endian bit length and compress the final block.
    unsigned char len_be[8];
    for (unsigned i = 0; i < 8; ++i) {
        len_be[i] = static_cast<unsigned char>((bit_len >> (56 - 8 * i)) & 0xffu);
    }
    std::memcpy(buffer_ + buffer_len_, len_be, 8);
    compress(buffer_);
    buffer_len_ = sha256_block_size; // marks the buffer as fully consumed

    for (unsigned i = 0; i < 8; ++i) {
        detail::store_be32(out + i * 4, state_[i]);
    }

    // Clear the internal state after producing the digest (best-effort).
    secure_wipe(state_, sizeof(state_));
    secure_wipe(buffer_, sizeof(buffer_));
    total_len_ = 0;
    buffer_len_ = 0;
}

sha256_digest Sha256::finalize() noexcept {
    sha256_digest d{};
    finalize(d.data());
    return d;
}

Sha256::~Sha256() {
    secure_wipe(state_, sizeof(state_));
    secure_wipe(buffer_, sizeof(buffer_));
}

sha256_digest sha256(const unsigned char* data, std::size_t len) noexcept {
    Sha256 h;
    h.update(data, len);
    return h.finalize();
}

void sha256(const unsigned char* data, std::size_t len,
            unsigned char out[sha256_digest_size]) noexcept {
    Sha256 h;
    h.update(data, len);
    h.finalize(out);
}

} // namespace ctcrypto
