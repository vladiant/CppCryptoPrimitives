// Tests for ctcrypto::HmacSha256 (P-4). Known-answer vectors are from RFC 4231.

#include "ctcrypto/hmac_sha256.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace ctcrypto;

std::string to_hex(const unsigned char* data, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0F]);
    }
    return out;
}

std::vector<unsigned char> repeat(unsigned char byte, std::size_t n) {
    return std::vector<unsigned char>(n, byte);
}

std::vector<unsigned char> bytes_of(const std::string& s) {
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::string hmac_hex(const std::vector<unsigned char>& key,
                     const std::vector<unsigned char>& msg) {
    hmac_sha256_tag tag = hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
    return to_hex(tag.data(), tag.size());
}

// --- RFC 4231 known-answer tests -------------------------------------------------

TEST(HmacKat, Rfc4231Case1) {
    EXPECT_EQ(hmac_hex(repeat(0x0b, 20), bytes_of("Hi There")),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HmacKat, Rfc4231Case2) {
    EXPECT_EQ(hmac_hex(bytes_of("Jefe"), bytes_of("what do ya want for nothing?")),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(HmacKat, Rfc4231Case3) {
    EXPECT_EQ(hmac_hex(repeat(0xaa, 20), repeat(0xdd, 50)),
              "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}

TEST(HmacKat, Rfc4231Case4) {
    std::vector<unsigned char> key;
    for (unsigned char b = 0x01; b <= 0x19; ++b) {
        key.push_back(b);
    }
    EXPECT_EQ(hmac_hex(key, repeat(0xcd, 50)),
              "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
}

TEST(HmacKat, Rfc4231Case5Truncation) {
    // We compare the full 32-byte tag; its 128-bit truncation is the RFC's value.
    const std::string full =
        hmac_hex(repeat(0x0c, 20), bytes_of("Test With Truncation"));
    EXPECT_EQ(full.substr(0, 32), "a3b6167473100ee06e0c796c2955552b");
}

TEST(HmacKat, Rfc4231Case6LargerThanBlockKey) {
    EXPECT_EQ(hmac_hex(repeat(0xaa, 131),
                       bytes_of("Test Using Larger Than Block-Size Key - "
                                "Hash Key First")),
              "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

TEST(HmacKat, Rfc4231Case7LargerThanBlockKeyAndData) {
    EXPECT_EQ(
        hmac_hex(repeat(0xaa, 131),
                 bytes_of("This is a test using a larger than block-size key and a "
                          "larger than block-size data. The key needs to be hashed "
                          "before being used by the HMAC algorithm.")),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
}

// --- key-length boundary cases (around the 64-byte block) ------------------------

// Deterministic key generator shared with the independent Python reference
// (bytes (i*7+1) mod 256). Reference tags computed via Python hmac/hashlib.
std::vector<unsigned char> gen_key(std::size_t n) {
    std::vector<unsigned char> k(n);
    for (std::size_t i = 0; i < n; ++i) {
        k[i] = static_cast<unsigned char>((i * 7u + 1u) & 0xFFu);
    }
    return k;
}

const std::vector<unsigned char>& boundary_msg() {
    static const std::vector<unsigned char> m =
        bytes_of("Sample message for keylen=blocklen");
    return m;
}

TEST(HmacKeyBoundary, ShorterThanBlock32) {
    EXPECT_EQ(hmac_hex(gen_key(32), boundary_msg()),
              "965705e520aaf4c224b22076aaf96140430a2cfeebdcdf18a1312fded80e7000");
}

TEST(HmacKeyBoundary, OneByteUnderBlock63) {
    EXPECT_EQ(hmac_hex(gen_key(63), boundary_msg()),
              "98e22702373c7ac147a80fdf055b360026a9aa86a0a34b0f38bc7e7edc23c6c5");
}

TEST(HmacKeyBoundary, ExactlyBlock64) {
    // 64-byte key == block size: used directly as K0, no key hashing (RFC 2104).
    EXPECT_EQ(hmac_hex(gen_key(64), boundary_msg()),
              "6bf4ac0f78d4463cb7915e86d6a11e644ee54a5a6e6e507f13a036c3885d7cbc");
}

TEST(HmacKeyBoundary, OneByteOverBlock65) {
    // 65-byte key > block size: hashed down to 32 bytes first (RFC 2104).
    EXPECT_EQ(hmac_hex(gen_key(65), boundary_msg()),
              "c3e2e10cf7f29bef1daf64e6026289fe9d9b6c294754a8050218823c203afe92");
}

TEST(HmacKeyBoundary, WellOverBlock100) {
    EXPECT_EQ(hmac_hex(gen_key(100), boundary_msg()),
              "6cadb9daaab0dfbee974385ff4502e7c745ab053b07d2e727213ffea36537f59");
}

// --- empty key / empty message edge cases (FR-10) --------------------------------

TEST(HmacEdge, EmptyKeyNonEmptyMessage) {
    EXPECT_EQ(hmac_hex({}, bytes_of("abc")),
              "fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351");
}

TEST(HmacEdge, NonEmptyKeyEmptyMessage) {
    EXPECT_EQ(hmac_hex(bytes_of("key"), {}),
              "5d5d139563c95b5967b9bd9a8c9b233a9dedb45072794cd232dc1b74832607d0");
}

TEST(HmacEdge, EmptyKeyEmptyMessage) {
    EXPECT_EQ(hmac_hex({}, {}),
              "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
}

// --- streaming equivalence -------------------------------------------------------

TEST(HmacStreaming, MatchesOneShotAtManyChunkBoundaries) {
    const std::vector<unsigned char> key = repeat(0x42, 40);
    std::vector<unsigned char> msg(250);
    for (std::size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<unsigned char>((i * 17u + 3u) & 0xFFu);
    }
    hmac_sha256_tag expected =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());

    for (std::size_t chunk : {std::size_t(1), std::size_t(7), std::size_t(63),
                              std::size_t(64), std::size_t(65), std::size_t(128)}) {
        HmacSha256 h(key.data(), key.size());
        std::size_t off = 0;
        while (off < msg.size()) {
            const std::size_t take =
                (msg.size() - off < chunk) ? (msg.size() - off) : chunk;
            h.update(msg.data() + off, take);
            off += take;
        }
        hmac_sha256_tag got = h.finalize();
        EXPECT_EQ(got, expected) << "chunk=" << chunk;
    }
}

TEST(HmacReuse, ResetWithNewKey) {
    HmacSha256 h(repeat(0x0b, 20).data(), 20);
    h.update(reinterpret_cast<const unsigned char*>("Hi There"), 8);
    hmac_sha256_tag first = h.finalize();
    EXPECT_EQ(to_hex(first.data(), first.size()),
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    const std::vector<unsigned char> key2 = bytes_of("Jefe");
    h.reset(key2.data(), key2.size());
    const std::vector<unsigned char> msg2 = bytes_of("what do ya want for nothing?");
    h.update(msg2.data(), msg2.size());
    hmac_sha256_tag second = h.finalize();
    EXPECT_EQ(to_hex(second.data(), second.size()),
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

// --- constant-time verify (FR-7) -------------------------------------------------

TEST(HmacVerify, AcceptsCorrectTag) {
    const std::vector<unsigned char> key = repeat(0x0b, 20);
    const std::vector<unsigned char> msg = bytes_of("Hi There");
    hmac_sha256_tag tag =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
    EXPECT_TRUE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                   tag.data(), tag.size()));
}

TEST(HmacVerify, RejectsEverySingleBitFlip) {
    const std::vector<unsigned char> key = repeat(0x0b, 20);
    const std::vector<unsigned char> msg = bytes_of("Hi There");
    hmac_sha256_tag tag =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());

    for (std::size_t byte = 0; byte < tag.size(); ++byte) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            hmac_sha256_tag bad = tag;
            bad[byte] = static_cast<unsigned char>(bad[byte] ^ (1u << bit));
            EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(),
                                            msg.size(), bad.data(), bad.size()))
                << "byte=" << byte << " bit=" << bit;
        }
    }
}

TEST(HmacVerify, RejectsWrongTagLength) {
    const std::vector<unsigned char> key = repeat(0x0b, 20);
    const std::vector<unsigned char> msg = bytes_of("Hi There");
    hmac_sha256_tag tag =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());

    // Truncated length and over-length are both rejected on the public length check.
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    tag.data(), 16));
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    tag.data(), 31));
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    tag.data(), 33));
}

TEST(HmacVerify, RejectsWrongMessage) {
    const std::vector<unsigned char> key = repeat(0x0b, 20);
    const std::vector<unsigned char> msg = bytes_of("Hi There");
    hmac_sha256_tag tag =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
    const std::vector<unsigned char> wrong = bytes_of("Hi there");
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), wrong.data(),
                                    wrong.size(), tag.data(), tag.size()));
}

TEST(HmacVerify, RejectsDegenerateTamperedTags) {
    const std::vector<unsigned char> key = repeat(0x0b, 20);
    const std::vector<unsigned char> msg = bytes_of("Hi There");
    hmac_sha256_tag correct =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());

    hmac_sha256_tag all_zero{};
    all_zero.fill(0x00);
    hmac_sha256_tag all_ones{};
    all_ones.fill(0xFF);
    // A tag equal to the correct one except its final byte flipped.
    hmac_sha256_tag last_byte_off = correct;
    last_byte_off.back() = static_cast<unsigned char>(last_byte_off.back() ^ 0x01u);

    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    all_zero.data(), all_zero.size()));
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    all_ones.data(), all_ones.size()));
    EXPECT_FALSE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                    last_byte_off.data(), last_byte_off.size()));
}

TEST(HmacVerify, AcceptsCorrectTagWithBlockSizedKey) {
    // Exercise the verify path with a key exactly equal to the block size.
    const std::vector<unsigned char> key = gen_key(64);
    const std::vector<unsigned char> msg = boundary_msg();
    hmac_sha256_tag tag =
        hmac_sha256(key.data(), key.size(), msg.data(), msg.size());
    EXPECT_TRUE(hmac_sha256_verify(key.data(), key.size(), msg.data(), msg.size(),
                                   tag.data(), tag.size()));
}

} // namespace
