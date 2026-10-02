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

} // namespace
