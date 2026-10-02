// Tests for ctcrypto::Sha256 (P-3). Known-answer vectors are from FIPS 180-4 /
// the NIST CSRC SHA-256 examples.

#include "ctcrypto/sha256.hpp"

#include <gtest/gtest.h>

#include <array>
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

std::string hex_of(const std::string& msg) {
    const auto* p = reinterpret_cast<const unsigned char*>(msg.data());
    sha256_digest d = sha256(p, msg.size());
    return to_hex(d.data(), d.size());
}

TEST(Sha256Kat, EmptyString) {
    EXPECT_EQ(hex_of(""),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256Kat, Abc) {
    EXPECT_EQ(hex_of("abc"),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256Kat, FiftySixByteBoundary) {
    // 448-bit message (56 bytes) — straddles the one/two-block padding boundary.
    EXPECT_EQ(hex_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256Kat, EightNineSixBitMessage) {
    // 896-bit message (112 bytes) — spans two blocks.
    EXPECT_EQ(
        hex_of("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
               "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
}

TEST(Sha256Kat, OneMillionA) {
    std::vector<unsigned char> msg(1000000, 'a');
    sha256_digest d = sha256(msg.data(), msg.size());
    EXPECT_EQ(to_hex(d.data(), d.size()),
              "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(Sha256OneShot, OutBufferFormMatchesArrayForm) {
    const std::string msg = "The quick brown fox jumps over the lazy dog";
    const auto* p = reinterpret_cast<const unsigned char*>(msg.data());
    unsigned char out[sha256_digest_size];
    sha256(p, msg.size(), out);
    sha256_digest d = sha256(p, msg.size());
    EXPECT_EQ(to_hex(out, sha256_digest_size), to_hex(d.data(), d.size()));
    EXPECT_EQ(to_hex(d.data(), d.size()),
              "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
}

TEST(Sha256Streaming, MatchesOneShotAtManyChunkBoundaries) {
    // Build a deterministic message longer than several blocks.
    std::vector<unsigned char> msg(300);
    for (std::size_t i = 0; i < msg.size(); ++i) {
        msg[i] = static_cast<unsigned char>((i * 31u + 7u) & 0xFFu);
    }
    sha256_digest expected = sha256(msg.data(), msg.size());

    for (std::size_t chunk : {std::size_t(1), std::size_t(2), std::size_t(3),
                              std::size_t(63), std::size_t(64), std::size_t(65),
                              std::size_t(127), std::size_t(128)}) {
        Sha256 h;
        std::size_t off = 0;
        while (off < msg.size()) {
            const std::size_t take =
                (msg.size() - off < chunk) ? (msg.size() - off) : chunk;
            h.update(msg.data() + off, take);
            off += take;
        }
        sha256_digest got = h.finalize();
        EXPECT_EQ(got, expected) << "chunk=" << chunk;
    }
}

TEST(Sha256Streaming, ZeroLengthUpdatesAreNoOps) {
    const std::string msg = "abc";
    const auto* p = reinterpret_cast<const unsigned char*>(msg.data());
    Sha256 h;
    h.update(nullptr, 0);
    h.update(p, 1);
    h.update(nullptr, 0);
    h.update(p + 1, 2);
    h.update(nullptr, 0);
    sha256_digest got = h.finalize();
    EXPECT_EQ(to_hex(got.data(), got.size()),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256PaddingEdges, Lengths55To65) {
    // Inputs straddling the 55/56/64-byte padding boundaries (FR-10). Validate
    // streaming equals one-shot for each length.
    for (std::size_t len = 50; len <= 70; ++len) {
        std::vector<unsigned char> msg(len);
        for (std::size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<unsigned char>('A' + (i % 26));
        }
        sha256_digest one = sha256(msg.data(), msg.size());

        Sha256 h;
        for (std::size_t i = 0; i < len; ++i) {
            h.update(msg.data() + i, 1); // one byte at a time
        }
        sha256_digest streamed = h.finalize();
        EXPECT_EQ(one, streamed) << "len=" << len;
    }
}

TEST(Sha256Reuse, ResetAllowsReuse) {
    Sha256 h;
    const std::string a = "abc";
    h.update(reinterpret_cast<const unsigned char*>(a.data()), a.size());
    sha256_digest first = h.finalize();

    h.reset();
    h.update(reinterpret_cast<const unsigned char*>(a.data()), a.size());
    sha256_digest second = h.finalize();
    EXPECT_EQ(first, second);
}

} // namespace
