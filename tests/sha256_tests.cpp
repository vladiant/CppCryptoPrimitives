// Tests for ctcrypto::Sha256 (P-3). Known-answer vectors are from FIPS 180-4 /
// the NIST CSRC SHA-256 examples.

#include "ctcrypto/sha256.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <random>
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

TEST(Sha256Kat, SingleByteA) {
    // NIST CAVP single-byte vector; reference from Python hashlib.
    EXPECT_EQ(hex_of("a"),
              "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
}

TEST(Sha256Kat, SixtyFourZeroBytes) {
    // Exactly one full block of zero bytes — a two-block case after padding.
    std::vector<unsigned char> msg(64, 0x00);
    sha256_digest d = sha256(msg.data(), msg.size());
    EXPECT_EQ(to_hex(d.data(), d.size()),
              "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
}

TEST(Sha256Kat, OneHundredTwentySevenA) {
    // 127 bytes: last byte before the 0x80 pad forces a fresh final block.
    std::vector<unsigned char> msg(127, 'a');
    sha256_digest d = sha256(msg.data(), msg.size());
    EXPECT_EQ(to_hex(d.data(), d.size()),
              "c57e9278af78fa3cab38667bef4ce29d783787a2f731d4e12200270f0c32320a");
}

TEST(Sha256Kat, OneHundredTwentyEightA) {
    // 128 bytes: exactly two blocks, padding spills into a third block.
    std::vector<unsigned char> msg(128, 'a');
    sha256_digest d = sha256(msg.data(), msg.size());
    EXPECT_EQ(to_hex(d.data(), d.size()),
              "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e");
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

TEST(Sha256Randomized, OneShotMatchesRandomlyChunkedStreaming) {
    // Reproducible randomized cross-check (NFR-12): a fixed-seed RNG drives both
    // the message content and the streaming split points, so any failure is
    // deterministically reproducible. Validates one-shot == streaming over many
    // random message lengths and chunkings without an external reference.
    std::mt19937 rng(0xC0FFEEu); // fixed seed (NFR-12)
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<std::size_t> len_dist(0, 600);

    for (int trial = 0; trial < 200; ++trial) {
        const std::size_t len = len_dist(rng);
        std::vector<unsigned char> msg(len);
        for (std::size_t i = 0; i < len; ++i) {
            msg[i] = static_cast<unsigned char>(byte_dist(rng));
        }
        const sha256_digest expected = sha256(msg.data(), msg.size());

        Sha256 h;
        std::size_t off = 0;
        std::uniform_int_distribution<std::size_t> chunk_dist(0, 80);
        while (off < msg.size()) {
            std::size_t take = chunk_dist(rng);
            if (take > msg.size() - off) {
                take = msg.size() - off;
            }
            h.update(msg.data() + off, take);
            off += take;
        }
        const sha256_digest got = h.finalize();
        ASSERT_EQ(got, expected) << "trial=" << trial << " len=" << len;
    }
}

} // namespace
