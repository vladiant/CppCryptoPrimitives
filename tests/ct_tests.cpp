// Tests for ctcrypto::ct constant-time building blocks (P-1, P-2).

#include "ctcrypto/ct.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <random>
#include <vector>

namespace {

using namespace ctcrypto;

constexpr std::uint32_t kAllOnes32 = ~std::uint32_t(0);

TEST(CtMask, MaskFromBit) {
    EXPECT_EQ(ct::mask_from_bit<std::uint32_t>(0), 0u);
    EXPECT_EQ(ct::mask_from_bit<std::uint32_t>(1), kAllOnes32);
    EXPECT_EQ(ct::mask_from_bit<std::uint8_t>(0), 0u);
    EXPECT_EQ(ct::mask_from_bit<std::uint8_t>(1),
              static_cast<std::uint8_t>(0xFFu));
}

TEST(CtMask, IsZeroIsNonzero) {
    EXPECT_EQ(ct::is_zero<std::uint32_t>(0), kAllOnes32);
    EXPECT_EQ(ct::is_nonzero<std::uint32_t>(0), 0u);
    for (std::uint32_t x : {1u, 2u, 0x80000000u, 0xFFFFFFFFu, 12345u}) {
        EXPECT_EQ(ct::is_zero<std::uint32_t>(x), 0u) << "x=" << x;
        EXPECT_EQ(ct::is_nonzero<std::uint32_t>(x), kAllOnes32) << "x=" << x;
    }
}

TEST(CtMask, IsZeroExhaustive8Bit) {
    for (unsigned v = 0; v < 256; ++v) {
        const auto x = static_cast<std::uint8_t>(v);
        const std::uint8_t expect_zero = (v == 0) ? 0xFFu : 0x00u;
        EXPECT_EQ(ct::is_zero<std::uint8_t>(x), expect_zero) << "v=" << v;
        EXPECT_EQ(ct::is_nonzero<std::uint8_t>(x),
                  static_cast<std::uint8_t>(~expect_zero))
            << "v=" << v;
    }
}

TEST(CtEq, TruthTableExhaustive8Bit) {
    for (unsigned a = 0; a < 256; ++a) {
        for (unsigned b = 0; b < 256; ++b) {
            const std::uint8_t m =
                ct::eq<std::uint8_t>(static_cast<std::uint8_t>(a),
                                     static_cast<std::uint8_t>(b));
            const std::uint8_t expect = (a == b) ? 0xFFu : 0x00u;
            ASSERT_EQ(m, expect) << "a=" << a << " b=" << b;
        }
    }
}

TEST(CtSelect, MatchesReferenceExhaustive8Bit) {
    for (unsigned a = 0; a < 256; ++a) {
        for (unsigned b = 0; b < 256; ++b) {
            const auto ua = static_cast<std::uint8_t>(a);
            const auto ub = static_cast<std::uint8_t>(b);
            EXPECT_EQ(ct::select<std::uint8_t>(0xFFu, ua, ub), ua);
            EXPECT_EQ(ct::select<std::uint8_t>(0x00u, ua, ub), ub);
        }
    }
}

TEST(CtSelect, MatchesReferenceRandom32) {
    std::mt19937 rng(12345); // fixed seed (NFR-12)
    std::uniform_int_distribution<std::uint32_t> dist;
    for (int i = 0; i < 10000; ++i) {
        const std::uint32_t a = dist(rng);
        const std::uint32_t b = dist(rng);
        const bool cond = (dist(rng) & 1u) != 0;
        const std::uint32_t mask = cond ? kAllOnes32 : 0u;
        const std::uint32_t ref = cond ? a : b;
        ASSERT_EQ(ct::select<std::uint32_t>(mask, a, b), ref);
    }
}

TEST(CtCswap, MatchesReferenceRandom32) {
    std::mt19937 rng(67890); // fixed seed (NFR-12)
    std::uniform_int_distribution<std::uint32_t> dist;
    for (int i = 0; i < 10000; ++i) {
        std::uint32_t a = dist(rng);
        std::uint32_t b = dist(rng);
        const std::uint32_t orig_a = a;
        const std::uint32_t orig_b = b;
        const bool cond = (dist(rng) & 1u) != 0;
        const std::uint32_t mask = cond ? kAllOnes32 : 0u;

        ct::cswap<std::uint32_t>(mask, a, b);
        if (cond) {
            ASSERT_EQ(a, orig_b);
            ASSERT_EQ(b, orig_a);
        } else {
            ASSERT_EQ(a, orig_a);
            ASSERT_EQ(b, orig_b);
        }
    }
}

TEST(CtMemcmp, EqualBuffers) {
    const std::vector<unsigned char> a = {1, 2, 3, 4, 5};
    const std::vector<unsigned char> b = a;
    EXPECT_EQ(ct::memcmp_mask(a.data(), b.data(), a.size()), kAllOnes32);
    EXPECT_TRUE(ct::equal(a.data(), b.data(), a.size()));
}

TEST(CtMemcmp, EmptyBuffersAreEqual) {
    EXPECT_EQ(ct::memcmp_mask(nullptr, nullptr, 0), kAllOnes32);
    EXPECT_TRUE(ct::equal(nullptr, nullptr, 0));
}

TEST(CtMemcmp, SingleByteDifferenceAtEachPosition) {
    std::vector<unsigned char> a(16);
    for (std::size_t i = 0; i < a.size(); ++i) {
        a[i] = static_cast<unsigned char>(i);
    }
    for (std::size_t pos = 0; pos < a.size(); ++pos) {
        std::vector<unsigned char> b = a;
        b[pos] ^= 0x01u; // flip one bit at this position
        EXPECT_EQ(ct::memcmp_mask(a.data(), b.data(), a.size()), 0u)
            << "pos=" << pos;
        EXPECT_FALSE(ct::equal(a.data(), b.data(), a.size())) << "pos=" << pos;
    }
}

TEST(CtMemcmp, EquivalentToStdMemcmpResult) {
    std::mt19937 rng(246810); // fixed seed (NFR-12)
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<std::size_t> len_dist(0, 64);
    for (int i = 0; i < 2000; ++i) {
        const std::size_t len = len_dist(rng);
        std::vector<unsigned char> a(len), b(len);
        for (std::size_t j = 0; j < len; ++j) {
            a[j] = static_cast<unsigned char>(byte_dist(rng));
            b[j] = static_cast<unsigned char>(byte_dist(rng));
        }
        const bool ref =
            (len == 0) ||
            (std::memcmp(a.data(), b.data(), len) == 0); // value equivalence only
        ASSERT_EQ(ct::equal(a.data(), b.data(), len), ref) << "len=" << len;
    }
}

TEST(CtMemcmp, MaskIsExactlyZeroOrAllOnes) {
    const std::vector<unsigned char> a = {0xAA, 0xBB, 0xCC};
    std::vector<unsigned char> b = a;
    EXPECT_EQ(ct::memcmp_mask(a.data(), b.data(), a.size()), kAllOnes32);
    b[1] ^= 0xFFu;
    EXPECT_EQ(ct::memcmp_mask(a.data(), b.data(), a.size()), 0u);
}

} // namespace
