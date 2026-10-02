// Tests for ctcrypto::secure_wipe. Correctness only — non-elimination of the
// writes cannot be unit-tested and is documented as a known limitation instead.

#include "ctcrypto/wipe.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

using namespace ctcrypto;

TEST(Wipe, ClearsBuffer) {
    std::vector<unsigned char> buf(64, 0xAB);
    secure_wipe(buf.data(), buf.size());
    for (unsigned char b : buf) {
        EXPECT_EQ(b, 0u);
    }
}

TEST(Wipe, ZeroLengthIsNoOp) {
    unsigned char dummy = 0x7F;
    secure_wipe(&dummy, 0);
    EXPECT_EQ(dummy, 0x7F);
}

TEST(Wipe, NullPointerIsSafe) {
    secure_wipe(nullptr, 0);
    SUCCEED();
}

TEST(Wipe, ArrayOverload) {
    std::array<unsigned char, 32> a;
    a.fill(0xFF);
    secure_wipe(a);
    for (unsigned char b : a) {
        EXPECT_EQ(b, 0u);
    }
}

TEST(Wipe, ArrayOverloadNonByteType) {
    std::array<std::uint32_t, 8> a;
    a.fill(0xDEADBEEFu);
    secure_wipe(a);
    for (std::uint32_t v : a) {
        EXPECT_EQ(v, 0u);
    }
}

} // namespace
