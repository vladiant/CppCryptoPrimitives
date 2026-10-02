#include "ctcrypto/wipe.hpp"

#include <cstring>

namespace ctcrypto {

// A volatile function pointer to std::memset: the compiler must assume the call
// may have observable side effects and therefore cannot elide it. This is the
// portable fallback mandated by DESIGN.md §5.4.
static void* (*volatile vmemset)(void*, int, std::size_t) = std::memset;

void secure_wipe(void* data, std::size_t len) noexcept {
    if (data == nullptr || len == 0) {
        return;
    }

    // Primary path: write zeros through a volatile byte pointer so the writes
    // are treated as observable and are not optimized away.
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    for (std::size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }

    // Belt-and-braces: a non-elidable memset plus a compiler memory barrier to
    // further discourage dead-store elimination.
    vmemset(data, 0, len);

#if defined(__GNUC__) || defined(__clang__)
    asm volatile("" : : "r"(data) : "memory");
#endif
}

} // namespace ctcrypto
