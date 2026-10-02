# CppCryptoPrimitives

> ## ⚠️ Educational — NOT for production
>
> **This code is for learning and demonstration only. It is NOT audited, NOT
> hardened, and MUST NOT be used to protect real data or in any production
> system.** Use a vetted, maintained library (e.g. [libsodium](https://libsodium.org),
> [BoringSSL](https://boringssl.googlesource.com/boringssl/), or
> [OpenSSL](https://www.openssl.org)) for real-world cryptography.
>
> Constant-time behavior here is **best-effort only** and is **not guaranteed**
> across compilers, optimization levels, or hardware. See the per-primitive
> side-channel notes for the limitations.

A small, focused C++17 library that implements a few common cryptographic
primitives using **constant-time programming techniques**, built from scratch
with no third-party crypto dependencies. It is a portfolio project that
demonstrates constant-time implementation discipline and side-channel awareness.

## MVP scope

| ID  | Primitive                                            | Header                         |
| --- | ---------------------------------------------------- | ------------------------------ |
| P-1 | Constant-time memory equality / comparison           | `ctcrypto/ct.hpp`              |
| P-2 | Constant-time conditional select & swap              | `ctcrypto/ct.hpp`              |
| P-3 | SHA-256 (one-shot + streaming)                       | `ctcrypto/sha256.hpp`          |
| P-4 | HMAC-SHA-256 (one-shot + streaming + ct verify)      | `ctcrypto/hmac_sha256.hpp`     |
|  —  | Best-effort secret zeroization (`secure_wipe`)       | `ctcrypto/wipe.hpp`            |

The public API lives in namespace `ctcrypto`; the low-level constant-time
helpers live in `ctcrypto::ct`.

## Build & test

Requirements: a C++17 compiler (GCC or Clang) and CMake ≥ 3.16. GoogleTest is
fetched automatically via `FetchContent` (network access is needed on the first
configure).

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Tests are built only when CppCryptoPrimitives is the top-level project
(`CTCRYPTO_BUILD_TESTS` defaults to `PROJECT_IS_TOP_LEVEL`).

## Using the library

Via `add_subdirectory` (vendored / submodule):

```cmake
add_subdirectory(third_party/CppCryptoPrimitives)
target_link_libraries(my_app PRIVATE ctcrypto::ctcrypto)
```

Or via `FetchContent`:

```cmake
include(FetchContent)
FetchContent_Declare(ctcrypto GIT_REPOSITORY <url> GIT_TAG v0.1.0)
FetchContent_MakeAvailable(ctcrypto)
target_link_libraries(my_app PRIVATE ctcrypto::ctcrypto)
```

A consumer pulling the library in does **not** build GoogleTest or the tests.

## Usage snippet

```cpp
#include <ctcrypto/ctcrypto.hpp>

#include <array>
#include <cstring>
#include <string>

int main() {
    using namespace ctcrypto;

    // --- SHA-256 (one-shot) ---
    const std::string msg = "abc";
    sha256_digest digest =
        sha256(reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

    // --- SHA-256 (streaming) ---
    Sha256 h;
    h.update(reinterpret_cast<const unsigned char*>("ab"), 2);
    h.update(reinterpret_cast<const unsigned char*>("c"), 1);
    sha256_digest streamed = h.finalize();

    // --- HMAC-SHA-256 + constant-time verify ---
    const unsigned char key[] = "secret key";
    hmac_sha256_tag tag =
        hmac_sha256(key, sizeof(key) - 1,
                    reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

    bool ok = hmac_sha256_verify(
        key, sizeof(key) - 1,
        reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
        tag.data(), tag.size()); // constant-time comparison

    // --- best-effort zeroization of sensitive material ---
    secure_wipe(tag); // non-guaranteed; see side-channel notes

    (void)digest;
    (void)streamed;
    return ok ? 0 : 1;
}
```

## License

MIT — see [LICENSE](LICENSE).
