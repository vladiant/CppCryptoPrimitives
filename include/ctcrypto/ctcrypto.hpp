#pragma once

// CppCryptoPrimitives — educational, constant-time crypto primitives.
//
// *** NOT FOR PRODUCTION ***
// This library is unaudited, unhardened, and provides best-effort constant-time
// behavior only. It MUST NOT be used to protect real data or in any production
// system. Use a vetted, maintained library (libsodium / BoringSSL / OpenSSL)
// for real-world cryptography. (FR-13)

#include "ctcrypto/ct.hpp"
#include "ctcrypto/wipe.hpp"
#include "ctcrypto/sha256.hpp"
#include "ctcrypto/hmac_sha256.hpp"
