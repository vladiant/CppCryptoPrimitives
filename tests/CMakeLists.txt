include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2)          # pin an exact release tag
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(ctcrypto_tests
    ct_tests.cpp
    sha256_tests.cpp
    hmac_sha256_tests.cpp
    wipe_tests.cpp)

target_link_libraries(ctcrypto_tests PRIVATE
    ctcrypto::ctcrypto
    GTest::gtest_main)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ctcrypto_tests PRIVATE -Wall -Wextra)
endif()

include(GoogleTest)
gtest_discover_tests(ctcrypto_tests)
