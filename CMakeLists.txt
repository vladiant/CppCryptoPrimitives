cmake_minimum_required(VERSION 3.16)
project(ctcrypto LANGUAGES CXX VERSION 0.1.0)

# PROJECT_IS_TOP_LEVEL is only defined by CMake >= 3.21. Provide a fallback so
# the >= 3.16 minimum still behaves correctly (defaults tests on when top-level).
if (NOT DEFINED PROJECT_IS_TOP_LEVEL)
    if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
        set(PROJECT_IS_TOP_LEVEL ON)
    else()
        set(PROJECT_IS_TOP_LEVEL OFF)
    endif()
endif()

# Only build tests when this is the top-level project (friendly to add_subdirectory).
option(CTCRYPTO_BUILD_TESTS "Build ctcrypto unit tests" ${PROJECT_IS_TOP_LEVEL})

add_library(ctcrypto
    src/sha256.cpp
    src/hmac_sha256.cpp
    src/wipe.cpp)
add_library(ctcrypto::ctcrypto ALIAS ctcrypto)      # canonical linkable name

target_include_directories(ctcrypto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

target_compile_features(ctcrypto PUBLIC cxx_std_17)

# Warning-clean requirement (NFR-4) — apply only to our own target, not consumers.
if (CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ctcrypto PRIVATE -Wall -Wextra)
endif()

if (CTCRYPTO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
