cmake_minimum_required(VERSION 3.15)
project(pqc_tcp_example)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Backend selection options
option(USE_OPENSSL_BACKEND "Use OpenSSL as crypto backend" ON)
option(USE_MBEDTLS_BACKEND "Use mbedTLS as crypto backend" ON)
set(CRYPTO_BACKEND_DEFAULT "openssl" CACHE STRING "Default backend: openssl or mbedtls")
option(TEST_MBEDTLS_DEFAULT "Test with mbedTLS as default backend" OFF)

# Configure liboqs build options
set(OQS_MINIMAL_BUILD "" CACHE STRING "Build all algorithms")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library")
set(OQS_DIST_BUILD OFF CACHE BOOL "Disable platform-specific optimizations for portability")
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only liboqs library, no tests or examples")

# Add liboqs subdirectory
add_subdirectory(../../impl/liboqs liboqs)

# Include liboqs headers globally (must be before add_executable)
include_directories(${CMAKE_BINARY_DIR}/liboqs/include)

# Backend-specific configuration
if(USE_OPENSSL_BACKEND)
    find_package(OpenSSL REQUIRED)
    add_definitions(-DUSE_OPENSSL_BACKEND)
    message(STATUS "OpenSSL backend enabled")
endif()

if(USE_MBEDTLS_BACKEND)
    # Configure mbedTLS build options before adding subdirectory
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS programs")
    set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS tests")
    
    # Add mbedTLS subdirectory
    add_subdirectory(../../impl/mbedtls mbedtls)
    
    # Add mbedTLS include directory
    include_directories(../../impl/mbedtls/include)
    
    add_definitions(-DUSE_MBEDTLS_BACKEND)
    message(STATUS "mbedTLS backend enabled")
endif()

# Validate backend selection
if(NOT USE_OPENSSL_BACKEND AND NOT USE_MBEDTLS_BACKEND)
    message(FATAL_ERROR "At least one crypto backend must be enabled")
endif()

# Set default backend
if(TEST_MBEDTLS_DEFAULT AND USE_MBEDTLS_BACKEND)
    add_definitions(-DCRYPTO_BACKEND_DEFAULT_MBEDTLS)
    message(STATUS "Test mode: Default backend set to mbedTLS")
elseif(CRYPTO_BACKEND_DEFAULT STREQUAL "openssl" AND USE_OPENSSL_BACKEND)
    add_definitions(-DCRYPTO_BACKEND_DEFAULT_OPENSSL)
elseif(CRYPTO_BACKEND_DEFAULT STREQUAL "mbedtls" AND USE_MBEDTLS_BACKEND)
    add_definitions(-DCRYPTO_BACKEND_DEFAULT_MBEDTLS)
elseif(USE_OPENSSL_BACKEND)
    add_definitions(-DCRYPTO_BACKEND_DEFAULT_OPENSSL)
    message(STATUS "Default backend set to OpenSSL")
elseif(USE_MBEDTLS_BACKEND)
    add_definitions(-DCRYPTO_BACKEND_DEFAULT_MBEDTLS)
    message(STATUS "Default backend set to mbedTLS")
endif()

# Create server executable
add_executable(server server.c crypto_backend_custom_pqc.c)

# Create client executable
add_executable(client client.c crypto_backend_custom_pqc.c)

# Create test executable
add_executable(test_backends test_backends.c crypto_backend_custom_pqc.c)

# Link liboqs to all executables
target_link_libraries(server oqs)
target_link_libraries(client oqs)
target_link_libraries(test_backends oqs)

# Link crypto backends
if(USE_OPENSSL_BACKEND)
    target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(test_backends OpenSSL::SSL OpenSSL::Crypto)
endif()

if(USE_MBEDTLS_BACKEND)
    target_link_libraries(server mbedtls)
    target_link_libraries(client mbedtls)
    target_link_libraries(test_backends mbedtls)
endif()

# Include liboqs headers for all targets
target_include_directories(server PRIVATE ../../impl/liboqs/src)
target_include_directories(client PRIVATE ../../impl/liboqs/src)
target_include_directories(test_backends PRIVATE ../../impl/liboqs/src)

# Optional: Set output directory
set_target_properties(server client test_backends PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
