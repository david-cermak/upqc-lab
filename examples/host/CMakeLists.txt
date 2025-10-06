cmake_minimum_required(VERSION 3.15)
project(pqc_tcp_example)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Backend selection options (exactly one must be ON)
option(USE_OPENSSL_BACKEND "Use OpenSSL as crypto backend" ON)
option(USE_MBEDTLS_BACKEND "Use mbedTLS as crypto backend" OFF)

# KEM parameter selection (shared with target)
set(UPQC_KEM_LEVEL "512" CACHE STRING "Select ML-KEM parameter set: 512 or 768")
set_property(CACHE UPQC_KEM_LEVEL PROPERTY STRINGS 512 768)

# Configure liboqs build options
# Restrict to the selected ML-KEM to reduce build time
if(UPQC_KEM_LEVEL STREQUAL "768")
    set(OQS_MINIMAL_BUILD "ML-KEM-768" CACHE STRING "Only build selected ML-KEM algorithm")
else()
    set(OQS_MINIMAL_BUILD "ML-KEM-512" CACHE STRING "Only build selected ML-KEM algorithm")
endif()
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library")
set(OQS_DIST_BUILD OFF CACHE BOOL "Disable platform-specific optimizations for portability")
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only liboqs library, no tests or examples")

# Add liboqs subdirectory
add_subdirectory(../../impl/liboqs liboqs)

# Include liboqs headers globally (must be before add_executable)
include_directories(${CMAKE_BINARY_DIR}/liboqs/include)
# Include shared config header
include_directories(../shared)

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
if((USE_OPENSSL_BACKEND AND USE_MBEDTLS_BACKEND) OR (NOT USE_OPENSSL_BACKEND AND NOT USE_MBEDTLS_BACKEND))
    message(FATAL_ERROR "Select exactly one backend: -DUSE_OPENSSL_BACKEND=ON -DUSE_MBEDTLS_BACKEND=OFF or vice versa")
endif()

# Create server executable
add_executable(server server.c crypto_backend_custom_pqc.c)

# Create client executable
add_executable(client client.c crypto_backend_custom_pqc.c)

# Create test executable
# add_executable(test_backends test_backends.c crypto_backend_custom_pqc.c)

# Link liboqs to all executables
target_link_libraries(server oqs)
target_link_libraries(client oqs)
# target_link_libraries(test_backends oqs)

# Backend-specific sources and linking
if(USE_OPENSSL_BACKEND)
    target_sources(server PRIVATE crypto_primitives_openssl.c)
    target_sources(client PRIVATE crypto_primitives_openssl.c)
    target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)
elseif(USE_MBEDTLS_BACKEND)
    target_sources(server PRIVATE crypto_primitives_mbedtls.c)
    target_sources(client PRIVATE crypto_primitives_mbedtls.c)
    target_link_libraries(server mbedtls)
    target_link_libraries(client mbedtls)
endif()

# Include liboqs headers for all targets
target_include_directories(server PRIVATE ../../impl/liboqs/src)
target_include_directories(client PRIVATE ../../impl/liboqs/src)
# target_include_directories(test_backends PRIVATE ../../impl/liboqs/src)

# Propagate selected KEM level to sources
target_compile_definitions(server PRIVATE UPQC_KEM_LEVEL=${UPQC_KEM_LEVEL})
target_compile_definitions(client PRIVATE UPQC_KEM_LEVEL=${UPQC_KEM_LEVEL})

# Optional: Set output directory
set_target_properties(server client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
