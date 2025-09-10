cmake_minimum_required(VERSION 3.15)
project(pqc_tcp_example)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

# Configure liboqs build options
set(OQS_MINIMAL_BUILD "ML-KEM-512" CACHE STRING "Only build ML-KEM-512 algorithm")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build static library")
set(OQS_DIST_BUILD OFF CACHE BOOL "Disable platform-specific optimizations for portability")
set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Build only liboqs library, no tests or examples")

# Add liboqs subdirectory
add_subdirectory(../../impl/liboqs liboqs)

# Find OpenSSL for AES encryption
find_package(OpenSSL REQUIRED)

# Include liboqs headers globally (must be before add_executable)
# Use the generated headers from the build directory
include_directories(${CMAKE_BINARY_DIR}/liboqs/include)

# Include OpenSSL headers globally
include_directories(/usr/include)

# Create server executable
add_executable(server server.c crypto_backend_custom_pqc.c)

# Create client executable
add_executable(client client.c crypto_backend_custom_pqc.c)

# Link liboqs and OpenSSL to both executables
target_link_libraries(server oqs OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(client oqs OpenSSL::SSL OpenSSL::Crypto)

# OpenSSL headers should be included automatically via the imported targets

# Include liboqs headers for all targets (redundant but explicit)
target_include_directories(server PRIVATE ../../impl/liboqs/src)
target_include_directories(client PRIVATE ../../impl/liboqs/src)

# Optional: Set output directory
set_target_properties(server client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
