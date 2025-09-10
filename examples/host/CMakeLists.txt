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

# Create server executable
add_executable(server server.c)

# Create client executable
add_executable(client client.c)

# Link liboqs to both executables
target_link_libraries(server oqs)
target_link_libraries(client oqs)

# Include liboqs headers
target_include_directories(server PRIVATE ../../impl/liboqs/src)
target_include_directories(client PRIVATE ../../impl/liboqs/src)

# Optional: Set output directory
set_target_properties(server client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
