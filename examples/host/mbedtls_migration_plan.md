# Dual Backend Migration Plan: OpenSSL + mbedTLS Support

## Overview

This document outlines the comprehensive plan for adding mbedTLS as an alternative cryptographic backend alongside the existing OpenSSL implementation. The current implementation uses OpenSSL for AES-256-GCM encryption, HKDF key derivation, and random number generation, while using liboqs for ML-KEM-512 post-quantum key exchange. This plan adds mbedTLS as a configurable alternative backend, allowing users to choose between system OpenSSL or mbedTLS submodule.

## Current OpenSSL Usage Analysis

### OpenSSL Components Used
1. **HKDF Key Derivation** (`derive_aes_key()`)
   - Uses `EVP_KDF` interface with SHA-256
   - Parameters: shared secret, salt, info string
   - Output: 32-byte AES key

2. **AES-256-GCM Encryption** (`encrypt_data()`)
   - Uses `EVP_CIPHER_CTX` with `EVP_aes_256_gcm()`
   - Features: Random IV generation, AAD (sequence numbers), authentication tags
   - Message format: `[IV][Encrypted Data][Tag]`

3. **AES-256-GCM Decryption** (`decrypt_data()`)
   - Uses `EVP_CIPHER_CTX` with `EVP_aes_256_gcm()`
   - Features: IV extraction, AAD verification, tag authentication

4. **Random Number Generation**
   - Uses `RAND_bytes()` for IV generation

### Files Requiring Changes
- `crypto_backend_custom_pqc.c` - Main implementation file
- `CMakeLists.txt` - Build configuration
- `crypto_backend.h` - Interface definitions (minor updates)

## Dual Backend Strategy

### Backend Selection Approach

The implementation will support both OpenSSL and mbedTLS backends with the following selection mechanisms:

1. **Compile-time Selection**: Choose backend at build time via CMake options
2. **Runtime Selection**: Choose backend at runtime via configuration
3. **Fallback Mechanism**: Automatic fallback if preferred backend fails

### Backend Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  (server.c / client.c - business logic)                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Crypto Backend Interface                     │
│  - derive_aes_key() / encrypt_data() / decrypt_data()      │
│  - Backend-agnostic API                                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Backend Selection Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   OpenSSL       │  │   mbedTLS       │  │   Future    │ │
│  │   Backend       │  │   Backend       │  │   Backends  │ │
│  │   (System)      │  │   (Submodule)   │  │             │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Backend-Specific Implementation                │
│  - OpenSSL: EVP_KDF, EVP_CIPHER_CTX, RAND_bytes            │
│  - mbedTLS: mbedtls_hkdf, mbedtls_cipher_*, ctr_drbg       │
└─────────────────────────────────────────────────────────────┘
```

## Implementation Strategy

### Phase 1: Backend Abstraction Layer

#### 1.1 Add mbedTLS as Submodule
```bash
# Navigate to project root
cd /home/david/repos/upqc-lab

# Add mbedTLS as submodule in impl folder
git submodule add https://github.com/Mbed-TLS/mbedtls.git impl/mbedtls

# Initialize and update submodule
git submodule update --init --recursive

# Commit the changes
git add .gitmodules impl/mbedtls
git commit -m "Add mbedTLS as submodule in impl folder"
```

#### 1.2 Update Build System with Dual Backend Support
**File: `examples/host/CMakeLists.txt`**

```cmake
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
option(CRYPTO_BACKEND_DEFAULT "Default crypto backend" "openssl" CACHE STRING "Default backend: openssl or mbedtls")

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
    # Add mbedTLS subdirectory
    add_subdirectory(../../impl/mbedtls mbedtls)
    
    # Configure mbedTLS build options
    set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls_config.h" CACHE STRING "Custom mbedTLS config file")
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Disable mbedTLS programs")
    set(ENABLE_TESTING OFF CACHE BOOL "Disable mbedTLS tests")
    
    # Include mbedTLS headers
    include_directories(${CMAKE_BINARY_DIR}/mbedtls/include)
    add_definitions(-DUSE_MBEDTLS_BACKEND)
    message(STATUS "mbedTLS backend enabled")
endif()

# Validate backend selection
if(NOT USE_OPENSSL_BACKEND AND NOT USE_MBEDTLS_BACKEND)
    message(FATAL_ERROR "At least one crypto backend must be enabled")
endif()

# Set default backend
if(CRYPTO_BACKEND_DEFAULT STREQUAL "openssl" AND USE_OPENSSL_BACKEND)
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

# Link liboqs to both executables
target_link_libraries(server oqs)
target_link_libraries(client oqs)

# Link crypto backends
if(USE_OPENSSL_BACKEND)
    target_link_libraries(server OpenSSL::SSL OpenSSL::Crypto)
    target_link_libraries(client OpenSSL::SSL OpenSSL::Crypto)
endif()

if(USE_MBEDTLS_BACKEND)
    target_link_libraries(server mbedtls mbedcrypto mbedx509)
    target_link_libraries(client mbedtls mbedcrypto mbedx509)
endif()

# Include liboqs headers for all targets
target_include_directories(server PRIVATE ../../impl/liboqs/src)
target_include_directories(client PRIVATE ../../impl/liboqs/src)

# Optional: Set output directory
set_target_properties(server client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
```

#### 1.3 Create mbedTLS Configuration File
**File: `examples/host/mbedtls_config.h`**

```c
#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* System support */
#define MBEDTLS_HAVE_ASM
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* mbed TLS feature support */
#define MBEDTLS_CIPHER_MODE_CBC
#define MBEDTLS_CIPHER_MODE_CFB
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_OFB
#define MBEDTLS_CIPHER_MODE_XTS
#define MBEDTLS_CIPHER_PADDING_PKCS7
#define MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS
#define MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN
#define MBEDTLS_CIPHER_PADDING_ZEROS

/* mbed TLS modules */
#define MBEDTLS_AES_C
#define MBEDTLS_AESNI_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_GCM_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA512_C

/* mbed TLS modules to disable */
#undef MBEDTLS_SSL_TLS_C
#undef MBEDTLS_X509_CRT_PARSE_C
#undef MBEDTLS_X509_CSR_PARSE_C
#undef MBEDTLS_X509_CREATE_C
#undef MBEDTLS_X509_CRL_PARSE_C
#undef MBEDTLS_X509_CRT_WRITE_C
#undef MBEDTLS_X509_CSR_WRITE_C

/* mbed TLS constants */
#define MBEDTLS_ENTROPY_MAX_SOURCES 2
#define MBEDTLS_ENTROPY_MAX_GATHER 128
#define MBEDTLS_CTR_DRBG_MAX_REQUEST 1024
#define MBEDTLS_CTR_DRBG_MAX_INPUT 256
#define MBEDTLS_CTR_DRBG_MAX_SEED_INPUT 384
#define MBEDTLS_CTR_DRBG_MAX_PERSONALIZATION_STRING_LEN 32

/* mbed TLS platform */
#define MBEDTLS_PLATFORM_STD_SNPRINTF snprintf
#define MBEDTLS_PLATFORM_STD_PRINTF printf
#define MBEDTLS_PLATFORM_STD_FPRINTF fprintf

#include "mbedtls/check_config.h"

#endif /* MBEDTLS_CONFIG_H */
```

### Phase 2: Backend Abstraction Layer

#### 2.1 Update Header File
**File: `crypto_backend.h`**

```c
#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// Backend types
typedef enum {
    CRYPTO_BACKEND_CUSTOM_PQC,
    CRYPTO_BACKEND_MBEDTLS,
    CRYPTO_BACKEND_OPENSSL
} crypto_backend_t;

// Crypto operation backend types
typedef enum {
    CRYPTO_OP_BACKEND_OPENSSL,
    CRYPTO_OP_BACKEND_MBEDTLS
} crypto_op_backend_t;

// Error codes
typedef enum {
    CRYPTO_SUCCESS = 0,
    CRYPTO_ERROR_INVALID_PARAM = -1,
    CRYPTO_ERROR_INIT_FAILED = -2,
    CRYPTO_ERROR_HANDSHAKE_FAILED = -3,
    CRYPTO_ERROR_SEND_FAILED = -4,
    CRYPTO_ERROR_RECV_FAILED = -5,
    CRYPTO_ERROR_ENCRYPT_FAILED = -6,
    CRYPTO_ERROR_DECRYPT_FAILED = -7,
    CRYPTO_ERROR_NOT_INITIALIZED = -8,
    CRYPTO_ERROR_HANDSHAKE_NOT_COMPLETE = -9,
    CRYPTO_ERROR_BACKEND_NOT_AVAILABLE = -10
} crypto_error_t;

// Main crypto context structure
typedef struct crypto_context {
    crypto_backend_t backend;
    crypto_op_backend_t op_backend;  // Backend for crypto operations (HKDF, AES, etc.)
    void *backend_ctx;  // Backend-specific context
    int socket_fd;
    bool handshake_complete;
    uint8_t *shared_secret;
    size_t shared_secret_len;
    uint32_t sequence_number;  // For replay protection
} crypto_context_t;

// Core interface functions
crypto_error_t crypto_init(crypto_context_t *ctx, crypto_backend_t backend, int socket_fd);
crypto_error_t crypto_set_operation_backend(crypto_context_t *ctx, crypto_op_backend_t op_backend);
crypto_error_t crypto_handshake_server(crypto_context_t *ctx);
crypto_error_t crypto_handshake_client(crypto_context_t *ctx);
crypto_error_t crypto_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len);
crypto_error_t crypto_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len);
crypto_error_t crypto_cleanup(crypto_context_t *ctx);

// Utility functions
const char* crypto_error_string(crypto_error_t error);
bool crypto_is_handshake_complete(crypto_context_t *ctx);
crypto_op_backend_t crypto_get_available_backends(void);

// Backend-specific functions (for future TLS backends)
crypto_error_t crypto_backend_custom_pqc_init(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_handshake_server(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_handshake_client(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len);
crypto_error_t crypto_backend_custom_pqc_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len);
crypto_error_t crypto_backend_custom_pqc_cleanup(crypto_context_t *ctx);

#endif // CRYPTO_BACKEND_H
```

#### 2.2 Update Header Includes with Conditional Compilation
**File: `crypto_backend_custom_pqc.c`**

```c
#include "crypto_backend.h"
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>

// Conditional includes based on available backends
#ifdef USE_OPENSSL_BACKEND
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif

#ifdef USE_MBEDTLS_BACKEND
#include <mbedtls/cipher.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform.h>
#endif

// Default backend selection
#ifndef CRYPTO_BACKEND_DEFAULT_OPENSSL
#ifndef CRYPTO_BACKEND_DEFAULT_MBEDTLS
#ifdef USE_OPENSSL_BACKEND
#define CRYPTO_BACKEND_DEFAULT_OPENSSL
#elif defined(USE_MBEDTLS_BACKEND)
#define CRYPTO_BACKEND_DEFAULT_MBEDTLS
#endif
#endif
#endif
```

#### 2.3 Dual Backend HKDF Implementation
**Function: `derive_aes_key()`**

```c
// OpenSSL HKDF implementation
#ifdef USE_OPENSSL_BACKEND
static crypto_error_t derive_aes_key_openssl(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    const char *info = "PQC-TCP-AES-KEY";
    const uint8_t *salt = (const uint8_t *)"PQC-TCP-SALT";
    
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;
    int ret = 0;
    
    // Fetch the HKDF implementation
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    // Create context
    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        EVP_KDF_free(kdf);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    // Set parameters
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)shared_secret, shared_secret_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, 12);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXTRACT_AND_EXPAND", 0);
    *p = OSSL_PARAM_construct_end();
    
    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    // Derive the key
    ret = EVP_KDF_derive(kctx, aes_key, AES_KEY_SIZE, NULL);
    
    // Cleanup
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    
    if (ret <= 0) {
        printf("DEBUG: OpenSSL HKDF key derivation failed\n");
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    printf("DEBUG: OpenSSL HKDF key derivation successful\n");
    printf("DEBUG: Derived AES key (first 8 bytes): ");
    for (int i = 0; i < 8 && i < AES_KEY_SIZE; i++) {
        printf("%02x ", aes_key[i]);
    }
    printf("\n");
    
    return CRYPTO_SUCCESS;
}
#endif

// mbedTLS HKDF implementation
#ifdef USE_MBEDTLS_BACKEND
static crypto_error_t derive_aes_key_mbedtls(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    const char *info = "PQC-TCP-AES-KEY";
    const uint8_t *salt = (const uint8_t *)"PQC-TCP-SALT";
    const size_t salt_len = 12;
    const size_t info_len = strlen(info);
    
    int ret = mbedtls_hkdf(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
        salt, salt_len,
        shared_secret, shared_secret_len,
        (const unsigned char *)info, info_len,
        aes_key, AES_KEY_SIZE
    );
    
    if (ret != 0) {
        printf("DEBUG: mbedTLS HKDF key derivation failed: -0x%04x\n", -ret);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    printf("DEBUG: mbedTLS HKDF key derivation successful\n");
    printf("DEBUG: Derived AES key (first 8 bytes): ");
    for (int i = 0; i < 8 && i < AES_KEY_SIZE; i++) {
        printf("%02x ", aes_key[i]);
    }
    printf("\n");
    
    return CRYPTO_SUCCESS;
}
#endif

// Unified HKDF interface
static crypto_error_t derive_aes_key(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key, crypto_op_backend_t backend) {
    switch (backend) {
#ifdef USE_OPENSSL_BACKEND
        case CRYPTO_OP_BACKEND_OPENSSL:
            return derive_aes_key_openssl(shared_secret, shared_secret_len, aes_key);
#endif
#ifdef USE_MBEDTLS_BACKEND
        case CRYPTO_OP_BACKEND_MBEDTLS:
            return derive_aes_key_mbedtls(shared_secret, shared_secret_len, aes_key);
#endif
        default:
            printf("DEBUG: Unsupported crypto backend for HKDF: %d\n", backend);
            return CRYPTO_ERROR_BACKEND_NOT_AVAILABLE;
    }
}
```

#### 2.4 Backend Selection and Initialization Updates

**Updated Context Structure and Backend Selection:**

```c
// Custom PQC backend context (updated)
typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    uint8_t *aes_key;
    uint32_t sequence_number;
    uint32_t expected_sequence;
    crypto_op_backend_t op_backend;  // Backend for crypto operations
} custom_pqc_ctx_t;

// Backend availability checking
static crypto_op_backend_t get_available_backends(void) {
    crypto_op_backend_t available = 0;
#ifdef USE_OPENSSL_BACKEND
    available |= (1 << CRYPTO_OP_BACKEND_OPENSSL);
#endif
#ifdef USE_MBEDTLS_BACKEND
    available |= (1 << CRYPTO_OP_BACKEND_MBEDTLS);
#endif
    return available;
}

// Default backend selection
static crypto_op_backend_t get_default_backend(void) {
#ifdef CRYPTO_BACKEND_DEFAULT_OPENSSL
    return CRYPTO_OP_BACKEND_OPENSSL;
#elif defined(CRYPTO_BACKEND_DEFAULT_MBEDTLS)
    return CRYPTO_OP_BACKEND_MBEDTLS;
#else
    // Fallback logic
#ifdef USE_OPENSSL_BACKEND
    return CRYPTO_OP_BACKEND_OPENSSL;
#elif defined(USE_MBEDTLS_BACKEND)
    return CRYPTO_OP_BACKEND_MBEDTLS;
#else
    return CRYPTO_OP_BACKEND_OPENSSL; // Default fallback
#endif
#endif
}

// Updated initialization function
crypto_error_t crypto_backend_custom_pqc_init(crypto_context_t *ctx) {
    if (ctx == NULL) {
        printf("DEBUG: ctx is NULL\n");
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    printf("DEBUG: Starting crypto backend initialization\n");
    
    custom_pqc_ctx_t *pqc_ctx = malloc(sizeof(custom_pqc_ctx_t));
    if (pqc_ctx == NULL) {
        printf("DEBUG: Failed to allocate memory for pqc_ctx\n");
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    memset(pqc_ctx, 0, sizeof(custom_pqc_ctx_t));
    
    // Set default operation backend
    pqc_ctx->op_backend = get_default_backend();
    ctx->op_backend = pqc_ctx->op_backend;
    
    printf("DEBUG: Selected crypto operation backend: %s\n", 
           (pqc_ctx->op_backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    
    // Initialize liboqs
    printf("DEBUG: Initializing liboqs\n");
    OQS_init();
    
    // Create ML-KEM-512 instance
    printf("DEBUG: Creating ML-KEM-512 instance\n");
    pqc_ctx->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (pqc_ctx->kem == NULL) {
        printf("DEBUG: Failed to create ML-KEM-512 instance\n");
        free(pqc_ctx);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    printf("DEBUG: ML-KEM-512 instance created successfully\n");
    
    // Allocate memory for keys
    printf("DEBUG: Allocating memory for keys\n");
    printf("DEBUG: Public key length: %zu\n", pqc_ctx->kem->length_public_key);
    printf("DEBUG: Secret key length: %zu\n", pqc_ctx->kem->length_secret_key);
    printf("DEBUG: Ciphertext length: %zu\n", pqc_ctx->kem->length_ciphertext);
    printf("DEBUG: Shared secret length: %zu\n", pqc_ctx->kem->length_shared_secret);
    
    pqc_ctx->public_key = malloc(pqc_ctx->kem->length_public_key);
    pqc_ctx->secret_key = malloc(pqc_ctx->kem->length_secret_key);
    pqc_ctx->ciphertext = malloc(pqc_ctx->kem->length_ciphertext);
    pqc_ctx->shared_secret = malloc(pqc_ctx->kem->length_shared_secret);
    pqc_ctx->aes_key = malloc(AES_KEY_SIZE);
    
    if (!pqc_ctx->public_key || !pqc_ctx->secret_key || !pqc_ctx->ciphertext || 
        !pqc_ctx->shared_secret || !pqc_ctx->aes_key) {
        printf("DEBUG: Failed to allocate memory for keys\n");
        crypto_backend_custom_pqc_cleanup(ctx);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    printf("DEBUG: Memory allocation successful\n");
    
    ctx->backend_ctx = pqc_ctx;
    ctx->shared_secret = pqc_ctx->shared_secret;
    ctx->shared_secret_len = pqc_ctx->kem->length_shared_secret;
    ctx->sequence_number = 0;
    pqc_ctx->expected_sequence = 0;
    
    return CRYPTO_SUCCESS;
}

// Backend switching function
crypto_error_t crypto_set_operation_backend(crypto_context_t *ctx, crypto_op_backend_t op_backend) {
    if (ctx == NULL || ctx->backend_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Check if backend is available
    crypto_op_backend_t available = get_available_backends();
    if (!(available & (1 << op_backend))) {
        printf("DEBUG: Requested backend %d not available\n", op_backend);
        return CRYPTO_ERROR_BACKEND_NOT_AVAILABLE;
    }
    
    pqc_ctx->op_backend = op_backend;
    ctx->op_backend = op_backend;
    
    printf("DEBUG: Switched crypto operation backend to: %s\n", 
           (op_backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    
    return CRYPTO_SUCCESS;
}

// Get available backends
crypto_op_backend_t crypto_get_available_backends(void) {
    return get_available_backends();
}
```

#### 2.5 Dual Backend AES-GCM Encryption
**Function: `encrypt_data()`**

```c
// mbedTLS version
static crypto_error_t encrypt_data(const uint8_t *aes_key, const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, size_t *ciphertext_len, uint32_t sequence_number) {
    printf("DEBUG: Starting mbedTLS encryption - plaintext_len=%zu, sequence_number=%u\n", plaintext_len, sequence_number);
    
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    
    // Get cipher info for AES-256-GCM
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
    if (cipher_info == NULL) {
        printf("DEBUG: Failed to get AES-256-GCM cipher info\n");
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Setup cipher
    int ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        printf("DEBUG: Failed to setup cipher: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Set key
    ret = mbedtls_cipher_setkey(&ctx, aes_key, 256, MBEDTLS_ENCRYPT);
    if (ret != 0) {
        printf("DEBUG: Failed to set cipher key: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Generate random IV
    uint8_t iv[AES_IV_SIZE];
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        printf("DEBUG: Failed to seed CTR_DRBG: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, AES_IV_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to generate random IV: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    printf("DEBUG: Generated IV successfully\n");
    printf("DEBUG: IV (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_IV_SIZE; i++) {
        printf("%02x ", iv[i]);
    }
    printf("\n");
    
    // Set IV
    ret = mbedtls_cipher_set_iv(&ctx, iv, AES_IV_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to set IV: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Set AAD (sequence number)
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(sequence_number);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    
    printf("DEBUG: Setting AAD (sequence number only) - sequence_number=%u, net_seq=0x%08x\n", sequence_number, net_seq);
    ret = mbedtls_cipher_update_ad(&ctx, aad, SEQUENCE_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to set AAD: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Encrypt plaintext
    size_t olen;
    printf("DEBUG: Encrypting plaintext\n");
    ret = mbedtls_cipher_update(&ctx, plaintext, plaintext_len, ciphertext, &olen);
    if (ret != 0) {
        printf("DEBUG: Failed to encrypt plaintext: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len = olen;
    printf("DEBUG: Encrypted %zu bytes\n", olen);
    
    // Finalize encryption
    printf("DEBUG: Finalizing encryption\n");
    ret = mbedtls_cipher_finish(&ctx, ciphertext + olen, &olen);
    if (ret != 0) {
        printf("DEBUG: Failed to finalize encryption: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += olen;
    
    // Get authentication tag
    printf("DEBUG: Getting authentication tag\n");
    uint8_t *tag = ciphertext + *ciphertext_len;
    ret = mbedtls_cipher_write_tag(&ctx, tag, AES_TAG_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to get authentication tag: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += AES_TAG_SIZE;
    printf("DEBUG: Got authentication tag, total ciphertext_len=%zu\n", *ciphertext_len);
    printf("DEBUG: Auth tag (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_TAG_SIZE; i++) {
        printf("%02x ", tag[i]);
    }
    printf("\n");
    
    // Cleanup
    mbedtls_cipher_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
    // Prepend IV to ciphertext (same logic as OpenSSL version)
    printf("DEBUG: Prepending IV to ciphertext\n");
    printf("DEBUG: Before memmove - ciphertext_len=%zu, tag at offset %zu\n", *ciphertext_len, *ciphertext_len - AES_TAG_SIZE);
    
    // Save the tag before memmove
    uint8_t saved_tag[AES_TAG_SIZE];
    memcpy(saved_tag, ciphertext + *ciphertext_len - AES_TAG_SIZE, AES_TAG_SIZE);
    
    // Move encrypted data (without tag) to make room for IV
    memmove(ciphertext + AES_IV_SIZE, ciphertext, *ciphertext_len - AES_TAG_SIZE);
    // Copy IV to the beginning
    memcpy(ciphertext, iv, AES_IV_SIZE);
    // Restore the tag at the end
    memcpy(ciphertext + *ciphertext_len - AES_TAG_SIZE + AES_IV_SIZE, saved_tag, AES_TAG_SIZE);
    *ciphertext_len += AES_IV_SIZE;
    printf("DEBUG: After memmove - ciphertext_len=%zu, tag should be at offset %zu\n", *ciphertext_len, *ciphertext_len - AES_TAG_SIZE);
    printf("DEBUG: Encryption completed successfully, final ciphertext_len=%zu\n", *ciphertext_len);
    
    return CRYPTO_SUCCESS;
}
```

#### 2.4 Replace AES-GCM Decryption
**Function: `decrypt_data()`**

```c
// mbedTLS version
static crypto_error_t decrypt_data(const uint8_t *aes_key, const uint8_t *ciphertext, size_t ciphertext_len,
                                  uint8_t *plaintext, size_t *plaintext_len, uint32_t expected_sequence) {
    printf("DEBUG: Starting mbedTLS decryption - ciphertext_len=%zu, expected_sequence=%u\n", ciphertext_len, expected_sequence);
    
    if (ciphertext_len < AES_IV_SIZE + AES_TAG_SIZE) {
        printf("DEBUG: Ciphertext too short: %zu < %d\n", ciphertext_len, AES_IV_SIZE + AES_TAG_SIZE);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    mbedtls_cipher_context_t ctx;
    mbedtls_cipher_init(&ctx);
    
    // Get cipher info for AES-256-GCM
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
    if (cipher_info == NULL) {
        printf("DEBUG: Failed to get AES-256-GCM cipher info\n");
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Setup cipher
    int ret = mbedtls_cipher_setup(&ctx, cipher_info);
    if (ret != 0) {
        printf("DEBUG: Failed to setup cipher: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Set key
    ret = mbedtls_cipher_setkey(&ctx, aes_key, 256, MBEDTLS_DECRYPT);
    if (ret != 0) {
        printf("DEBUG: Failed to set cipher key: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Extract IV and tag
    const uint8_t *iv = ciphertext;
    const uint8_t *tag = ciphertext + ciphertext_len - AES_TAG_SIZE;
    const uint8_t *encrypted_data = ciphertext + AES_IV_SIZE;
    size_t encrypted_len = ciphertext_len - AES_IV_SIZE - AES_TAG_SIZE;
    
    printf("DEBUG: Extracted IV, tag, encrypted_len=%zu\n", encrypted_len);
    printf("DEBUG: Extracted IV (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_IV_SIZE; i++) {
        printf("%02x ", iv[i]);
    }
    printf("\n");
    
    // Set IV
    ret = mbedtls_cipher_set_iv(&ctx, iv, AES_IV_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to set IV: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    printf("DEBUG: Initialized decryption successfully\n");
    
    // Set AAD (sequence number)
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(expected_sequence);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    
    printf("DEBUG: Setting AAD for decryption (sequence number only) - expected_sequence=%u, net_seq=0x%08x\n", expected_sequence, net_seq);
    ret = mbedtls_cipher_update_ad(&ctx, aad, SEQUENCE_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to set AAD for decryption: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Decrypt data
    size_t olen;
    printf("DEBUG: Decrypting data\n");
    ret = mbedtls_cipher_update(&ctx, encrypted_data, encrypted_len, plaintext, &olen);
    if (ret != 0) {
        printf("DEBUG: Failed to decrypt data: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len = olen;
    printf("DEBUG: Decrypted %zu bytes\n", olen);
    
    // Set expected tag
    printf("DEBUG: Setting expected authentication tag\n");
    printf("DEBUG: Expected auth tag (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_TAG_SIZE; i++) {
        printf("%02x ", tag[i]);
    }
    printf("\n");
    ret = mbedtls_cipher_check_tag(&ctx, tag, AES_TAG_SIZE);
    if (ret != 0) {
        printf("DEBUG: Failed to verify authentication tag: -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Finalize decryption
    printf("DEBUG: Finalizing decryption\n");
    ret = mbedtls_cipher_finish(&ctx, plaintext + olen, &olen);
    if (ret != 0) {
        printf("DEBUG: Failed to finalize decryption (authentication failed): -0x%04x\n", -ret);
        mbedtls_cipher_free(&ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len += olen;
    printf("DEBUG: Decryption completed successfully, final plaintext_len=%zu\n", *plaintext_len);
    
    mbedtls_cipher_free(&ctx);
    return CRYPTO_SUCCESS;
}
```

### Phase 3: Testing and Validation

#### 3.1 Build System Testing
```bash
# Clean previous build
rm -rf build
mkdir build && cd build

# Configure with mbedTLS
cmake ..

# Build
make

# Verify binaries are created
ls -la bin/
```

#### 3.2 Functional Testing
```bash
# Terminal 1: Start server
./bin/server

# Terminal 2: Start client
./bin/client

# Verify encrypted communication works
# Check debug output for mbedTLS operations
```

#### 3.3 Compatibility Testing
- Test with existing liboqs ML-KEM-512 integration
- Verify message format compatibility
- Test sequence number handling
- Validate authentication tag verification

### Phase 4: Post-Quantum Considerations

#### 4.1 mbedTLS Post-Quantum Status
**Current Status (2024):**
- mbedTLS does not yet have native ML-KEM/Kyber support
- Post-quantum algorithms are still experimental in mbedTLS
- liboqs integration remains the best approach for ML-KEM-512

#### 4.2 Hybrid Approach
The migration maintains the hybrid approach:
- **liboqs**: ML-KEM-512 key exchange (post-quantum)
- **mbedTLS**: AES-256-GCM encryption, HKDF, random generation (classical)

#### 4.3 Future mbedTLS Integration
When mbedTLS adds native ML-KEM support:
1. Replace liboqs ML-KEM calls with mbedTLS equivalents
2. Update key exchange protocol
3. Maintain same application interface

### Phase 5: Performance and Security Considerations

#### 5.1 Performance Impact
- **mbedTLS vs OpenSSL**: Generally similar performance for AES-GCM
- **Memory footprint**: mbedTLS typically smaller
- **Build time**: mbedTLS may be faster to build

#### 5.2 Security Considerations
- **FIPS compliance**: mbedTLS has FIPS 140-2 validation
- **Side-channel resistance**: mbedTLS has good constant-time implementations
- **Vulnerability management**: Different vulnerability profile than OpenSSL

#### 5.3 Maintenance Benefits
- **Smaller codebase**: mbedTLS is more focused
- **Better documentation**: Clear API documentation
- **Embedded-friendly**: Designed for resource-constrained environments

## Implementation Timeline

### Week 1: Setup and Integration
- [ ] Add mbedTLS submodule
- [ ] Update CMakeLists.txt
- [ ] Create mbedtls_config.h
- [ ] Test basic build

### Week 2: Code Migration
- [ ] Replace HKDF implementation
- [ ] Replace AES-GCM encryption
- [ ] Replace AES-GCM decryption
- [ ] Update error handling

### Week 3: Testing and Validation
- [ ] Build system testing
- [ ] Functional testing
- [ ] Compatibility testing
- [ ] Performance testing

### Week 4: Documentation and Cleanup
- [ ] Update documentation
- [ ] Remove OpenSSL dependencies
- [ ] Code cleanup and optimization
- [ ] Final validation

## Concerns and Risk Mitigation

### Technical Concerns

#### 1. **Dual Backend Complexity**
**Concern**: Managing two different crypto backends increases code complexity and maintenance burden.

**Mitigation**:
- Clear abstraction layer with unified interface
- Comprehensive testing for both backends
- Conditional compilation to avoid runtime overhead
- Well-documented backend selection mechanism

#### 2. **API Differences**
**Concern**: mbedTLS and OpenSSL have different APIs, error handling, and memory management patterns.

**Mitigation**:
- Backend-specific wrapper functions
- Unified error code mapping
- Consistent memory management patterns
- Extensive testing of both implementations

#### 3. **Build System Complexity**
**Concern**: Supporting both backends makes the build system more complex.

**Mitigation**:
- Clear CMake options for backend selection
- Automated build scripts for different configurations
- Comprehensive documentation for build options
- CI/CD testing for both backend combinations

#### 4. **Performance Impact**
**Concern**: Conditional compilation and backend switching might impact performance.

**Mitigation**:
- Compile-time backend selection (no runtime overhead)
- Benchmarking both backends
- Performance regression testing
- Optional runtime switching for testing only

### Compatibility Concerns

#### 1. **Protocol Interoperability**
**Concern**: Different backends might produce different results for the same operations.

**Mitigation**:
- Extensive cross-backend testing
- Validation that both backends produce identical results
- Protocol compatibility testing
- Message format consistency verification

#### 2. **liboqs Integration**
**Concern**: Potential conflicts between liboqs and different crypto backends.

**Mitigation**:
- Test thoroughly with existing liboqs code
- Maintain clear separation between PQC and classical crypto
- Validate ML-KEM-512 integration with both backends

#### 3. **System Dependencies**
**Concern**: Different system requirements for OpenSSL vs mbedTLS.

**Mitigation**:
- Clear documentation of system requirements
- Docker containers for consistent build environments
- Fallback mechanisms if preferred backend unavailable

### Security Concerns

#### 1. **Backend Security Differences**
**Concern**: Different security properties and vulnerability profiles.

**Mitigation**:
- Security audit of both implementations
- Regular security updates for both backends
- Clear documentation of security considerations
- Option to disable less secure backends if needed

#### 2. **Key Derivation Consistency**
**Concern**: Different HKDF implementations might produce different keys.

**Mitigation**:
- Extensive testing of key derivation
- Validation that both backends produce identical keys
- Cross-backend key compatibility testing

### Operational Concerns

#### 1. **Maintenance Burden**
**Concern**: Supporting two backends increases maintenance work.

**Mitigation**:
- Automated testing for both backends
- Clear separation of backend-specific code
- Comprehensive documentation
- Community contribution guidelines

#### 2. **User Confusion**
**Concern**: Users might be confused about which backend to use.

**Mitigation**:
- Clear documentation of backend differences
- Default backend selection with clear rationale
- Runtime backend information and switching
- Performance and security comparison guides

## Risk Mitigation Summary

### Technical Risks
1. **API Differences**: Backend-specific wrapper functions and unified interface
2. **Performance Regression**: Compile-time selection and benchmarking
3. **Build Complexity**: Clear CMake options and automated scripts

### Compatibility Risks
1. **Protocol Changes**: Maintain same message format and extensive testing
2. **liboqs Integration**: Clear separation and thorough validation

### Security Risks
1. **Backend Differences**: Security audits and regular updates
2. **Key Consistency**: Cross-backend validation and testing

## Success Criteria

### Functional Requirements
- [ ] All existing functionality preserved
- [ ] Same message format and protocol
- [ ] Compatible with existing client/server
- [ ] No performance regression > 10%

### Technical Requirements
- [ ] Clean build with mbedTLS
- [ ] No OpenSSL dependencies
- [ ] Proper error handling
- [ ] Memory leak free

### Quality Requirements
- [ ] Comprehensive testing
- [ ] Updated documentation
- [ ] Code review completed
- [ ] Security validation

## Conclusion

This dual backend migration plan provides a comprehensive approach to adding mbedTLS as an alternative cryptographic backend alongside the existing OpenSSL implementation. The plan maintains the existing post-quantum cryptography functionality while providing users with flexibility to choose between system OpenSSL or mbedTLS submodule.

### Key Benefits of Dual Backend Approach

1. **Flexibility**: Users can choose the backend that best fits their needs
2. **Compatibility**: Maintains existing OpenSSL functionality while adding mbedTLS option
3. **Future-Proofing**: Easy to add additional backends in the future
4. **Testing**: Cross-backend validation ensures implementation correctness
5. **Performance**: Users can benchmark and choose the best performing backend

### Hybrid Architecture Maintained

The implementation preserves the hybrid approach:
- **liboqs**: ML-KEM-512 post-quantum key exchange (unchanged)
- **OpenSSL/mbedTLS**: Classical cryptography (AES-GCM, HKDF, random generation)

### Implementation Strategy

The migration is designed to be:
- **Incremental**: Add mbedTLS without removing OpenSSL
- **Low-risk**: Extensive testing and validation at each phase
- **Configurable**: Compile-time and runtime backend selection
- **Maintainable**: Clear separation of backend-specific code

### Build Options

Users can build with different backend combinations:
```bash
# Both backends enabled (default)
cmake -DUSE_OPENSSL_BACKEND=ON -DUSE_MBEDTLS_BACKEND=ON ..

# OpenSSL only
cmake -DUSE_OPENSSL_BACKEND=ON -DUSE_MBEDTLS_BACKEND=OFF ..

# mbedTLS only
cmake -DUSE_OPENSSL_BACKEND=OFF -DUSE_MBEDTLS_BACKEND=ON ..

# Default backend selection
cmake -DCRYPTO_BACKEND_DEFAULT=mbedtls ..
```

This approach provides the best of both worlds: proven OpenSSL compatibility with modern mbedTLS flexibility, ensuring the PQC Lab implementation can adapt to different deployment requirements and user preferences.
