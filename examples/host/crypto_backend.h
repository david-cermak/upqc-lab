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
    CRYPTO_ERROR_HANDSHAKE_NOT_COMPLETE = -9
} crypto_error_t;

// Main crypto context structure
typedef struct crypto_context {
    crypto_backend_t backend;
    void *backend_ctx;  // Backend-specific context
    int socket_fd;
    bool handshake_complete;
    uint8_t *shared_secret;
    size_t shared_secret_len;
    uint32_t sequence_number;  // For replay protection
} crypto_context_t;

// Core interface functions
crypto_error_t crypto_init(crypto_context_t *ctx, crypto_backend_t backend, int socket_fd);
crypto_error_t crypto_handshake_server(crypto_context_t *ctx);
crypto_error_t crypto_handshake_client(crypto_context_t *ctx);
crypto_error_t crypto_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len);
crypto_error_t crypto_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len);
crypto_error_t crypto_cleanup(crypto_context_t *ctx);

// Utility functions
const char* crypto_error_string(crypto_error_t error);
bool crypto_is_handshake_complete(crypto_context_t *ctx);

// Backend-specific functions (for future TLS backends)
crypto_error_t crypto_backend_custom_pqc_init(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_handshake_server(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_handshake_client(crypto_context_t *ctx);
crypto_error_t crypto_backend_custom_pqc_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len);
crypto_error_t crypto_backend_custom_pqc_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len);
crypto_error_t crypto_backend_custom_pqc_cleanup(crypto_context_t *ctx);

#endif // CRYPTO_BACKEND_H
