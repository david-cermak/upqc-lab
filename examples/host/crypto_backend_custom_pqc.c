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

// Backend-agnostic primitives (implemented per backend at compile time)
#include "crypto_primitives.h"

// Compile-time backend only: selection handled in build system by choosing primitives impl

// Message types for our custom protocol
#define MSG_TYPE_PUBLIC_KEY    0x01
#define MSG_TYPE_CIPHERTEXT    0x02
#define MSG_TYPE_ENCRYPTED     0x03
#define MSG_TYPE_ERROR         0x04

// Protocol constants
#define MAX_MESSAGE_SIZE       4096
#define AES_KEY_SIZE           AES_GCM_KEY_SIZE
#define AES_IV_SIZE            AES_GCM_IV_SIZE
#define AES_TAG_SIZE           AES_GCM_TAG_SIZE
#define SEQUENCE_SIZE          4
#define TIMESTAMP_SIZE         8

// Custom PQC backend context
typedef struct {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
    uint8_t *aes_key;
    uint32_t sequence_number;
    uint32_t expected_sequence;
} custom_pqc_ctx_t;
// No runtime backend selection: primitives decide based on compile-time

// Helper function to send protocol message
static crypto_error_t send_protocol_message(int socket_fd, uint8_t msg_type, const uint8_t *data, size_t len) {
    if (len > MAX_MESSAGE_SIZE) {
        return CRYPTO_ERROR_SEND_FAILED;
    }
    
    // Send message type (1 byte)
    if (send(socket_fd, &msg_type, 1, 0) != 1) {
        return CRYPTO_ERROR_SEND_FAILED;
    }
    
    // Send length (4 bytes, network byte order)
    uint32_t net_len = htonl((uint32_t)len);
    if (send(socket_fd, &net_len, 4, 0) != 4) {
        return CRYPTO_ERROR_SEND_FAILED;
    }
    
    // Send data if present
    if (len > 0 && data != NULL) {
        if (send(socket_fd, data, len, 0) != (ssize_t)len) {
            return CRYPTO_ERROR_SEND_FAILED;
        }
    }
    
    return CRYPTO_SUCCESS;
}

// Helper function to receive protocol message
static crypto_error_t recv_protocol_message(int socket_fd, uint8_t *msg_type, uint8_t *data, size_t *len) {
    // Receive message type
    if (recv(socket_fd, msg_type, 1, 0) != 1) {
        return CRYPTO_ERROR_RECV_FAILED;
    }
    
    // Receive length
    uint32_t net_len;
    if (recv(socket_fd, &net_len, 4, 0) != 4) {
        return CRYPTO_ERROR_RECV_FAILED;
    }
    uint32_t msg_len = ntohl(net_len);
    
    if (msg_len > MAX_MESSAGE_SIZE) {
        return CRYPTO_ERROR_RECV_FAILED;
    }
    
    // Receive data if present
    if (msg_len > 0 && data != NULL) {
        if (recv(socket_fd, data, msg_len, 0) != (ssize_t)msg_len) {
            return CRYPTO_ERROR_RECV_FAILED;
        }
    }
    
    *len = msg_len;
    return CRYPTO_SUCCESS;
}

// HKDF provided by primitives (per-backend implementation)

// HKDF provided by primitives (per-backend implementation)

// Unified HKDF helper using primitives API
static crypto_error_t derive_aes_key(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    const uint8_t salt[] = "PQC-TCP-SALT";
    const uint8_t info[] = "PQC-TCP-AES-KEY";
    int r = hkdf_sha256(shared_secret, shared_secret_len,
                        salt, sizeof(salt) - 1,
                        info, sizeof(info) - 1,
                        aes_key, AES_KEY_SIZE);
    return (r == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_INIT_FAILED;
}

// AEAD encryption/decryption implemented in primitives; no local per-backend code

// Decrypt via primitives (backend-specific implementation in separate file)

// mbedTLS AEAD implementation
// mbedTLS per-backend AEAD removed; handled by primitives

// Unified AEAD interface
static crypto_error_t encrypt_data(const uint8_t *aes_key,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *ciphertext, size_t *ciphertext_len,
                                   uint32_t sequence_number) {
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(sequence_number);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    size_t out_len = 0;
    int r = aead_aes256gcm_encrypt(aes_key, aad, sizeof(aad),
                                   plaintext, plaintext_len,
                                   ciphertext, &out_len);
    if (r != 0) return CRYPTO_ERROR_ENCRYPT_FAILED;
    *ciphertext_len = out_len;
    return CRYPTO_SUCCESS;
}

static crypto_error_t decrypt_data(const uint8_t *aes_key,
                                   const uint8_t *ciphertext, size_t ciphertext_len,
                                   uint8_t *plaintext, size_t *plaintext_len,
                                   uint32_t expected_sequence) {
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(expected_sequence);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    size_t out_len = 0;
    int r = aead_aes256gcm_decrypt(aes_key, aad, sizeof(aad),
                                   ciphertext, ciphertext_len,
                                   plaintext, &out_len);
    if (r != 0) return CRYPTO_ERROR_DECRYPT_FAILED;
    *plaintext_len = out_len;
    return CRYPTO_SUCCESS;
}

// Custom PQC backend implementation
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
    
    // Compile-time backend only; no runtime selection or RNG setup here
    
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

crypto_error_t crypto_backend_custom_pqc_handshake_server(crypto_context_t *ctx) {
    if (ctx == NULL || ctx->backend_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Generate keypair
    OQS_STATUS rc = OQS_KEM_keypair(pqc_ctx->kem, pqc_ctx->public_key, pqc_ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    
    // Send public key to client
    crypto_error_t err = send_protocol_message(ctx->socket_fd, MSG_TYPE_PUBLIC_KEY, 
                                              pqc_ctx->public_key, pqc_ctx->kem->length_public_key);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    // Receive ciphertext from client
    uint8_t msg_type;
    size_t msg_len;
    err = recv_protocol_message(ctx->socket_fd, &msg_type, pqc_ctx->ciphertext, &msg_len);
    if (err != CRYPTO_SUCCESS || msg_type != MSG_TYPE_CIPHERTEXT || 
        msg_len != pqc_ctx->kem->length_ciphertext) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    
    // Decapsulate shared secret
    rc = OQS_KEM_decaps(pqc_ctx->kem, pqc_ctx->shared_secret, pqc_ctx->ciphertext, pqc_ctx->secret_key);
    if (rc != OQS_SUCCESS) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    
    // Derive AES key
    err = derive_aes_key(pqc_ctx->shared_secret, pqc_ctx->kem->length_shared_secret, pqc_ctx->aes_key);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    ctx->handshake_complete = true;
    // Server sends first message, so start with sequence number 1
    ctx->sequence_number = 1;
    // Server expects client messages to start with sequence number 0
    pqc_ctx->expected_sequence = 0;
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_backend_custom_pqc_handshake_client(crypto_context_t *ctx) {
    if (ctx == NULL || ctx->backend_ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Receive public key from server
    uint8_t msg_type;
    size_t msg_len;
    crypto_error_t err = recv_protocol_message(ctx->socket_fd, &msg_type, pqc_ctx->public_key, &msg_len);
    if (err != CRYPTO_SUCCESS || msg_type != MSG_TYPE_PUBLIC_KEY || 
        msg_len != pqc_ctx->kem->length_public_key) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    
    // Encapsulate shared secret
    OQS_STATUS rc = OQS_KEM_encaps(pqc_ctx->kem, pqc_ctx->ciphertext, pqc_ctx->shared_secret, pqc_ctx->public_key);
    if (rc != OQS_SUCCESS) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    
    // Send ciphertext to server
    err = send_protocol_message(ctx->socket_fd, MSG_TYPE_CIPHERTEXT, 
                               pqc_ctx->ciphertext, pqc_ctx->kem->length_ciphertext);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    // Derive AES key
    err = derive_aes_key(pqc_ctx->shared_secret, pqc_ctx->kem->length_shared_secret, pqc_ctx->aes_key);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    ctx->handshake_complete = true;
    // Client expects server messages to start with sequence number 1
    pqc_ctx->expected_sequence = 1;
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_backend_custom_pqc_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len) {
    if (ctx == NULL || ctx->backend_ctx == NULL || !ctx->handshake_complete) {
        return CRYPTO_ERROR_HANDSHAKE_NOT_COMPLETE;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Encrypt data
    uint8_t encrypted_data[MAX_MESSAGE_SIZE];
    size_t encrypted_len;
    crypto_error_t err = encrypt_data(pqc_ctx->aes_key, data, len, encrypted_data, &encrypted_len, ctx->sequence_number);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    // Send encrypted message
    err = send_protocol_message(ctx->socket_fd, MSG_TYPE_ENCRYPTED, encrypted_data, encrypted_len);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    ctx->sequence_number++;
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_backend_custom_pqc_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len) {
    if (ctx == NULL || ctx->backend_ctx == NULL || !ctx->handshake_complete) {
        return CRYPTO_ERROR_HANDSHAKE_NOT_COMPLETE;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Receive encrypted message
    uint8_t msg_type;
    uint8_t encrypted_data[MAX_MESSAGE_SIZE];
    size_t encrypted_len;
    crypto_error_t err = recv_protocol_message(ctx->socket_fd, &msg_type, encrypted_data, &encrypted_len);
    if (err != CRYPTO_SUCCESS || msg_type != MSG_TYPE_ENCRYPTED) {
        return CRYPTO_ERROR_RECV_FAILED;
    }
    
    // Decrypt data using expected sequence number
    err = decrypt_data(pqc_ctx->aes_key, encrypted_data, encrypted_len, data, len, pqc_ctx->expected_sequence);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    // Increment expected sequence for next message
    pqc_ctx->expected_sequence++;
    return CRYPTO_SUCCESS;
}

crypto_error_t crypto_backend_custom_pqc_cleanup(crypto_context_t *ctx) {
    if (ctx == NULL || ctx->backend_ctx == NULL) {
        return CRYPTO_SUCCESS;
    }
    
    custom_pqc_ctx_t *pqc_ctx = (custom_pqc_ctx_t *)ctx->backend_ctx;
    
    // Secure cleanup of sensitive data
    if (pqc_ctx->secret_key) {
        OQS_MEM_secure_free(pqc_ctx->secret_key, pqc_ctx->kem->length_secret_key);
    }
    if (pqc_ctx->shared_secret) {
        OQS_MEM_secure_free(pqc_ctx->shared_secret, pqc_ctx->kem->length_shared_secret);
    }
    if (pqc_ctx->aes_key) {
        OQS_MEM_secure_free(pqc_ctx->aes_key, AES_KEY_SIZE);
    }
    
    // Regular cleanup
    OQS_MEM_insecure_free(pqc_ctx->public_key);
    OQS_MEM_insecure_free(pqc_ctx->ciphertext);
    
    if (pqc_ctx->kem) {
        OQS_KEM_free(pqc_ctx->kem);
    }

    

    free(pqc_ctx);
    ctx->backend_ctx = NULL;
    
    OQS_destroy();
    return CRYPTO_SUCCESS;
}

// Main interface functions that delegate to backend
crypto_error_t crypto_init(crypto_context_t *ctx, crypto_backend_t backend, int socket_fd) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    memset(ctx, 0, sizeof(crypto_context_t));
    ctx->backend = backend;
    ctx->socket_fd = socket_fd;
    ctx->handshake_complete = false;
    ctx->sequence_number = 0;
    
    switch (backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_init(ctx);
        default:
            return CRYPTO_ERROR_INVALID_PARAM;
    }
}

crypto_error_t crypto_handshake_server(crypto_context_t *ctx) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    switch (ctx->backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_handshake_server(ctx);
        default:
            return CRYPTO_ERROR_INVALID_PARAM;
    }
}

crypto_error_t crypto_handshake_client(crypto_context_t *ctx) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    switch (ctx->backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_handshake_client(ctx);
        default:
            return CRYPTO_ERROR_INVALID_PARAM;
    }
}

crypto_error_t crypto_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    switch (ctx->backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_send_message(ctx, data, len);
        default:
            return CRYPTO_ERROR_INVALID_PARAM;
    }
}

crypto_error_t crypto_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    switch (ctx->backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_recv_message(ctx, data, len);
        default:
            return CRYPTO_ERROR_INVALID_PARAM;
    }
}

crypto_error_t crypto_cleanup(crypto_context_t *ctx) {
    if (ctx == NULL) {
        return CRYPTO_SUCCESS;
    }
    
    switch (ctx->backend) {
        case CRYPTO_BACKEND_CUSTOM_PQC:
            return crypto_backend_custom_pqc_cleanup(ctx);
        default:
            return CRYPTO_SUCCESS;
    }
}

const char* crypto_error_string(crypto_error_t error) {
    switch (error) {
        case CRYPTO_SUCCESS: return "Success";
        case CRYPTO_ERROR_INVALID_PARAM: return "Invalid parameter";
        case CRYPTO_ERROR_INIT_FAILED: return "Initialization failed";
        case CRYPTO_ERROR_HANDSHAKE_FAILED: return "Handshake failed";
        case CRYPTO_ERROR_SEND_FAILED: return "Send failed";
        case CRYPTO_ERROR_RECV_FAILED: return "Receive failed";
        case CRYPTO_ERROR_ENCRYPT_FAILED: return "Encryption failed";
        case CRYPTO_ERROR_DECRYPT_FAILED: return "Decryption failed";
        case CRYPTO_ERROR_NOT_INITIALIZED: return "Not initialized";
        case CRYPTO_ERROR_HANDSHAKE_NOT_COMPLETE: return "Handshake not complete";
        case CRYPTO_ERROR_BACKEND_NOT_AVAILABLE: return "Backend not available";
        default: return "Unknown error";
    }
}

bool crypto_is_handshake_complete(crypto_context_t *ctx) {
    return ctx != NULL && ctx->handshake_complete;
}

// No runtime backend switching in compile-time-only model
