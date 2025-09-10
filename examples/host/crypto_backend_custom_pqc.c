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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

// Message types for our custom protocol
#define MSG_TYPE_PUBLIC_KEY    0x01
#define MSG_TYPE_CIPHERTEXT    0x02
#define MSG_TYPE_ENCRYPTED     0x03
#define MSG_TYPE_ERROR         0x04

// Protocol constants
#define MAX_MESSAGE_SIZE       4096
#define AES_KEY_SIZE           32
#define AES_IV_SIZE            12
#define AES_TAG_SIZE           16
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
} custom_pqc_ctx_t;

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

// Derive AES key from shared secret using HKDF
static crypto_error_t derive_aes_key(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
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
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    return CRYPTO_SUCCESS;
}

// Encrypt data with AES-256-GCM
static crypto_error_t encrypt_data(const uint8_t *aes_key, const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, size_t *ciphertext_len, uint32_t sequence_number) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Generate random IV
    uint8_t iv[AES_IV_SIZE];
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Set additional authenticated data (sequence number + timestamp)
    uint8_t aad[SEQUENCE_SIZE + TIMESTAMP_SIZE];
    uint32_t net_seq = htonl(sequence_number);
    uint64_t timestamp = (uint64_t)time(NULL);
    // Convert to network byte order manually
    timestamp = ((timestamp & 0xFF00000000000000ULL) >> 56) |
                ((timestamp & 0x00FF000000000000ULL) >> 40) |
                ((timestamp & 0x0000FF0000000000ULL) >> 24) |
                ((timestamp & 0x000000FF00000000ULL) >> 8)  |
                ((timestamp & 0x00000000FF000000ULL) << 8)  |
                ((timestamp & 0x0000000000FF0000ULL) << 24) |
                ((timestamp & 0x000000000000FF00ULL) << 40) |
                ((timestamp & 0x00000000000000FFULL) << 56);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    memcpy(aad + SEQUENCE_SIZE, &timestamp, TIMESTAMP_SIZE);
    
    if (EVP_EncryptUpdate(ctx, NULL, (int*)ciphertext_len, aad, SEQUENCE_SIZE + TIMESTAMP_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Encrypt plaintext
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len = len;
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += len;
    
    // Get authentication tag
    uint8_t *tag = ciphertext + *ciphertext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += AES_TAG_SIZE;
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    memmove(ciphertext + AES_IV_SIZE, ciphertext, *ciphertext_len - AES_TAG_SIZE);
    memcpy(ciphertext, iv, AES_IV_SIZE);
    *ciphertext_len += AES_IV_SIZE;
    
    return CRYPTO_SUCCESS;
}

// Decrypt data with AES-256-GCM
static crypto_error_t decrypt_data(const uint8_t *aes_key, const uint8_t *ciphertext, size_t ciphertext_len,
                                  uint8_t *plaintext, size_t *plaintext_len, uint32_t expected_sequence) {
    if (ciphertext_len < AES_IV_SIZE + AES_TAG_SIZE) {
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Extract IV and tag
    const uint8_t *iv = ciphertext;
    const uint8_t *tag = ciphertext + ciphertext_len - AES_TAG_SIZE;
    const uint8_t *encrypted_data = ciphertext + AES_IV_SIZE;
    size_t encrypted_len = ciphertext_len - AES_IV_SIZE - AES_TAG_SIZE;
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Set additional authenticated data
    uint8_t aad[SEQUENCE_SIZE + TIMESTAMP_SIZE];
    uint32_t net_seq = htonl(expected_sequence);
    uint64_t timestamp = (uint64_t)time(NULL);
    // Convert to network byte order manually
    timestamp = ((timestamp & 0xFF00000000000000ULL) >> 56) |
                ((timestamp & 0x00FF000000000000ULL) >> 40) |
                ((timestamp & 0x0000FF0000000000ULL) >> 24) |
                ((timestamp & 0x000000FF00000000ULL) >> 8)  |
                ((timestamp & 0x00000000FF000000ULL) << 8)  |
                ((timestamp & 0x0000000000FF0000ULL) << 24) |
                ((timestamp & 0x000000000000FF00ULL) << 40) |
                ((timestamp & 0x00000000000000FFULL) << 56);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    memcpy(aad + SEQUENCE_SIZE, &timestamp, TIMESTAMP_SIZE);
    
    int len;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, SEQUENCE_SIZE + TIMESTAMP_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Decrypt data
    if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data, (int)encrypted_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len = len;
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}

// Custom PQC backend implementation
crypto_error_t crypto_backend_custom_pqc_init(crypto_context_t *ctx) {
    if (ctx == NULL) {
        return CRYPTO_ERROR_INVALID_PARAM;
    }
    
    custom_pqc_ctx_t *pqc_ctx = malloc(sizeof(custom_pqc_ctx_t));
    if (pqc_ctx == NULL) {
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    memset(pqc_ctx, 0, sizeof(custom_pqc_ctx_t));
    
    // Initialize liboqs
    OQS_init();
    
    // Create ML-KEM-512 instance
    pqc_ctx->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (pqc_ctx->kem == NULL) {
        free(pqc_ctx);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    // Allocate memory for keys
    pqc_ctx->public_key = malloc(pqc_ctx->kem->length_public_key);
    pqc_ctx->secret_key = malloc(pqc_ctx->kem->length_secret_key);
    pqc_ctx->ciphertext = malloc(pqc_ctx->kem->length_ciphertext);
    pqc_ctx->shared_secret = malloc(pqc_ctx->kem->length_shared_secret);
    pqc_ctx->aes_key = malloc(AES_KEY_SIZE);
    
    if (!pqc_ctx->public_key || !pqc_ctx->secret_key || !pqc_ctx->ciphertext || 
        !pqc_ctx->shared_secret || !pqc_ctx->aes_key) {
        crypto_backend_custom_pqc_cleanup(ctx);
        return CRYPTO_ERROR_INIT_FAILED;
    }
    
    ctx->backend_ctx = pqc_ctx;
    ctx->shared_secret = pqc_ctx->shared_secret;
    ctx->shared_secret_len = pqc_ctx->kem->length_shared_secret;
    ctx->sequence_number = 0;
    
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
    
    // Decrypt data
    err = decrypt_data(pqc_ctx->aes_key, encrypted_data, encrypted_len, data, len, ctx->sequence_number);
    if (err != CRYPTO_SUCCESS) {
        return err;
    }
    
    ctx->sequence_number++;
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_ERROR_INIT_FAILED; // Not implemented yet
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_ERROR_HANDSHAKE_FAILED; // Not implemented yet
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_ERROR_HANDSHAKE_FAILED; // Not implemented yet
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_ERROR_SEND_FAILED; // Not implemented yet
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_ERROR_RECV_FAILED; // Not implemented yet
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
        case CRYPTO_BACKEND_MBEDTLS:
        case CRYPTO_BACKEND_OPENSSL:
            return CRYPTO_SUCCESS; // Nothing to cleanup
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
        default: return "Unknown error";
    }
}

bool crypto_is_handshake_complete(crypto_context_t *ctx) {
    return ctx != NULL && ctx->handshake_complete;
}
