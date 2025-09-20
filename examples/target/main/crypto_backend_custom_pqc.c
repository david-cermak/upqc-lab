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
#include "esp_log.h"
#include "crypto_primitives.h"

#define TAG "pqc"

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

// Backend availability checking
// mbedTLS-only build: no backend selection

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

// OpenSSL HKDF implementation
#ifdef USE_OPENSSL_BACKEND
static crypto_error_t derive_aes_key_openssl(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    printf("DEBUG: Using OpenSSL backend for HKDF key derivation\n");
    
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

// Unified HKDF helper (mbedTLS primitives)
static crypto_error_t derive_aes_key(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    const uint8_t salt[] = "PQC-TCP-SALT";
    const uint8_t info[] = "PQC-TCP-AES-KEY";
    int r = hkdf_sha256(shared_secret, shared_secret_len,
                        salt, sizeof(salt) - 1,
                        info, sizeof(info) - 1,
                        aes_key, AES_KEY_SIZE);
    return (r == 0) ? CRYPTO_SUCCESS : CRYPTO_ERROR_INIT_FAILED;
}

// Encrypt data with AES-256-GCM
// OpenSSL AEAD implementation
#ifdef USE_OPENSSL_BACKEND
static crypto_error_t encrypt_data_openssl(const uint8_t *aes_key, const uint8_t *plaintext, size_t plaintext_len,
                                  uint8_t *ciphertext, size_t *ciphertext_len, uint32_t sequence_number) {
    printf("DEBUG: Starting encryption - plaintext_len=%zu, sequence_number=%u\n", plaintext_len, sequence_number);
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("DEBUG: Failed to create EVP_CIPHER_CTX\n");
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Generate random IV
    uint8_t iv[AES_IV_SIZE];
    if (RAND_bytes(iv, AES_IV_SIZE) != 1) {
        printf("DEBUG: Failed to generate random IV\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    printf("DEBUG: Generated IV successfully\n");
    printf("DEBUG: IV (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_IV_SIZE; i++) {
        printf("%02x ", iv[i]);
    }
    printf("\n");
    
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        printf("DEBUG: Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    printf("DEBUG: Initialized encryption successfully\n");
    
    // Set additional authenticated data (sequence number only)
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(sequence_number);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    
    printf("DEBUG: Setting AAD (sequence number only) - sequence_number=%u, net_seq=0x%08x\n", sequence_number, net_seq);
    if (EVP_EncryptUpdate(ctx, NULL, (int*)ciphertext_len, aad, SEQUENCE_SIZE) != 1) {
        printf("DEBUG: Failed to set AAD\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    
    // Encrypt plaintext
    int len;
    printf("DEBUG: Encrypting plaintext\n");
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1) {
        printf("DEBUG: Failed to encrypt plaintext\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len = len;
    printf("DEBUG: Encrypted %d bytes\n", len);
    
    // Finalize encryption
    printf("DEBUG: Finalizing encryption\n");
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        printf("DEBUG: Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += len;
    
    // Get authentication tag
    printf("DEBUG: Getting authentication tag\n");
    uint8_t *tag = ciphertext + *ciphertext_len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE, tag) != 1) {
        printf("DEBUG: Failed to get authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }
    *ciphertext_len += AES_TAG_SIZE;
    printf("DEBUG: Got authentication tag, total ciphertext_len=%zu\n", *ciphertext_len);
    printf("DEBUG: Auth tag (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_TAG_SIZE; i++) {
        printf("%02x ", tag[i]);
    }
    printf("\n");
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
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
#endif

// Decrypt data with AES-256-GCM
// OpenSSL AEAD implementation
#ifdef USE_OPENSSL_BACKEND
static crypto_error_t decrypt_data_openssl(const uint8_t *aes_key, const uint8_t *ciphertext, size_t ciphertext_len,
                                  uint8_t *plaintext, size_t *plaintext_len, uint32_t expected_sequence) {
    printf("DEBUG: Starting decryption - ciphertext_len=%zu, expected_sequence=%u\n", ciphertext_len, expected_sequence);
    
    if (ciphertext_len < AES_IV_SIZE + AES_TAG_SIZE) {
        printf("DEBUG: Ciphertext too short: %zu < %d\n", ciphertext_len, AES_IV_SIZE + AES_TAG_SIZE);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("DEBUG: Failed to create EVP_CIPHER_CTX for decryption\n");
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
    
    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes_key, iv) != 1) {
        printf("DEBUG: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    printf("DEBUG: Initialized decryption successfully\n");
    
    // Set additional authenticated data (sequence number only)
    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(expected_sequence);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);
    
    printf("DEBUG: Setting AAD for decryption (sequence number only) - expected_sequence=%u, net_seq=0x%08x\n", expected_sequence, net_seq);
    int len;
    if (EVP_DecryptUpdate(ctx, NULL, &len, aad, SEQUENCE_SIZE) != 1) {
        printf("DEBUG: Failed to set AAD for decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Decrypt data
    printf("DEBUG: Decrypting data\n");
    if (EVP_DecryptUpdate(ctx, plaintext, &len, encrypted_data, (int)encrypted_len) != 1) {
        printf("DEBUG: Failed to decrypt data\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len = len;
    printf("DEBUG: Decrypted %d bytes\n", len);
    
    // Set expected tag
    printf("DEBUG: Setting expected authentication tag\n");
    printf("DEBUG: Expected auth tag (first 4 bytes): ");
    for (int i = 0; i < 4 && i < AES_TAG_SIZE; i++) {
        printf("%02x ", tag[i]);
    }
    printf("\n");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE, (void*)tag) != 1) {
        printf("DEBUG: Failed to set expected authentication tag\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    
    // Finalize decryption
    printf("DEBUG: Finalizing decryption\n");
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        printf("DEBUG: Failed to finalize decryption (authentication failed)\n");
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }
    *plaintext_len += len;
    printf("DEBUG: Decryption completed successfully, final plaintext_len=%zu\n", *plaintext_len);
    
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_SUCCESS;
}
#endif

// AEAD helpers (mbedTLS primitives)
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
    
    // No runtime backend selection on target
    
    // Initialize liboqs
    printf("DEBUG: Initializing liboqs\n");
    OQS_init();
    
    // Create ML-KEM-512 instance
    printf("DEBUG: Creating ML-KEM-512 instance\n");
    pqc_ctx->kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    // pqc_ctx->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
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
    ESP_LOGI(TAG, "Before encapsulation");
    OQS_STATUS rc = OQS_KEM_encaps(pqc_ctx->kem, pqc_ctx->ciphertext, pqc_ctx->shared_secret, pqc_ctx->public_key);
    if (rc != OQS_SUCCESS) {
        return CRYPTO_ERROR_HANDSHAKE_FAILED;
    }
    ESP_LOGI(TAG, "After encapsulation");
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

// No runtime backend switching on target
