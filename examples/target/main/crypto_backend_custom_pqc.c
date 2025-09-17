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

#define USE_MBEDTLS_BACKEND

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
#include <mbedtls/gcm.h>
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
    uint32_t expected_sequence;
    crypto_op_backend_t op_backend;  // Backend for crypto operations
#ifdef USE_MBEDTLS_BACKEND
    // RNG for IV generation when using mbedTLS AEAD
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool rng_initialized;
#endif
} custom_pqc_ctx_t;

// Backend availability checking
static crypto_op_backend_t get_available_backends(void) {
    crypto_op_backend_t available = 0;
#ifdef USE_OPENSSL_BACKEND
    available |= (1 << CRYPTO_OP_BACKEND_OPENSSL);  // 1 << 0 = 1
#endif
#ifdef USE_MBEDTLS_BACKEND
    available |= (1 << CRYPTO_OP_BACKEND_MBEDTLS);  // 1 << 1 = 2
#endif
    return available;
}

// Default backend selection
static crypto_op_backend_t get_default_backend(void) {
    printf("DEBUG: Backend selection logic:\n");
#ifdef CRYPTO_BACKEND_DEFAULT_OPENSSL
    printf("DEBUG: CRYPTO_BACKEND_DEFAULT_OPENSSL defined - using OpenSSL\n");
    return CRYPTO_OP_BACKEND_OPENSSL;
#elif defined(CRYPTO_BACKEND_DEFAULT_MBEDTLS)
    printf("DEBUG: CRYPTO_BACKEND_DEFAULT_MBEDTLS defined - using mbedTLS\n");
    return CRYPTO_OP_BACKEND_MBEDTLS;
#else
    printf("DEBUG: No default backend defined, using fallback logic\n");
    // Fallback logic
#ifdef USE_OPENSSL_BACKEND
    printf("DEBUG: USE_OPENSSL_BACKEND defined - using OpenSSL\n");
    return CRYPTO_OP_BACKEND_OPENSSL;
#elif defined(USE_MBEDTLS_BACKEND)
    printf("DEBUG: USE_MBEDTLS_BACKEND defined - using mbedTLS\n");
    return CRYPTO_OP_BACKEND_MBEDTLS;
#else
    printf("DEBUG: No backend defined - defaulting to OpenSSL\n");
    return CRYPTO_OP_BACKEND_OPENSSL; // Default fallback
#endif
#endif
}

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

// mbedTLS HKDF implementation
#ifdef USE_MBEDTLS_BACKEND
static crypto_error_t derive_aes_key_mbedtls(const uint8_t *shared_secret, size_t shared_secret_len, uint8_t *aes_key) {
    printf("DEBUG: Using mbedTLS backend for HKDF key derivation\n");
    
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
    printf("DEBUG: HKDF key derivation requested with backend: %s\n", 
           (backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    
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

// mbedTLS AEAD implementation
#ifdef USE_MBEDTLS_BACKEND
static crypto_error_t encrypt_data_mbedtls(custom_pqc_ctx_t *pqc_ctx, const uint8_t *aes_key,
                                           const uint8_t *plaintext, size_t plaintext_len,
                                           uint8_t *ciphertext, size_t *ciphertext_len,
                                           uint32_t sequence_number) {
    printf("DEBUG: Starting mbedTLS encryption - plaintext_len=%zu, sequence_number=%u\n", plaintext_len, (int)sequence_number);

    if (!pqc_ctx->rng_initialized) {
        printf("DEBUG: mbedTLS RNG not initialized\n");
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret != 0) {
        printf("DEBUG: mbedTLS setkey failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }

    // Generate random IV
    uint8_t iv[AES_IV_SIZE];
    ret = mbedtls_ctr_drbg_random(&pqc_ctx->ctr_drbg, iv, AES_IV_SIZE);
    if (ret != 0) {
        printf("DEBUG: mbedTLS IV generation failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }

    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(sequence_number);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);

    // Output layout: [IV][ciphertext][tag]
    uint8_t *out = ciphertext;
    memcpy(out, iv, AES_IV_SIZE);

    uint8_t tag[AES_TAG_SIZE];

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                    plaintext_len,
                                    iv, AES_IV_SIZE,
                                    aad, SEQUENCE_SIZE,
                                    plaintext,
                                    out + AES_IV_SIZE,
                                    AES_TAG_SIZE,
                                    tag);
    if (ret != 0) {
        printf("DEBUG: mbedTLS gcm_crypt_and_tag failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return CRYPTO_ERROR_ENCRYPT_FAILED;
    }

    memcpy(out + AES_IV_SIZE + plaintext_len, tag, AES_TAG_SIZE);
    *ciphertext_len = AES_IV_SIZE + plaintext_len + AES_TAG_SIZE;

    mbedtls_gcm_free(&gcm);
    printf("DEBUG: mbedTLS encryption completed successfully, final ciphertext_len=%zu\n", *ciphertext_len);
    return CRYPTO_SUCCESS;
}

static crypto_error_t decrypt_data_mbedtls(const uint8_t *aes_key,
                                           const uint8_t *ciphertext, size_t ciphertext_len,
                                           uint8_t *plaintext, size_t *plaintext_len,
                                           uint32_t expected_sequence) {
    printf("DEBUG: Starting mbedTLS decryption - ciphertext_len=%zu, expected_sequence=%u\n", ciphertext_len, (int)expected_sequence);

    if (ciphertext_len < AES_IV_SIZE + AES_TAG_SIZE) {
        printf("DEBUG: Ciphertext too short: %zu < %d\n", ciphertext_len, AES_IV_SIZE + AES_TAG_SIZE);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }

    const uint8_t *iv = ciphertext;
    const uint8_t *tag = ciphertext + ciphertext_len - AES_TAG_SIZE;
    const uint8_t *encrypted_data = ciphertext + AES_IV_SIZE;
    size_t encrypted_len = ciphertext_len - AES_IV_SIZE - AES_TAG_SIZE;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
    if (ret != 0) {
        printf("DEBUG: mbedTLS setkey failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }

    uint8_t aad[SEQUENCE_SIZE];
    uint32_t net_seq = htonl(expected_sequence);
    memcpy(aad, &net_seq, SEQUENCE_SIZE);

    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                   encrypted_len,
                                   iv, AES_IV_SIZE,
                                   aad, SEQUENCE_SIZE,
                                   tag, AES_TAG_SIZE,
                                   encrypted_data,
                                   plaintext);
    if (ret != 0) {
        printf("DEBUG: mbedTLS gcm_auth_decrypt failed: -0x%04x\n", -ret);
        mbedtls_gcm_free(&gcm);
        return CRYPTO_ERROR_DECRYPT_FAILED;
    }

    *plaintext_len = encrypted_len;
    mbedtls_gcm_free(&gcm);
    printf("DEBUG: mbedTLS decryption completed successfully, final plaintext_len=%zu\n", *plaintext_len);
    return CRYPTO_SUCCESS;
}
#endif

// Unified AEAD interface
static crypto_error_t encrypt_data(custom_pqc_ctx_t *pqc_ctx, const uint8_t *aes_key,
                                   const uint8_t *plaintext, size_t plaintext_len,
                                   uint8_t *ciphertext, size_t *ciphertext_len,
                                   uint32_t sequence_number, crypto_op_backend_t backend) {
    printf("DEBUG: AEAD encrypt requested with backend: %s\n",
           (backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    switch (backend) {
#ifdef USE_OPENSSL_BACKEND
        case CRYPTO_OP_BACKEND_OPENSSL:
            return encrypt_data_openssl(aes_key, plaintext, plaintext_len, ciphertext, ciphertext_len, sequence_number);
#endif
#ifdef USE_MBEDTLS_BACKEND
        case CRYPTO_OP_BACKEND_MBEDTLS:
            return encrypt_data_mbedtls(pqc_ctx, aes_key, plaintext, plaintext_len, ciphertext, ciphertext_len, sequence_number);
#endif
        default:
            printf("DEBUG: Unsupported crypto backend for AEAD encrypt: %d\n", backend);
            return CRYPTO_ERROR_BACKEND_NOT_AVAILABLE;
    }
}

static crypto_error_t decrypt_data(custom_pqc_ctx_t *pqc_ctx, const uint8_t *aes_key,
                                   const uint8_t *ciphertext, size_t ciphertext_len,
                                   uint8_t *plaintext, size_t *plaintext_len,
                                   uint32_t expected_sequence, crypto_op_backend_t backend) {
    printf("DEBUG: AEAD decrypt requested with backend: %s\n",
           (backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    switch (backend) {
#ifdef USE_OPENSSL_BACKEND
        case CRYPTO_OP_BACKEND_OPENSSL:
            return decrypt_data_openssl(aes_key, ciphertext, ciphertext_len, plaintext, plaintext_len, expected_sequence);
#endif
#ifdef USE_MBEDTLS_BACKEND
        case CRYPTO_OP_BACKEND_MBEDTLS:
            return decrypt_data_mbedtls(aes_key, ciphertext, ciphertext_len, plaintext, plaintext_len, expected_sequence);
#endif
        default:
            printf("DEBUG: Unsupported crypto backend for AEAD decrypt: %d\n", backend);
            return CRYPTO_ERROR_BACKEND_NOT_AVAILABLE;
    }
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
    
    // Set default operation backend
    pqc_ctx->op_backend = get_default_backend();
    ctx->op_backend = pqc_ctx->op_backend;

    printf("DEBUG: Selected crypto operation backend: %s\n", 
           (pqc_ctx->op_backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");

#ifdef USE_MBEDTLS_BACKEND
    // Initialize RNG if using mbedTLS backend for operations (needed for IVs)
    pqc_ctx->rng_initialized = false;
    if (pqc_ctx->op_backend == CRYPTO_OP_BACKEND_MBEDTLS) {
        const char *pers = "pqc-aes-gcm";
        mbedtls_entropy_init(&pqc_ctx->entropy);
        mbedtls_ctr_drbg_init(&pqc_ctx->ctr_drbg);
        int ret = mbedtls_ctr_drbg_seed(&pqc_ctx->ctr_drbg, mbedtls_entropy_func, &pqc_ctx->entropy,
                                        (const unsigned char *)pers, strlen(pers));
        if (ret != 0) {
            printf("DEBUG: mbedTLS RNG seed failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&pqc_ctx->ctr_drbg);
            mbedtls_entropy_free(&pqc_ctx->entropy);
            free(pqc_ctx);
            return CRYPTO_ERROR_INIT_FAILED;
        }
        pqc_ctx->rng_initialized = true;
    }
#endif
    
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
    err = derive_aes_key(pqc_ctx->shared_secret, pqc_ctx->kem->length_shared_secret, pqc_ctx->aes_key, pqc_ctx->op_backend);
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
    err = derive_aes_key(pqc_ctx->shared_secret, pqc_ctx->kem->length_shared_secret, pqc_ctx->aes_key, pqc_ctx->op_backend);
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
    crypto_error_t err = encrypt_data(pqc_ctx, pqc_ctx->aes_key, data, len, encrypted_data, &encrypted_len, ctx->sequence_number, pqc_ctx->op_backend);
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
    err = decrypt_data(pqc_ctx, pqc_ctx->aes_key, encrypted_data, encrypted_len, data, len, pqc_ctx->expected_sequence, pqc_ctx->op_backend);
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

#ifdef USE_MBEDTLS_BACKEND
    if (pqc_ctx->rng_initialized) {
        mbedtls_ctr_drbg_free(&pqc_ctx->ctr_drbg);
        mbedtls_entropy_free(&pqc_ctx->entropy);
        pqc_ctx->rng_initialized = false;
    }
#endif

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
        case CRYPTO_ERROR_BACKEND_NOT_AVAILABLE: return "Backend not available";
        default: return "Unknown error";
    }
}

bool crypto_is_handshake_complete(crypto_context_t *ctx) {
    return ctx != NULL && ctx->handshake_complete;
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
        printf("DEBUG: Requested backend %d not available (available: %d)\n", op_backend, available);
        return CRYPTO_ERROR_BACKEND_NOT_AVAILABLE;
    }
    
    pqc_ctx->op_backend = op_backend;
    ctx->op_backend = op_backend;

#ifdef USE_MBEDTLS_BACKEND
    // Ensure RNG is initialized if switching to mbedTLS
    if (op_backend == CRYPTO_OP_BACKEND_MBEDTLS && !pqc_ctx->rng_initialized) {
        const char *pers = "pqc-aes-gcm";
        mbedtls_entropy_init(&pqc_ctx->entropy);
        mbedtls_ctr_drbg_init(&pqc_ctx->ctr_drbg);
        int ret = mbedtls_ctr_drbg_seed(&pqc_ctx->ctr_drbg, mbedtls_entropy_func, &pqc_ctx->entropy,
                                        (const unsigned char *)pers, strlen(pers));
        if (ret != 0) {
            printf("DEBUG: mbedTLS RNG seed (switch) failed: -0x%04x\n", -ret);
            mbedtls_ctr_drbg_free(&pqc_ctx->ctr_drbg);
            mbedtls_entropy_free(&pqc_ctx->entropy);
            return CRYPTO_ERROR_INIT_FAILED;
        }
        pqc_ctx->rng_initialized = true;
    }
#endif
    
    printf("DEBUG: Switched crypto operation backend to: %s\n", 
           (op_backend == CRYPTO_OP_BACKEND_OPENSSL) ? "OpenSSL" : "mbedTLS");
    
    return CRYPTO_SUCCESS;
}

// Get available backends
crypto_op_backend_t crypto_get_available_backends(void) {
    return get_available_backends();
}
