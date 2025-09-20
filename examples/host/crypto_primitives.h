#ifndef CRYPTO_PRIMITIVES_H
#define CRYPTO_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

// AES-256-GCM primitives constants
#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16

// HKDF-SHA256
// Derives out_key of length out_len from ikm using optional salt and info.
// Returns 0 on success, non-zero on failure.
int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out_key, size_t out_len);

// AEAD AES-256-GCM
// Encrypts and authenticates plaintext with AAD.
// Output layout: [IV (12)][ciphertext][TAG (16)].
// Caller must provide out buffer large enough: plaintext_len + AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE
// Returns 0 on success, non-zero on failure. Writes total bytes to out_len.
int aead_aes256gcm_encrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t *out_len);

// Decrypts and verifies input layout [IV][ciphertext][TAG] with AAD.
// On success, writes plaintext and length to out and out_len.
// Returns 0 on success, non-zero on failure.
int aead_aes256gcm_decrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len);

#endif // CRYPTO_PRIMITIVES_H

