#ifndef CRYPTO_PRIMITIVES_H
#define CRYPTO_PRIMITIVES_H

#include <stddef.h>
#include <stdint.h>

#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16

int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out_key, size_t out_len);

int aead_aes256gcm_encrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t *out_len);

int aead_aes256gcm_decrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len);

#endif // CRYPTO_PRIMITIVES_H

