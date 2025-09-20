#include "crypto_primitives.h"

#ifdef USE_MBEDTLS_BACKEND

#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>

static int rng_fill(uint8_t *out, size_t out_len) {
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "aes-gcm-iv";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)pers, strlen(pers));
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return ret ? ret : -1;
    }
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, out, out_len);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out_key, size_t out_len) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    int ret = mbedtls_hkdf(md,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           out_key, out_len);
    return ret;
}

int aead_aes256gcm_encrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t *out_len) {
    int ret;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return ret; }

    // Output: [IV][ciphertext][TAG]
    uint8_t *iv = out;
    ret = rng_fill(iv, AES_GCM_IV_SIZE);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return ret; }

    uint8_t *ciphertext = out + AES_GCM_IV_SIZE;
    uint8_t *tag = out + AES_GCM_IV_SIZE + plaintext_len;

    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                    plaintext_len,
                                    iv, AES_GCM_IV_SIZE,
                                    aad, aad_len,
                                    plaintext,
                                    ciphertext,
                                    AES_GCM_TAG_SIZE,
                                    tag);
    mbedtls_gcm_free(&gcm);
    if (ret != 0) return ret;

    *out_len = AES_GCM_IV_SIZE + plaintext_len + AES_GCM_TAG_SIZE;
    return 0;
}

int aead_aes256gcm_decrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len) {
    if (in_len < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) return -1;
    int ret;
    const uint8_t *iv = in;
    const uint8_t *ciphertext = in + AES_GCM_IV_SIZE;
    size_t ciphertext_len = in_len - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t *tag = in + in_len - AES_GCM_TAG_SIZE;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return ret; }

    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                   ciphertext_len,
                                   iv, AES_GCM_IV_SIZE,
                                   aad, aad_len,
                                   tag, AES_GCM_TAG_SIZE,
                                   ciphertext,
                                   out);
    mbedtls_gcm_free(&gcm);
    if (ret != 0) return ret;

    *out_len = ciphertext_len;
    return 0;
}

#endif // USE_MBEDTLS_BACKEND

