#include "crypto_primitives.h"

#ifdef USE_OPENSSL_BACKEND

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <string.h>

int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *out_key, size_t out_len) {
    int ret = 1;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;

    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (!kdf) return 1;

    kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) { EVP_KDF_free(kdf); return 1; }

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    if (salt && salt_len)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    if (info && info_len)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE, "EXTRACT_AND_EXPAND", 0);
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_CTX_set_params(kctx, params) <= 0) goto cleanup;
    if (EVP_KDF_derive(kctx, out_key, out_len, NULL) <= 0) goto cleanup;
    ret = 0;

cleanup:
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

int aead_aes256gcm_encrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t *out_len) {
    int ret = 1;
    int len = 0, outl = 0;
    uint8_t *iv = out; // first bytes in output
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;

    if (RAND_bytes(iv, AES_GCM_IV_SIZE) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto cleanup;

    if (aad && aad_len) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }

    if (EVP_EncryptUpdate(ctx, out + AES_GCM_IV_SIZE, &len, plaintext, (int)plaintext_len) != 1) goto cleanup;
    outl = len;

    if (EVP_EncryptFinal_ex(ctx, out + AES_GCM_IV_SIZE + outl, &len) != 1) goto cleanup;
    outl += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                             out + AES_GCM_IV_SIZE + outl) != 1) goto cleanup;

    *out_len = AES_GCM_IV_SIZE + outl + AES_GCM_TAG_SIZE;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int aead_aes256gcm_decrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len) {
    if (in_len < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) return 1;

    int ret = 1;
    int len = 0, outl = 0;
    const uint8_t *iv = in;
    const uint8_t *ciphertext = in + AES_GCM_IV_SIZE;
    size_t ciphertext_len = in_len - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t *tag = in + in_len - AES_GCM_TAG_SIZE;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1) goto cleanup;
    if (aad && aad_len) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) goto cleanup;
    }
    if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, (int)ciphertext_len) != 1) goto cleanup;
    outl = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) goto cleanup;
    if (EVP_DecryptFinal_ex(ctx, out + outl, &len) != 1) goto cleanup;
    outl += len;

    *out_len = (size_t)outl;
    ret = 0;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

#endif // USE_OPENSSL_BACKEND

