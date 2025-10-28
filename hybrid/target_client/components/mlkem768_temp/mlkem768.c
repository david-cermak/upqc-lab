#include "mlkem768.h"
#include <oqs/oqs.h>
#include <oqs/kem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "upqc_config.h"
#include "esp_log.h"
#define TAG "MLKEM768"

// ML-KEM-768 context implementation
struct mlkem768_ctx_impl {
    OQS_KEM *kem;
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
};

int mlkem768_init(mlkem768_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }

    // Allocate context
    struct mlkem768_ctx_impl *impl = calloc(1, sizeof(struct mlkem768_ctx_impl));
    if (impl == NULL) {
        return -1;
    }

    // Initialize liboqs
    OQS_init();

    // Create ML-KEM-768 instance
    impl->kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
    if (impl->kem == NULL) {
        free(impl);
        return -1;
    }

    // Attach impl early so cleanup can free on partial failures
    ctx->kem = impl;

    // Allocate memory for keys
    impl->public_key = malloc(impl->kem->length_public_key);
    impl->secret_key = malloc(impl->kem->length_secret_key);
    impl->ciphertext = malloc(impl->kem->length_ciphertext);
    impl->shared_secret = malloc(impl->kem->length_shared_secret);

    if (impl->public_key == NULL || impl->secret_key == NULL || 
        impl->ciphertext == NULL || impl->shared_secret == NULL) {
        mlkem768_cleanup(ctx);
        return -1;
    }

    // Expose internal buffers via public ctx for external users
    ctx->public_key = impl->public_key;
    ctx->secret_key = impl->secret_key;
    ctx->ciphertext = impl->ciphertext;
    ctx->shared_secret = impl->shared_secret;
    return 0;
}

int mlkem768_keypair(mlkem768_ctx_t *ctx)
{
    if (ctx == NULL || ctx->kem == NULL) {
        return -1;
    }
    ESP_LOGW(TAG, "Generating ML-KEM-768 keypair");
    struct mlkem768_ctx_impl *impl = (struct mlkem768_ctx_impl *)ctx->kem;
    
    // Generate keypair
    OQS_STATUS rc = OQS_KEM_keypair(impl->kem, impl->public_key, impl->secret_key);
    if (rc != OQS_SUCCESS) {
        return -1;
    }
    ESP_LOGW(TAG, "Generated ML-KEM-768 keypair");
    return 0;
}

int mlkem768_encaps(mlkem768_ctx_t *ctx, const uint8_t *public_key)
{
    if (ctx == NULL || ctx->kem == NULL || public_key == NULL) {
        return -1;
    }
    ESP_LOGW(TAG, "Encapsulating ML-KEM-768 shared secret");
    struct mlkem768_ctx_impl *impl = (struct mlkem768_ctx_impl *)ctx->kem;
    // Encapsulate shared secret
    OQS_STATUS rc = OQS_KEM_encaps(impl->kem, impl->ciphertext, impl->shared_secret, public_key);
    if (rc != OQS_SUCCESS) {
        return -1;
    }
    ESP_LOGW(TAG, "Encapsulated ML-KEM-768 shared secret");

    return 0;
}

int mlkem768_decaps(mlkem768_ctx_t *ctx, const uint8_t *ciphertext)
{
    if (ctx == NULL || ctx->kem == NULL || ciphertext == NULL) {
        return -1;
    }
    ESP_LOGW(TAG, "Decapsulating ML-KEM-768 shared secret");
    struct mlkem768_ctx_impl *impl = (struct mlkem768_ctx_impl *)ctx->kem;

    // Decapsulate shared secret
    OQS_STATUS rc = OQS_KEM_decaps(impl->kem, impl->shared_secret, ciphertext, impl->secret_key);
    if (rc != OQS_SUCCESS) {
        return -1;
    }
    ESP_LOGW(TAG, "Decapsulated ML-KEM-768 shared secret");
    return 0;
}

int mlkem768_cleanup(mlkem768_ctx_t *ctx)
{
    if (ctx == NULL || ctx->kem == NULL) {
        return 0;
    }

    struct mlkem768_ctx_impl *impl = (struct mlkem768_ctx_impl *)ctx->kem;

    // Free allocated memory
    if (impl->public_key) {
        free(impl->public_key);
    }
    if (impl->secret_key) {
        free(impl->secret_key);
    }
    if (impl->ciphertext) {
        free(impl->ciphertext);
    }
    if (impl->shared_secret) {
        free(impl->shared_secret);
    }
    if (impl->kem) {
        OQS_KEM_free(impl->kem);
    }

    free(impl);
    ctx->kem = NULL;
    ctx->public_key = NULL;
    ctx->secret_key = NULL;
    ctx->ciphertext = NULL;
    ctx->shared_secret = NULL;

    return 0;
}

// Utility functions
const char* mlkem768_get_algorithm_name(void)
{
    return UPQC_OQS_KEM_ALG;
}

size_t mlkem768_get_public_key_len(void)
{
    return MLKEM768_PUBLIC_KEY_LEN;
}

size_t mlkem768_get_secret_key_len(void)
{
    return MLKEM768_SECRET_KEY_LEN;
}

size_t mlkem768_get_ciphertext_len(void)
{
    return MLKEM768_CIPHERTEXT_LEN;
}

size_t mlkem768_get_shared_secret_len(void)
{
    return MLKEM768_SHARED_SECRET_LEN;
}



