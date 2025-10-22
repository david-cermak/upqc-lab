#ifndef MLKEM768_H
#define MLKEM768_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ML-KEM-768 key sizes
#define MLKEM768_PUBLIC_KEY_LEN  1184
#define MLKEM768_SECRET_KEY_LEN  2400
#define MLKEM768_CIPHERTEXT_LEN  1088
#define MLKEM768_SHARED_SECRET_LEN 32

// ML-KEM-768 context
typedef struct {
    void *kem;  // OQS_KEM instance
    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;
} mlkem768_ctx_t;

// ML-KEM-768 API
int mlkem768_init(mlkem768_ctx_t *ctx);
int mlkem768_keypair(mlkem768_ctx_t *ctx);
int mlkem768_encaps(mlkem768_ctx_t *ctx, const uint8_t *public_key);
int mlkem768_decaps(mlkem768_ctx_t *ctx, const uint8_t *ciphertext);
int mlkem768_cleanup(mlkem768_ctx_t *ctx);

// Utility functions
const char* mlkem768_get_algorithm_name(void);
size_t mlkem768_get_public_key_len(void);
size_t mlkem768_get_secret_key_len(void);
size_t mlkem768_get_ciphertext_len(void);
size_t mlkem768_get_shared_secret_len(void);

#ifdef __cplusplus
}
#endif

#endif // MLKEM768_H
