#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"

#include "mlkem768.h"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

// Dedicated secure channel demo:
// - ML-KEM-768 key exchange using liboqs_mlkem component
// - Shared secret stretched to AES-256 key via HKDF-SHA256
// - AES-256-GCM data channel with simple sequence-number AAD

#define TAG "custom_pqc_channel"

// AES-256-GCM parameters (match examples/host)
#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16

// Simple helper to fill a buffer with random bytes using ESP RNG
static void fill_random(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; ) {
        uint32_t r = esp_random();
        size_t chunk = (len - i) < sizeof(r) ? (len - i) : sizeof(r);
        memcpy(out + i, &r, chunk);
        i += chunk;
    }
}

// Derive an AES-256 key from the ML-KEM shared secret using HKDF-SHA256
static int derive_aes_key(const uint8_t *shared_secret, size_t shared_secret_len,
                          uint8_t *aes_key, size_t aes_key_len)
{
    const uint8_t salt[] = "PQC-TCP-SALT";
    const uint8_t info[] = "PQC-TCP-AES-KEY";

    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md == NULL) {
        return -1;
    }

    int ret = mbedtls_hkdf(md,
                           salt, sizeof(salt) - 1,
                           shared_secret, shared_secret_len,
                           info, sizeof(info) - 1,
                           aes_key, aes_key_len);
    return ret;
}

// AES-256-GCM encrypt: out = [IV (12)][ciphertext][TAG (16)]
static int aes_gcm_encrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *out, size_t *out_len)
{
    int ret;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    uint8_t *iv = out;
    fill_random(iv, AES_GCM_IV_SIZE);

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
    if (ret != 0) {
        return ret;
    }

    *out_len = AES_GCM_IV_SIZE + plaintext_len + AES_GCM_TAG_SIZE;
    return 0;
}

// AES-256-GCM decrypt from layout [IV][ciphertext][TAG]
static int aes_gcm_decrypt(const uint8_t *key,
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t *out_len)
{
    if (in_len < AES_GCM_IV_SIZE + AES_GCM_TAG_SIZE) {
        return -1;
    }

    int ret;
    const uint8_t *iv = in;
    const uint8_t *ciphertext = in + AES_GCM_IV_SIZE;
    size_t ciphertext_len = in_len - AES_GCM_IV_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t *tag = in + in_len - AES_GCM_TAG_SIZE;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        return ret;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                   ciphertext_len,
                                   iv, AES_GCM_IV_SIZE,
                                   aad, aad_len,
                                   tag, AES_GCM_TAG_SIZE,
                                   ciphertext,
                                   out);
    mbedtls_gcm_free(&gcm);
    if (ret != 0) {
        return ret;
    }

    *out_len = ciphertext_len;
    return 0;
}

// Helper to encode a 32-bit sequence number as 4-byte big-endian AAD
static void encode_sequence_aad(uint32_t seq, uint8_t aad[4])
{
    aad[0] = (uint8_t)((seq >> 24) & 0xFF);
    aad[1] = (uint8_t)((seq >> 16) & 0xFF);
    aad[2] = (uint8_t)((seq >> 8) & 0xFF);
    aad[3] = (uint8_t)(seq & 0xFF);
}

static void run_pqc_channel_demo(void)
{
    ESP_LOGI(TAG, "=== Demo: Dedicated Secure Channel with ML-KEM-768 + AES-256-GCM ===");
    ESP_LOGI(TAG, "Goal: ML-KEM key exchange -> AES-GCM data channel");

    // Simulated roles: server (keypair + decaps) and client (encaps only)
    mlkem768_ctx_t server_ctx = {0};
    mlkem768_ctx_t client_ctx = {0};

    if (mlkem768_init(&server_ctx) != 0 || mlkem768_init(&client_ctx) != 0) {
        ESP_LOGE(TAG, "Failed to initialize ML-KEM contexts");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Server generating ML-KEM-%s keypair...", mlkem768_get_algorithm_name());
    if (mlkem768_keypair(&server_ctx) != 0) {
        ESP_LOGE(TAG, "Server keypair generation failed");
        goto cleanup;
    }

    // "Publish" server public key to client (in a real demo this would go over TCP)
    ESP_LOGI(TAG, "Client encapsulating shared secret to server public key");
    if (mlkem768_encaps(&client_ctx, server_ctx.public_key) != 0) {
        ESP_LOGE(TAG, "Client encapsulation failed");
        goto cleanup;
    }

    // "Send" ciphertext to server
    memcpy(server_ctx.ciphertext, client_ctx.ciphertext, mlkem768_get_ciphertext_len());

    ESP_LOGI(TAG, "Server decapsulating shared secret from received ciphertext");
    if (mlkem768_decaps(&server_ctx, server_ctx.ciphertext) != 0) {
        ESP_LOGE(TAG, "Server decapsulation failed");
        goto cleanup;
    }

    // Verify both sides derived the same shared secret
    size_t ss_len = mlkem768_get_shared_secret_len();
    if (memcmp(server_ctx.shared_secret, client_ctx.shared_secret, ss_len) != 0) {
        ESP_LOGE(TAG, "Shared secrets DO NOT match!");
        goto cleanup;
    }
    ESP_LOGI(TAG, "Shared secret established successfully (%d bytes)", (int)ss_len);

    // Derive AES-256 keys on both sides via HKDF
    uint8_t server_aes_key[AES_GCM_KEY_SIZE];
    uint8_t client_aes_key[AES_GCM_KEY_SIZE];

    if (derive_aes_key(server_ctx.shared_secret, ss_len,
                       server_aes_key, sizeof(server_aes_key)) != 0 ||
        derive_aes_key(client_ctx.shared_secret, ss_len,
                       client_aes_key, sizeof(client_aes_key)) != 0) {
        ESP_LOGE(TAG, "HKDF key derivation failed");
        goto cleanup;
    }

    if (memcmp(server_aes_key, client_aes_key, AES_GCM_KEY_SIZE) != 0) {
        ESP_LOGE(TAG, "Derived AES keys DO NOT match!");
        goto cleanup;
    }
    ESP_LOGI(TAG, "AES-256-GCM key derived successfully on both sides");

    // Simulate encrypted data channel with sequence-number AAD
    uint32_t server_seq = 0;
    uint32_t client_seq = 0;

    const char *server_msg = "Hello from server over PQC channel\n";
    uint8_t server_aad[4];
    encode_sequence_aad(server_seq, server_aad);

    uint8_t encrypted_from_server[256];
    size_t encrypted_from_server_len = 0;

    if (aes_gcm_encrypt(server_aes_key,
                        server_aad, sizeof(server_aad),
                        (const uint8_t *)server_msg, strlen(server_msg),
                        encrypted_from_server, &encrypted_from_server_len) != 0) {
        ESP_LOGE(TAG, "Server AES-GCM encryption failed");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Server -> Client: encrypted message length = %d bytes",
             (int)encrypted_from_server_len);

    // Client decrypts using its key and expected sequence number
    uint8_t client_aad[4];
    encode_sequence_aad(client_seq, client_aad);

    uint8_t decrypted_on_client[256];
    size_t decrypted_on_client_len = 0;

    if (aes_gcm_decrypt(client_aes_key,
                        client_aad, sizeof(client_aad),
                        encrypted_from_server, encrypted_from_server_len,
                        decrypted_on_client, &decrypted_on_client_len) != 0) {
        ESP_LOGE(TAG, "Client AES-GCM decryption failed");
        goto cleanup;
    }

    decrypted_on_client[decrypted_on_client_len] = '\0';
    ESP_LOGI(TAG, "Client received: %s", (char *)decrypted_on_client);

    // Bump sequence numbers as in real protocol
    server_seq++;
    client_seq++;

    // Optional: Client -> Server message using same channel
    const char *client_msg = "Hello back from client over PQC channel\n";
    encode_sequence_aad(client_seq, client_aad);

    uint8_t encrypted_from_client[256];
    size_t encrypted_from_client_len = 0;

    if (aes_gcm_encrypt(client_aes_key,
                        client_aad, sizeof(client_aad),
                        (const uint8_t *)client_msg, strlen(client_msg),
                        encrypted_from_client, &encrypted_from_client_len) != 0) {
        ESP_LOGE(TAG, "Client AES-GCM encryption failed");
        goto cleanup;
    }

    ESP_LOGI(TAG, "Client -> Server: encrypted message length = %d bytes",
             (int)encrypted_from_client_len);

    uint8_t server_aad2[4];
    encode_sequence_aad(server_seq, server_aad2);

    uint8_t decrypted_on_server[256];
    size_t decrypted_on_server_len = 0;

    if (aes_gcm_decrypt(server_aes_key,
                        server_aad2, sizeof(server_aad2),
                        encrypted_from_client, encrypted_from_client_len,
                        decrypted_on_server, &decrypted_on_server_len) != 0) {
        ESP_LOGE(TAG, "Server AES-GCM decryption failed");
        goto cleanup;
    }

    decrypted_on_server[decrypted_on_server_len] = '\0';
    ESP_LOGI(TAG, "Server received: %s", (char *)decrypted_on_server);

    ESP_LOGI(TAG, "Dedicated secure channel demo completed successfully");

cleanup:
    mlkem768_cleanup(&client_ctx);
    mlkem768_cleanup(&server_ctx);
}

void app_main(void)
{
    run_pqc_channel_demo();
}
