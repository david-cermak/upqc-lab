#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "sdkconfig.h"

#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"

#include "mlkem768.h"

#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// Dedicated secure channel demo:
// - ML-KEM-768 key exchange using liboqs_mlkem component
// - Shared secret stretched to AES-256 key via HKDF-SHA256
// - AES-256-GCM data channel with simple sequence-number AAD

#define TAG "custom_pqc_channel"

// AES-256-GCM parameters (match examples/host)
#define AES_GCM_KEY_SIZE 32
#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16

// Default TCP settings for the demo transport
#define CUSTOM_PQC_SERVER_PORT 3333
#define CUSTOM_PQC_SERVER_ADDR "192.168.0.34"  // Adjust to your server IP when running in client mode

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

// Transport helpers: abstract plain TCP connection setup so the
// underlying medium (TCP, UART, PPP, etc.) can be swapped later.
static int setup_server_connection(void)
{
    int listen_fd = -1;
    int client_fd = -1;
    int opt = 1;
    struct sockaddr_in addr = { 0 };
    socklen_t addr_len = sizeof(addr);

    ESP_LOGI(TAG, "Setting up server socket on port %d", CUSTOM_PQC_SERVER_PORT);

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "socket() failed");
        return -1;
    }

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(CUSTOM_PQC_SERVER_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind() failed");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, 1) < 0) {
        ESP_LOGE(TAG, "listen() failed");
        close(listen_fd);
        return -1;
    }

    ESP_LOGI(TAG, "Waiting for incoming connection...");
    client_fd = accept(listen_fd, (struct sockaddr *)&addr, &addr_len);
    close(listen_fd);

    if (client_fd < 0) {
        ESP_LOGE(TAG, "accept() failed");
        return -1;
    }

    ESP_LOGI(TAG, "Client connected");
    return client_fd;
}

static int setup_client_connection(void)
{
    int sock = -1;
    struct sockaddr_in addr = { 0 };

    ESP_LOGI(TAG, "Connecting to server %s:%d", CUSTOM_PQC_SERVER_ADDR, CUSTOM_PQC_SERVER_PORT);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket() failed");
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(CUSTOM_PQC_SERVER_PORT);

    if (inet_pton(AF_INET, CUSTOM_PQC_SERVER_ADDR, &addr.sin_addr) <= 0) {
        ESP_LOGE(TAG, "inet_pton() failed for %s", CUSTOM_PQC_SERVER_ADDR);
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "connect() failed");
        close(sock);
        return -1;
    }

    ESP_LOGI(TAG, "Connected to server");
    return sock;
}

// Minimal length-prefixed send/recv helpers
static int send_all(int sock, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        ssize_t r = send(sock, buf + sent, len - sent, 0);
        if (r <= 0) {
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

static int recv_all(int sock, uint8_t *buf, size_t len)
{
    size_t recvd = 0;
    while (recvd < len) {
        ssize_t r = recv(sock, buf + recvd, len - recvd, 0);
        if (r <= 0) {
            return -1;
        }
        recvd += (size_t)r;
    }
    return 0;
}

static int send_with_len(int sock, const uint8_t *buf, uint32_t len)
{
    uint32_t net_len = htonl(len);
    if (send_all(sock, (const uint8_t *)&net_len, sizeof(net_len)) != 0) {
        return -1;
    }
    if (len > 0 && send_all(sock, buf, len) != 0) {
        return -1;
    }
    return 0;
}

static int recv_with_len(int sock, uint8_t *buf, size_t max_len, uint32_t *out_len)
{
    uint32_t net_len = 0;
    if (recv_all(sock, (uint8_t *)&net_len, sizeof(net_len)) != 0) {
        return -1;
    }
    uint32_t len = ntohl(net_len);
    if (len > max_len) {
        ESP_LOGE(TAG, "Received length %u exceeds buffer %zu", (unsigned)len, max_len);
        return -1;
    }
    if (len > 0 && recv_all(sock, buf, len) != 0) {
        return -1;
    }
    *out_len = len;
    return 0;
}

// Handshake helpers: perform ML-KEM handshake over the abstracted transport
static int pqc_server_handshake(int sock, uint8_t aes_key[AES_GCM_KEY_SIZE])
{
    mlkem768_ctx_t ctx = {0};
    int ret = -1;

    if (mlkem768_init(&ctx) != 0) {
        ESP_LOGE(TAG, "mlkem768_init (server) failed");
        return -1;
    }

    ESP_LOGI(TAG, "Server generating ML-KEM-%s keypair...", mlkem768_get_algorithm_name());
    if (mlkem768_keypair(&ctx) != 0) {
        ESP_LOGE(TAG, "mlkem768_keypair (server) failed");
        goto out;
    }

    uint32_t pk_len = (uint32_t)mlkem768_get_public_key_len();
    if (send_with_len(sock, ctx.public_key, pk_len) != 0) {
        ESP_LOGE(TAG, "Failed to send public key");
        goto out;
    }

    ESP_LOGI(TAG, "Server waiting for ciphertext from client");
    uint32_t ct_len = 0;
    if (recv_with_len(sock, ctx.ciphertext, mlkem768_get_ciphertext_len(), &ct_len) != 0) {
        ESP_LOGE(TAG, "Failed to receive ciphertext");
        goto out;
    }

    if (ct_len != mlkem768_get_ciphertext_len()) {
        ESP_LOGE(TAG, "Unexpected ciphertext length %u", (unsigned)ct_len);
        goto out;
    }

    if (mlkem768_decaps(&ctx, ctx.ciphertext) != 0) {
        ESP_LOGE(TAG, "mlkem768_decaps (server) failed");
        goto out;
    }

    if (derive_aes_key(ctx.shared_secret,
                       mlkem768_get_shared_secret_len(),
                       aes_key, AES_GCM_KEY_SIZE) != 0) {
        ESP_LOGE(TAG, "Server HKDF key derivation failed");
        goto out;
    }

    ESP_LOGI(TAG, "Server handshake complete, AES key derived");
    ret = 0;

out:
    mlkem768_cleanup(&ctx);
    return ret;
}

static int pqc_client_handshake(int sock, uint8_t aes_key[AES_GCM_KEY_SIZE])
{
    mlkem768_ctx_t ctx = {0};
    int ret = -1;

    if (mlkem768_init(&ctx) != 0) {
        ESP_LOGE(TAG, "mlkem768_init (client) failed");
        return -1;
    }

    ESP_LOGI(TAG, "Client waiting for server public key...");
    uint32_t pk_len = 0;
    if (recv_with_len(sock, ctx.public_key, mlkem768_get_public_key_len(), &pk_len) != 0) {
        ESP_LOGE(TAG, "Failed to receive public key");
        goto out;
    }

    if (pk_len != mlkem768_get_public_key_len()) {
        ESP_LOGE(TAG, "Unexpected public key length %u", (unsigned)pk_len);
        goto out;
    }

    if (mlkem768_encaps(&ctx, ctx.public_key) != 0) {
        ESP_LOGE(TAG, "mlkem768_encaps (client) failed");
        goto out;
    }

    uint32_t ct_len = (uint32_t)mlkem768_get_ciphertext_len();
    if (send_with_len(sock, ctx.ciphertext, ct_len) != 0) {
        ESP_LOGE(TAG, "Failed to send ciphertext");
        goto out;
    }

    if (derive_aes_key(ctx.shared_secret,
                       mlkem768_get_shared_secret_len(),
                       aes_key, AES_GCM_KEY_SIZE) != 0) {
        ESP_LOGE(TAG, "Client HKDF key derivation failed");
        goto out;
    }

    ESP_LOGI(TAG, "Client handshake complete, AES key derived");
    ret = 0;

out:
    mlkem768_cleanup(&ctx);
    return ret;
}

// Demo roles
static void run_server_side(void)
{
    ESP_LOGI(TAG, "=== Demo: Dedicated Secure Channel (SERVER) ===");

    int sock = setup_server_connection();
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to set up server connection");
        return;
    }

    uint8_t aes_key[AES_GCM_KEY_SIZE];
    if (pqc_server_handshake(sock, aes_key) != 0) {
        ESP_LOGE(TAG, "Server handshake failed");
        close(sock);
        return;
    }

    // Send a single encrypted welcome message
    const char *welcome = "Welcome from ML-KEM server over AES-GCM channel\n";
    uint8_t aad[4];
    uint32_t seq = 0;
    encode_sequence_aad(seq, aad);

    uint8_t enc_buf[256];
    size_t enc_len = 0;

    if (aes_gcm_encrypt(aes_key,
                        aad, sizeof(aad),
                        (const uint8_t *)welcome, strlen(welcome),
                        enc_buf, &enc_len) != 0) {
        ESP_LOGE(TAG, "Server AES-GCM encryption failed");
        close(sock);
        return;
    }

    if (send_with_len(sock, enc_buf, (uint32_t)enc_len) != 0) {
        ESP_LOGE(TAG, "Failed to send encrypted welcome message");
        close(sock);
        return;
    }

    ESP_LOGI(TAG, "Sent encrypted welcome message (%d bytes)", (int)enc_len);
    close(sock);
}

static void run_client_side(void)
{
    ESP_LOGI(TAG, "=== Demo: Dedicated Secure Channel (CLIENT) ===");

    int sock = setup_client_connection();
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to set up client connection");
        return;
    }

    uint8_t aes_key[AES_GCM_KEY_SIZE];
    if (pqc_client_handshake(sock, aes_key) != 0) {
        ESP_LOGE(TAG, "Client handshake failed");
        close(sock);
        return;
    }

    // Receive and decrypt the welcome message
    uint8_t enc_buf[256];
    uint32_t enc_len = 0;
    if (recv_with_len(sock, enc_buf, sizeof(enc_buf), &enc_len) != 0) {
        ESP_LOGE(TAG, "Failed to receive encrypted welcome message");
        close(sock);
        return;
    }

    uint8_t aad[4];
    uint32_t expected_seq = 0;
    encode_sequence_aad(expected_seq, aad);

    uint8_t plain_buf[256];
    size_t plain_len = 0;
    if (aes_gcm_decrypt(aes_key,
                        aad, sizeof(aad),
                        enc_buf, enc_len,
                        plain_buf, &plain_len) != 0) {
        ESP_LOGE(TAG, "Client AES-GCM decryption failed");
        close(sock);
        return;
    }

    plain_buf[plain_len] = '\0';
    ESP_LOGI(TAG, "Decrypted welcome: %s", (char *)plain_buf);

    close(sock);
}

#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"
#include "protocol_examples_common.h"


void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());

#if CONFIG_SERVER_SIDE
    run_server_side();
#else
    run_client_side();
#endif
}
