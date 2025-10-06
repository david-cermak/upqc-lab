#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypto_backend.h"
#include "upqc_config.h"
#include "esp_log.h"

#define TAG "client"
#define PORT 3333
#define BUFFER_SIZE 1024
#define SERVER_IP "192.168.0.29"

int client_main()
{
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE];

    // Create socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    // Convert IP address from string to binary
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server on port %d\n", PORT);

    // Initialize crypto context
    crypto_context_t crypto_ctx;
    crypto_error_t err = crypto_init(&crypto_ctx, CRYPTO_BACKEND_CUSTOM_PQC, client_fd);
    if (err != CRYPTO_SUCCESS) {
        printf("Crypto initialization failed: %s\n", crypto_error_string(err));
        close(client_fd);
        return EXIT_FAILURE;
    }

    // Perform handshake using selected ML-KEM parameter set
    ESP_LOGW(TAG, "Performing %s handshake...\n", UPQC_KEM_NAME);
    err = crypto_handshake_client(&crypto_ctx);
    if (err != CRYPTO_SUCCESS) {
        printf("Handshake failed: %s\n", crypto_error_string(err));
        crypto_cleanup(&crypto_ctx);
        close(client_fd);
        return EXIT_FAILURE;
    }
    ESP_LOGW(TAG, "Handshake completed successfully!\n");

    // Receive a welcome message
    uint8_t welcome_buffer[BUFFER_SIZE];
    size_t welcome_len;
    err = crypto_recv_message(&crypto_ctx, welcome_buffer, &welcome_len);
    if (err == CRYPTO_SUCCESS) {
        welcome_buffer[welcome_len] = '\0';
        ESP_LOGI(TAG, "Server: %s", (char *)welcome_buffer);
    }

    // Interactive loop
    // printf("Type messages to send to server (type 'exit' to quit):\n");
    int exit = 0;
    while (1) {
        printf("> ");
        fflush(stdout);
        
        // Read user input
        // if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
        //     break;
        // }
        if (exit)
            strcpy(message, "exit\n\0");
        else
            strcpy(message, "Hello from ESP32\n\0");

        // Send a message to server
        err = crypto_send_message(&crypto_ctx, (const uint8_t *)message, strlen(message));
        if (err != CRYPTO_SUCCESS) {
            printf("Failed to send message: %s\n", crypto_error_string(err));
            break;
        }

        // Check for exit command
        if (strncmp(message, "exit", 4) == 0) {
            printf("Disconnecting...\n");
            break;
        }

        // Receive echo from server
        uint8_t echo_buffer[BUFFER_SIZE];
        size_t echo_len;
        err = crypto_recv_message(&crypto_ctx, echo_buffer, &echo_len);
        if (err != CRYPTO_SUCCESS) {
            printf("Failed to receive echo: %s\n", crypto_error_string(err));
            break;
        }

        echo_buffer[echo_len] = '\0';
        ESP_LOGI(TAG, "Echo: %s", (char *)echo_buffer);
        if (exit)
            break;
        exit = 1;
    }

    // Cleanup
    crypto_cleanup(&crypto_ctx);
    close(client_fd);
    printf("Client shutdown\n");

    return 0;
}
