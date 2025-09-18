#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "crypto_backend.h"

#define PORT 3333
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    int opt = 1;

    // Create socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options to reuse address
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind socket to address
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    // Accept client connection
    client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // Initialize crypto context
    crypto_context_t crypto_ctx;
    crypto_error_t err = crypto_init(&crypto_ctx, CRYPTO_BACKEND_CUSTOM_PQC, client_fd);
    if (err != CRYPTO_SUCCESS) {
        printf("Crypto initialization failed: %s\n", crypto_error_string(err));
        close(client_fd);
        close(server_fd);
        return EXIT_FAILURE;
    }

    // Perform ML-KEM-512 handshake
    printf("Performing ML-KEM-512 handshake...\n");
    err = crypto_handshake_server(&crypto_ctx);
    if (err != CRYPTO_SUCCESS) {
        printf("Handshake failed: %s\n", crypto_error_string(err));
        crypto_cleanup(&crypto_ctx);
        close(client_fd);
        close(server_fd);
        return EXIT_FAILURE;
    }
    printf("Handshake completed successfully!\n");

    // Send welcome message
    const char *welcome_msg = "Alice says hello\n";
    err = crypto_send_message(&crypto_ctx, (const uint8_t *)welcome_msg, strlen(welcome_msg));
    if (err != CRYPTO_SUCCESS) {
        printf("Failed to send welcome message: %s\n", crypto_error_string(err));
        crypto_cleanup(&crypto_ctx);
        close(client_fd);
        close(server_fd);
        return EXIT_FAILURE;
    }

    // Encrypted echo loop
    while (1) {
        uint8_t encrypted_buffer[BUFFER_SIZE];
        size_t received_len;
        
        err = crypto_recv_message(&crypto_ctx, encrypted_buffer, &received_len);
        if (err != CRYPTO_SUCCESS) {
            printf("Failed to receive message: %s\n", crypto_error_string(err));
            break;
        }

        // Null-terminate for printing
        encrypted_buffer[received_len] = '\0';
        printf("Received (encrypted): %s", (char *)encrypted_buffer);

        // Echo back the message
        err = crypto_send_message(&crypto_ctx, encrypted_buffer, received_len);
        if (err != CRYPTO_SUCCESS) {
            printf("Failed to send echo: %s\n", crypto_error_string(err));
            break;
        }

        // Check for exit command
        if (strncmp((char *)encrypted_buffer, "exit", 4) == 0) {
            printf("Client requested exit\n");
            break;
        }
    }

    // Cleanup
    crypto_cleanup(&crypto_ctx);
    close(client_fd);
    close(server_fd);
    printf("Server shutdown\n");

    return 0;
}
