#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 3333
#define BUFFER_SIZE 1024

int main() {
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
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(client_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server on port %d\n", PORT);

    // Receive welcome message
    memset(buffer, 0, BUFFER_SIZE);
    int bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        printf("Server: %s", buffer);
    }

    // Interactive loop
    printf("Type messages to send to server (type 'exit' to quit):\n");
    
    while (1) {
        printf("> ");
        fflush(stdout);
        
        // Read user input
        if (fgets(message, BUFFER_SIZE, stdin) == NULL) {
            break;
        }

        // Send message to server
        if (send(client_fd, message, strlen(message), 0) < 0) {
            perror("Send failed");
            break;
        }

        // Check for exit command
        if (strncmp(message, "exit", 4) == 0) {
            printf("Disconnecting...\n");
            break;
        }

        // Receive echo from server
        memset(buffer, 0, BUFFER_SIZE);
        bytes_received = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Server disconnected\n");
            break;
        }

        printf("Echo: %s", buffer);
    }

    // Cleanup
    close(client_fd);
    printf("Client shutdown\n");

    return 0;
}
