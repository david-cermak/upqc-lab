#!/bin/bash

# OpenSSL TLS Server for testing ESP-IDF mbedTLS client
# This script creates a self-signed certificate and starts an OpenSSL server

echo "Creating self-signed certificate for localhost testing..."

# Create a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

echo "Starting OpenSSL TLS server on port 8443..."
echo "Server will respond to any HTTP request with a simple hello message"
echo "Press Ctrl+C to stop the server"
echo ""

# Start the OpenSSL server
openssl s_server -accept 8443 -cert server.crt -key server.key -www -quiet
