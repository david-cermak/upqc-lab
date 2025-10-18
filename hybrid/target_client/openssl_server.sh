#!/bin/bash

# OpenSSL TLS Server for testing ESP-IDF mbedTLS client with X25519MLKEM768 hybrid group
# This script creates a self-signed certificate and starts an OpenSSL server with hybrid PQC support

# Check if OpenSSL 3.5+ is available
echo "Checking OpenSSL version..."
openssl version -a

echo ""
echo "Creating self-signed certificate for localhost testing..."

# Create a self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

echo ""
echo "Starting OpenSSL TLS server on port 8443 with X25519MLKEM768 hybrid group..."
echo "Server will respond to any HTTP request with a simple hello message"
echo "Debug logging enabled - you'll see detailed handshake information"
echo "Press Ctrl+C to stop the server"
echo ""

# Start the OpenSSL server with TLS 1.3, hybrid group, and debug logging
openssl s_server -accept 8443 -cert server.crt -key server.key \
    -tls1_3 -groups X25519MLKEM768 \
    -www -trace -msg -debug
