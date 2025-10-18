# Localhost TLS Testing

This directory contains modified examples and tools for testing TLS connections between ESP-IDF and localhost servers.

## Modified Files

- `main/https_mbedtls_example_main.c` - Modified to connect to localhost:8443 with certificate validation disabled

## Server Options

### Option 1: OpenSSL Server (Recommended)
```bash
./openssl_server.sh
```
This script will:
1. Create a self-signed certificate (server.crt and server.key)
2. Start an OpenSSL TLS server on port 8443

### Option 2: Python TLS Server
```bash
# First create the certificate files
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=127.0.0.1" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

# Then run the Python server
python3 tls_server.py
```

## Testing the Connection

1. Start one of the TLS servers above
2. Build and run the ESP-IDF example:
   ```bash
   idf.py build
   idf.py -p /dev/ttyUSB0 flash monitor
   ```

## Key Changes Made

1. **Server Address**: Changed from `www.howsmyssl.com` to `127.0.0.1`
2. **Port**: Changed from `443` to `8443`
3. **Certificate Validation**: Disabled (`MBEDTLS_SSL_VERIFY_NONE`)
4. **Certificate Bundle**: Removed certificate bundle attachment
5. **Request Path**: Simplified to `/hello`

## Troubleshooting

- Make sure the server is running before starting the ESP-IDF example
- Check that port 8443 is not in use by another process
- The ESP-IDF example will retry every 10 seconds if connection fails
- Certificate validation is disabled, so any self-signed certificate will work
