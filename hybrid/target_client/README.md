# Hybrid TLS 1.3 Client (mbedTLS + ML‑KEM‑768 + X25519)

This target client establishes a TLS 1.3 connection to an OpenSSL 3.5+ server using the hybrid group X25519MLKEM768 (IANA 0x11EC). The client runs on the ESP‑IDF Linux port (or ESP32) and integrates liboqs ML‑KEM‑768 with mbedTLS’ TLS 1.3 stack.

## What’s implemented
- TLS 1.3 handshake with the hybrid key exchange X25519+ML‑KEM‑768
- ClientHello KeyShare serialization: ML‑KEM pk (1184) || X25519 pk (32) → 1216 bytes
- ServerHello KeyShare parsing: ML‑KEM ct (1088) || X25519 pk_s (32) → 1120 bytes
- Shared secret derivation: ML‑KEM ss (32) || X25519 ss (32) → 64 bytes fed into TLS 1.3 key schedule

## Build and run (Linux port)
```bash
# From repo root
cd hybrid/target_client
idf.py build

# In another shell, start an OpenSSL 3.5+ server with the hybrid group:
# (Use your local OpenSSL 3.5+ install; certs are classical, hybrid affects KEX)
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem \
  -subj '/CN=localhost' -days 1
openssl s_server -accept 8443 -tls1_3 -cert cert.pem -key key.pem \
  -www -msg -debug -groups X25519MLKEM768

# Back in the client shell, run the built binary
./build/https_mbedtls.elf
```
You should see “Handshake completed successfully” and the server will print TLS 1.3 and the selected group.

## Quick test (MCP fast test)
If you prefer the automated path used during development:
```bash
# From repo root
mcp_hybrid-pqc-tester_run_fast_test
```
This builds and runs both server and client, capturing both sides’ logs.

## How to inspect and confirm the hybrid group
- With tshark on loopback (Linux):
```bash
sudo tshark -i lo -f "tcp port 8443"
```
You will see the TCP 3‑way handshake, a TLS 1.2 “Client Hello” record header (legacy framing), then a TLS 1.3 ServerHello, EncryptedExtensions, etc.

- To decode TLS details (groups, key shares), use:
```bash
sudo tshark -i lo -Y "tls.handshake.extensions_supported_groups || tls.handshake.extensions_key_share" -O tls
```
Look for these in ClientHello/ServerHello:
- Supported Groups extension includes 0x11ec
- KeyShare (ClientHello): group 0x11ec, key_exchange length 1216
- KeyShare (ServerHello): group 0x11ec, key_exchange length 1120

Notes:
- 0x11EC (decimal 4588) = X25519MLKEM768
- Wireshark may show the ClientHello record as TLS 1.2 due to legacy record‑layer framing; the handshake is TLS 1.3.

## High‑level changes in mbedTLS
The following minimal edits enable the hybrid group end‑to‑end while preserving TLS 1.3 behavior.

- mbedtls/library/ssl_tls13_client.c
  - ClientHello KeyShare writer now dispatches to a hybrid generator when the offered group is X25519MLKEM768.
  - ServerHello KeyShare parser dispatches to a hybrid parser for group 0x11EC.

- mbedtls/library/ssl_hybrid_pqc.c (new helper integration)
  - mbedtls_ssl_tls13_generate_hybrid_x25519mlkem768_key_exchange(...):
    - Generates X25519 via PSA Crypto (to align with existing ECDHE paths).
    - Uses mlkem768_temp component (liboqs) to generate ML‑KEM‑768 keypair.
    - Serializes ML‑KEM pk || X25519 pk (1216 bytes) into ClientHello KeyShare.
    - Stores ML‑KEM secret key (client side) for decapsulation on ServerHello.
  - mbedtls_ssl_tls13_parse_hybrid_x25519mlkem768_key_share(...):
    - Reads 2‑byte key_exchange length and bounds‑checks.
    - Splits ML‑KEM ct (1088) and X25519 pk_s (32).
    - Decapsulates ML‑KEM ss via liboqs and derives X25519 ss via PSA ECDH.
    - Concatenates to 64B hybrid secret and stores it in the handshake context.
  - Zeroization of temporary secrets and proper cleanup paths.

- mbedtls/library/ssl_tls13_keys.c
  - In the handshake key schedule, when group is X25519MLKEM768, the 64B hybrid secret replaces the standard (EC)DHE secret as input to HKDF‑Extract.

- mbedtls/library/ssl_misc.h
  - Handshake struct extended with:
    - uint8_t hybrid_ss[64]; size_t hybrid_ss_len; uint8_t hybrid_ss_valid;
    - uint8_t *mlx_mlkem_sk; size_t mlx_mlkem_sk_len; (client ML‑KEM state)

## ML‑KEM component (liboqs)
- Component: components/mlkem768_temp
  - Wraps liboqs ML‑KEM‑768 (and Kyber ref sources) for ESP‑IDF.
  - Public API in include/mlkem768.h with sizes:
    - MLKEM768_PUBLIC_KEY_LEN  = 1184
    - MLKEM768_SECRET_KEY_LEN  = 2400
    - MLKEM768_CIPHERTEXT_LEN  = 1088
    - MLKEM768_SHARED_SECRET_LEN = 32
  - mlkem768.c allocates and exposes buffers on init, and frees/zeroizes on cleanup.

## Wire formats (reference)
- Client → Server (ClientHello KeyShare):
  - Group: 0x11EC
  - key_exchange = ML‑KEM pk (1184) || X25519 pk (32)
  - Total key_exchange_len = 1216

- Server → Client (ServerHello KeyShare):
  - Group: 0x11EC
  - key_exchange = ML‑KEM ct (1088) || X25519 pk_s (32)
  - Total key_exchange_len = 1120

- Shared secret into TLS 1.3:
  - hybrid_ss = ML‑KEM ss (32) || X25519 ss (32) (64 bytes)

## Security notes
- The demo config sets VERIFY_NONE for local interop; enable verification for real networks.
- Secrets (ML‑KEM sk, intermediate shared secrets, hybrid secret) are zeroized after use.
- No PSK/0‑RTT/early data are used in these tests.

## Troubleshooting
- If the server sends a fatal alert early, check the lengths (1216/1120) and that group 0x11EC appears in both ClientHello and ServerHello KeyShare.
- If Wireshark shows TLS 1.2 for ClientHello, that’s the legacy record‑layer for TLS 1.3; expand the TLS handshake and check the extensions and KeyShare groups.

## References
- OpenSSL hybrid group: X25519MLKEM768 (IANA 0x11EC)
- Implementation guide (server): hybrid/linux_server/X25519MLKEM768_Implementation_Guide.md
- mbedTLS sources changed under: impl/idf/components/mbedtls/mbedtls/library/
- ML‑KEM component: components/mlkem768_temp
