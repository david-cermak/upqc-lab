# PQC Lab TCP Example

A complete TCP server and client application demonstrating post-quantum cryptography (PQC) with ML‑KEM‑512/768 key exchange and AES‑256‑GCM authenticated encryption.

## Features

- **Post-Quantum Key Exchange**: ML‑KEM‑512 or ML‑KEM‑768 (Kyber)
- **Authenticated Encryption**: AES-256-GCM for message confidentiality and integrity
- **Key Derivation**: HKDF (HMAC-based Key Derivation Function) for symmetric key generation
- **Sequence Numbers**: Protection against replay attacks
- **Bidirectional Communication**: Full duplex encrypted messaging

## Build

```bash
mkdir build
cd build
cmake ..
make
```

### Backend Selection

This example supports OpenSSL or mbedTLS for HKDF and AES‑GCM. Exactly one backend is compiled in, selected at configure time. liboqs provides the KEM.

- Configure exactly one:
  - OpenSSL: `-DUSE_OPENSSL_BACKEND=ON -DUSE_MBEDTLS_BACKEND=OFF` (requires OpenSSL ≥ 3)
  - mbedTLS: `-DUSE_OPENSSL_BACKEND=OFF -DUSE_MBEDTLS_BACKEND=ON` (built from `impl/mbedtls`)

Examples:

```bash
# OpenSSL backend (default)
cmake -DUSE_OPENSSL_BACKEND=ON -DUSE_MBEDTLS_BACKEND=OFF -DUPQC_KEM_LEVEL=512 .. && make -j

# mbedTLS backend (no system OpenSSL required)
cmake -DUSE_OPENSSL_BACKEND=OFF -DUSE_MBEDTLS_BACKEND=ON -DUPQC_KEM_LEVEL=512 .. && make -j
```

## Run

1. Start the server:
```bash
./bin/server
```

2. In another terminal, start the client:
```bash
./bin/client
```

3. Type messages in the client terminal. The server will echo them back.
4. Type `exit` to quit.

## Example Output

### Server Output
```
Server listening on port 3333...
Client connected from 127.0.0.1:37124
Performing ML-KEM-512 handshake...
Handshake completed successfully!
Received (encrypted): asdf
Echo: asdf
Received (encrypted): exit
```

### Client Output
```
Connected to server on port 3333
Performing ML-KEM-512 handshake...
Handshake completed successfully!
Server: Welcome to the PQC Lab Server! (Encrypted)
Type messages to send to server (type 'exit' to quit):
> asdf
Echo: asdf
> exit
Disconnecting...
Client shutdown
```

## Technical Implementation

### Cryptographic Components

1. **ML-KEM-512**: Post-quantum key encapsulation mechanism
   - Public key: 800 bytes
   - Secret key: 1632 bytes
   - Ciphertext: 768 bytes
   - Shared secret: 32 bytes

2. **AES-256-GCM**: Authenticated encryption
   - Key size: 256 bits (32 bytes)
   - IV size: 96 bits (12 bytes)
   - Tag size: 128 bits (16 bytes)

3. **HKDF**: Key derivation function
   - Uses SHA-256 as the underlying hash function
   - Derives AES keys from ML-KEM shared secrets

### Message Format

Each encrypted message follows the structure:
```
[IV (12 bytes)][Encrypted Data][Authentication Tag (16 bytes)]
```

### Security Features

- **Forward Secrecy**: Each session uses fresh ML-KEM key pairs
- **Authentication**: All messages are authenticated using AES-GCM
- **Replay Protection**: Sequence numbers prevent message replay attacks
- **Post-Quantum Security**: Resistant to attacks from quantum computers

## Dependencies

- **OpenSSL 3.0+**: For AES-GCM and HKDF when OpenSSL backend is enabled
- **mbedTLS**: Built from `impl/mbedtls` when enabled (provides HKDF and AES-GCM)
- **liboqs**: Submodule for ML-KEM-512 implementation
- **CMake**: Build system

## Architecture

The implementation is split into a clean primitives API and a single PQC channel backend:
- `crypto_primitives.h`: Backend-agnostic API for HKDF-SHA256 and AES-256-GCM.
- `crypto_primitives_openssl.c` and `crypto_primitives_mbedtls.c`: Per-backend implementations compiled exclusively based on CMake options.
- `crypto_backend_custom_pqc.c`: The PQC channel (ML-KEM-512 handshake + AEAD framing) calling the primitives API with no `#ifdef`s.
- `crypto_backend.h`: Public interface for the host crypto context.
- `server.c` / `client.c`: Application logic.

There is no runtime crypto backend switching; selection is compile-time only.
