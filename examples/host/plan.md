# ML-KEM-512 Integration Plan for PQC Lab TCP Demo

## Overview

This plan outlines the integration of ML-KEM-512 (NIST FIPS 203 standardized post-quantum key encapsulation mechanism) into the existing TCP server/client demo application using liboqs.

## Current State Analysis

### Existing Infrastructure
- **TCP Server/Client**: Basic echo server on port 3333 with plain text communication
- **Build System**: CMake-based build with separate server and client executables
- **Platform**: Linux with GCC compiler support

### liboqs ML-KEM-512 Capabilities
- **Algorithm**: ML-KEM-512 (NIST Level 1 security, equivalent to AES-128)
- **Key Sizes**: 
  - Public Key: 800 bytes
  - Secret Key: 1632 bytes  
  - Ciphertext: 768 bytes
  - Shared Secret: 32 bytes
- **Implementation**: Platform-agnostic C reference implementation with optional x86_64/AArch64 optimizations
- **API**: Both direct function calls and generic OQS_KEM object interface

## Integration Strategy

### Phase 1: Build System Integration ✅ **COMPLETED**
**Objective**: Add liboqs as a dependency and configure build system

**Tasks**:
- [x] **Add liboqs as submodule dependency**
  - Reference `../impl/liboqs` in CMakeLists.txt
  - Configure liboqs build with ML-KEM-512 enabled
  - Link against liboqs static library

- [x] **Update CMakeLists.txt**
  ```cmake
  # Add liboqs subdirectory
  add_subdirectory(../../impl/liboqs liboqs)
  
  # Link liboqs to both executables
  target_link_libraries(server oqs)
  target_link_libraries(client oqs)
  
  # Include liboqs headers
  target_include_directories(server PRIVATE ../../impl/liboqs/src)
  target_include_directories(client PRIVATE ../../impl/liboqs/src)
  ```

- [x] **Configure liboqs build options**
  - Enable only ML-KEM-512: `-DOQS_MINIMAL_BUILD="ML-KEM-512"`
  - Use platform-agnostic C implementation (no x86_64/AArch64 optimizations)
  - Build static library: `-DBUILD_SHARED_LIBS=OFF`

**Status**: ✅ Successfully integrated liboqs. Build system now compiles both server and client with liboqs dependency. All executables link correctly against liboqs static library.

## Abstraction Strategy for Future TLS Integration

### Design Philosophy
To enable future migration to standard TLS (mbedTLS/OpenSSL), we'll design an abstraction layer that separates the cryptographic handshake from the transport layer. This allows switching between custom PQC handshake and standard TLS without changing the application logic.

### Proposed Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
│  (server.c / client.c - business logic)                    │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                Communication Abstraction                    │
│  - send_message() / recv_message()                         │
│  - handle_handshake() / establish_secure_channel()         │
│  - encrypt_data() / decrypt_data()                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Cryptographic Backend Interface                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Custom PQC    │  │   mbedTLS       │  │  OpenSSL    │ │
│  │   Handshake     │  │   Backend       │  │  Backend    │ │
│  │   (Current)     │  │   (Future)      │  │  (Future)   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    Transport Layer                          │
│  (TCP socket operations)                                    │
└─────────────────────────────────────────────────────────────┘
```

### Abstraction Interface Design

```c
// crypto_backend.h - Abstract interface for cryptographic operations
typedef enum {
    CRYPTO_BACKEND_CUSTOM_PQC,
    CRYPTO_BACKEND_MBEDTLS,
    CRYPTO_BACKEND_OPENSSL
} crypto_backend_t;

typedef struct crypto_context {
    crypto_backend_t backend;
    void *backend_ctx;  // Backend-specific context
    int socket_fd;
    bool handshake_complete;
    uint8_t *shared_secret;
    size_t shared_secret_len;
} crypto_context_t;

// Core interface functions
int crypto_init(crypto_context_t *ctx, crypto_backend_t backend);
int crypto_handshake_server(crypto_context_t *ctx);
int crypto_handshake_client(crypto_context_t *ctx);
int crypto_send_message(crypto_context_t *ctx, const uint8_t *data, size_t len);
int crypto_recv_message(crypto_context_t *ctx, uint8_t *data, size_t *len);
int crypto_cleanup(crypto_context_t *ctx);
```

### Implementation Strategy

1. **Phase 2A: Custom PQC Backend**
   - Implement `crypto_backend_custom_pqc.c`
   - Handle ML-KEM-512 key exchange
   - Use AES-256-GCM for symmetric encryption
   - Provide full implementation of abstraction interface

2. **Phase 2B: TLS Backend Preparation**
   - Design interface to be TLS-compatible
   - Ensure message format allows TLS record layer
   - Prepare for mbedTLS/OpenSSL integration

3. **Future Migration Path**
   - Implement `crypto_backend_mbedtls.c` or `crypto_backend_openssl.c`
   - Switch backend via configuration or compile-time flag
   - Maintain same application-level API

### Benefits of This Approach

1. **Modularity**: Clear separation between transport, crypto, and application layers
2. **Flexibility**: Easy to switch between custom PQC and standard TLS
3. **Testability**: Each backend can be tested independently
4. **Maintainability**: Changes to crypto implementation don't affect application logic
5. **Future-Proof**: Ready for TLS 1.3 with PQC extensions when available

### Phase 2: Cryptographic Protocol Design
**Objective**: Design secure key exchange protocol over TCP

**Protocol Flow**:
1. **Handshake Phase**:
   - Client connects to server
   - Server generates ML-KEM-512 keypair
   - Server sends public key to client
   - Client generates shared secret using server's public key
   - Client sends ciphertext to server
   - Server decapsulates shared secret

2. **Secure Communication Phase**:
   - Use shared secret for symmetric encryption (AES-256-GCM)
   - Implement message authentication
   - Add sequence numbers to prevent replay attacks

**Message Format**:
```
[Message Type: 1 byte][Length: 4 bytes][Payload: variable]
Message Types:
- 0x01: Public Key (800 bytes)
- 0x02: Ciphertext (768 bytes)  
- 0x03: Encrypted Data
- 0x04: Error
```

### Phase 3: Server Implementation
**Objective**: Implement ML-KEM-512 server-side key exchange

**Key Components**:
1. **ML-KEM-512 Integration**:
   ```c
   #include <oqs/oqs.h>
   #include <oqs/kem_ml_kem.h>
   
   // Initialize liboqs
   OQS_init();
   
   // Create ML-KEM-512 instance
   OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
   if (kem == NULL) {
       // Handle error - ML-KEM-512 not available
   }
   ```

2. **Key Generation**:
   ```c
   uint8_t public_key[OQS_KEM_ml_kem_512_length_public_key];
   uint8_t secret_key[OQS_KEM_ml_kem_512_length_secret_key];
   
   OQS_STATUS rc = OQS_KEM_keypair(kem, public_key, secret_key);
   ```

3. **Decapsulation**:
   ```c
   uint8_t shared_secret[OQS_KEM_ml_kem_512_length_shared_secret];
   OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key);
   ```

4. **Memory Management**:
   - Use `OQS_MEM_secure_free()` for secret keys
   - Use `OQS_MEM_insecure_free()` for public data
   - Implement proper cleanup on connection close

### Phase 4: Client Implementation  
**Objective**: Implement ML-KEM-512 client-side key exchange

**Key Components**:
1. **Public Key Reception**:
   - Receive server's public key (800 bytes)
   - Validate key format and size

2. **Encapsulation**:
   ```c
   uint8_t ciphertext[OQS_KEM_ml_kem_512_length_ciphertext];
   uint8_t shared_secret[OQS_KEM_ml_kem_512_length_shared_secret];
   
   OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, shared_secret, public_key);
   ```

3. **Ciphertext Transmission**:
   - Send ciphertext (768 bytes) to server
   - Verify successful transmission

### Phase 5: Symmetric Encryption Layer
**Objective**: Add AES-256-GCM encryption using shared secret

**Implementation**:
1. **Key Derivation**:
   - Use HKDF to derive AES key from shared secret
   - Generate separate keys for encryption and authentication

2. **Message Encryption**:
   ```c
   // Encrypt user message with AES-256-GCM
   // Include sequence number and timestamp
   // Add authentication tag
   ```

3. **Message Decryption**:
   - Verify authentication tag
   - Check sequence numbers for replay protection
   - Decrypt and display message

### Phase 6: Error Handling & Security
**Objective**: Implement robust error handling and security measures

**Security Measures**:
1. **Input Validation**:
   - Validate all received data sizes
   - Check cryptographic operation return codes
   - Implement timeout mechanisms

2. **Memory Security**:
   - Clear sensitive data from memory
   - Use secure memory allocation for keys
   - Prevent memory leaks

3. **Error Handling**:
   - Graceful degradation on crypto failures
   - Clear error messages for debugging
   - Proper connection cleanup

### Phase 7: Testing & Validation
**Objective**: Comprehensive testing of the integrated system

**Test Cases**:
1. **Basic Functionality**:
   - Successful key exchange
   - Encrypted message transmission
   - Multiple client connections

2. **Error Scenarios**:
   - Invalid public keys
   - Malformed ciphertexts
   - Network interruptions

3. **Security Validation**:
   - Verify shared secrets match
   - Test replay attack prevention
   - Validate memory cleanup

## Implementation Priority

### High Priority (Core Functionality)
1. Build system integration with liboqs
2. Basic ML-KEM-512 key exchange protocol
3. Server and client key generation/encapsulation/decapsulation
4. Simple encrypted message exchange

### Medium Priority (Enhanced Security)
1. AES-256-GCM symmetric encryption
2. Message authentication and integrity
3. Sequence number anti-replay protection
4. Comprehensive error handling

### Low Priority (Advanced Features)
1. Multiple algorithm support (ML-KEM-768, ML-KEM-1024)
2. Performance benchmarking
3. Configuration file support
4. Logging and monitoring

## Technical Considerations

### Platform Compatibility
- **Target**: Linux x86_64 with GCC
- **Implementation**: Use platform-agnostic C reference implementation
- **Dependencies**: Minimal external dependencies (OpenSSL for AES)

### Performance Expectations
- **Key Generation**: ~0.65M cycles (Cortex-M4 reference)
- **Encapsulation**: ~0.96M cycles  
- **Decapsulation**: ~0.96M cycles
- **Memory Usage**: ~2-3KB RAM (optimized implementation)

### Security Considerations
- **Algorithm**: NIST FIPS 203 standardized ML-KEM-512
- **Security Level**: NIST Level 1 (equivalent to AES-128)
- **Implementation**: Production-ready liboqs library
- **Key Management**: Proper secure memory handling

## Success Criteria

1. **Functional**: Successful ML-KEM-512 key exchange between server and client
2. **Security**: Encrypted communication using derived symmetric keys
3. **Reliability**: Robust error handling and connection management
4. **Usability**: Simple build and run process for demonstration
5. **Documentation**: Clear usage instructions and code comments

## Next Steps

1. **Immediate**: Implement Phase 1 (Build System Integration)
2. **Short-term**: Complete Phases 2-4 (Core ML-KEM-512 Integration)
3. **Medium-term**: Add Phases 5-6 (Symmetric Encryption & Security)
4. **Long-term**: Implement Phase 7 (Testing & Advanced Features)

This plan provides a structured approach to integrating ML-KEM-512 into the existing TCP demo, prioritizing production-ready implementations and platform-agnostic code as requested.
