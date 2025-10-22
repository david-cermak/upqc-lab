# Hybrid PQC TLS Handshake Implementation Plan

## Goal
Successfully establish a TLS 1.3 connection between an OpenSSL 3.5+ server using X25519MLKEM768 hybrid group and an ESP32/ESP-IDF mbedTLS client.

## Current Setup
- **Server**: OpenSSL 3.5+ with X25519MLKEM768 hybrid group support
- **Client**: ESP-IDF mbedTLS client (target_client example)
- **Protocol**: TLS 1.3 with hybrid post-quantum cryptography

## ✅ Phase 1: Environment Setup (COMPLETED)
- [x] Verify OpenSSL 3.5+ installation with X25519MLKEM768 support
- [x] Ensure ESP-IDF environment is properly configured
- [x] Test basic OpenSSL server functionality

## ✅ Phase 2: Testing Infrastructure (COMPLETED)
- [x] Create MCP server for automated testing
- [x] Develop shell scripts for manual testing
- [x] Implement build error detection and reporting
- [x] Create comprehensive test output capture

## ✅ Phase 2.5: TLS Version Fix (COMPLETED)
- [x] **TLS 1.3 Negotiation Fixed**: Client now successfully negotiates TLS 1.3 instead of falling back to TLS 1.2
- [x] **Runtime Configuration**: Added explicit TLS version configuration in client code
- [x] **Version Constants**: Used correct `MBEDTLS_SSL_VERSION_TLS1_3` constants
- [x] **Verification**: Server logs confirm TLS 1.3 handshake processing

## ✅ Phase 3: Group Negotiation Investigation (COMPLETED)

### Breakthrough Findings
- **✅ TLS 1.3 Working**: Client successfully negotiates TLS 1.3 with server
- **✅ Group Processing**: Client internally processes X25519MLKEM768 (0x11EC) group
- **✅ Group Propagation**: X25519MLKEM768 group now successfully sent over wire
- **✅ Server Reception**: Server receives and processes the hybrid group

### Evidence
1. **Client printf output**: `*** SIMPLE PRINTF: WRITING GROUP TO WIRE: 0x11ec ***`
2. **Server hex dump**: Shows `11 ec` in supported groups extension: `00 33 00 26 00 24 11 ec 00 20`
3. **TLS 1.3 confirmation**: Server logs show `<<< TLS 1.3, Handshake [length 00d3], ClientHello`
4. **Error Progression**: Changed from `fatal handshake_failure` to `fatal illegal_parameter`

### Root Cause Resolution
- **Problem**: `mbedtls_ssl_tls13_named_group_is_ecdhe` didn't recognize X25519MLKEM768
- **Solution**: Added X25519MLKEM768 to ECDHE group recognition function
- **Additional Fix**: Added X25519MLKEM768 to `tls_id_match_table` in `ssl_tls.c`
- **Result**: Group now successfully propagates through entire mbedTLS stack

## 🎯 Phase 4: Key Exchange Implementation (NEXT)
- **Current Status**: Group negotiation successful, handshake progresses to key exchange
- **New Error**: `fatal illegal_parameter` indicates key share data issue
- **Next Step**: Implement key share generation for X25519MLKEM768 hybrid group
- **Goal**: Complete successful TLS 1.3 handshake with hybrid PQC groups

### Testing Tools Available
1. **MCP Server** (`/home/david/repos/upqc-lab/hybrid/mcp/fast_server.py`)
   - Automated build and test execution
   - Real-time output capture
   - Error detection and reporting
   - Tools: `run_fast_test`, `get_outputs`, `stop_test`

2. **Shell Scripts** (`/home/david/repos/upqc-lab/hybrid/mcp/`)
   - `run.sh` - Complete test execution
   - `run_server.sh` - OpenSSL server only
   - `run_client.sh` - ESP32 client only

3. **Debug Infrastructure**
   - ✅ printf statements in `ssl_client.c` for group processing tracking
   - ✅ Server hex dump analysis for group presence verification
   - ✅ TLS version negotiation confirmation

## 🎯 Phase 3: X25519MLKEM768 Implementation

### OpenSSL Server Implementation (COMPLETED)
- **Location**: `/home/david/repos/upqc-lab/impl/openssl-3.5.0/`
- **Implementation Guide**: `/home/david/repos/upqc-lab/hybrid/linux_server/X25519MLKEM768_Implementation_Guide.md`
- **Key Files**:
  - `providers/implementations/keymgmt/mlx_kmgmt.c` - Key management
  - `providers/implementations/kem/mlx_kem.c` - KEM operations
  - `providers/implementations/include/prov/mlx_kem.h` - Header definitions
  - `include/internal/tlsgroups.h` - Group definitions (Group ID: 0x11EC)

### ESP-IDF mbedTLS Implementation (TODO)
- **Location**: `/home/david/repos/upqc-lab/impl/idf/components/mbedtls/`
- **Target**: Add X25519MLKEM768 support to mbedTLS
- **Key Areas**:
  - Group negotiation support
  - Hybrid key exchange implementation
  - TLS 1.3 integration

### Implementation Strategy
1. **Analyze mbedTLS Group Support**
   - Review current group negotiation code
   - Identify where to add X25519MLKEM768 support
   - Study OpenSSL implementation for reference

2. **Add Group Definition**
   - Define X25519MLKEM768 group ID (0x11EC)
   - Add to supported groups list
   - Implement group-specific parameters

3. **Implement Hybrid Key Exchange**
   - ML-KEM-768 key generation and operations
   - X25519 key generation and ECDH
   - Hybrid shared secret derivation
   - Key material encoding/decoding

4. **TLS 1.3 Integration**
   - Update handshake state machine
   - Modify key derivation process
   - Add debug logging for hybrid operations

### Phase 4: Testing and Validation
- [ ] Test mbedTLS client with X25519MLKEM768 support
- [ ] Verify successful handshake completion
- [ ] Validate hybrid key exchange
- [ ] Test encrypted data exchange
- [ ] Performance benchmarking

## Debug Logging Strategy

### OpenSSL Server Side
- Use `-msg -debug` flags for detailed handshake logging (removed `-trace` for cleaner output)
- Monitor for group negotiation and key exchange details
- Log certificate validation steps

### mbedTLS Client Side
- Enable mbedTLS debug logging
- Add custom debug prints for handshake steps
- Monitor group and cipher suite selection
- Log certificate verification process

## Implementation References

### OpenSSL X25519MLKEM768 Implementation
- **Group ID**: 0x11EC (4588 decimal)
- **Security Level**: 192 bits (ML-KEM-768)
- **Key Sizes**:
  - Public Key: 1216 bytes (1184 ML-KEM + 32 X25519)
  - Private Key: 2432 bytes (2400 ML-KEM + 32 X25519)
  - Ciphertext: 1120 bytes (1088 ML-KEM + 32 X25519)
  - Shared Secret: 64 bytes (32 ML-KEM + 32 X25519)

### Key Implementation Files
1. **OpenSSL Server** (`/home/david/repos/upqc-lab/impl/openssl-3.5.0/`):
   - `providers/implementations/keymgmt/mlx_kmgmt.c` - Key management
   - `providers/implementations/kem/mlx_kem.c` - KEM operations
   - `providers/implementations/include/prov/mlx_kem.h` - Headers
   - `include/internal/tlsgroups.h` - Group definitions

2. **ESP-IDF mbedTLS** (`/home/david/repos/upqc-lab/impl/idf/components/mbedtls/`):
   - `mbedtls/include/mbedtls/ssl.h` - SSL context and configuration
   - `mbedtls/include/mbedtls/ssl_internal.h` - Internal SSL structures
   - `mbedtls/library/ssl_tls13_client.c` - TLS 1.3 client implementation
   - `mbedtls/library/ssl_tls13_generic.c` - Generic TLS 1.3 functions

## Expected Challenges
1. **Group Support**: mbedTLS needs X25519MLKEM768 implementation
2. **Protocol Version**: TLS 1.3 negotiation between OpenSSL and mbedTLS
3. **Certificate Validation**: Self-signed certificate handling
4. **Key Exchange**: Hybrid key exchange algorithm implementation
5. **Memory Constraints**: ESP32 memory limitations for large key sizes

## Success Criteria
- [ ] Successful TLS 1.3 handshake completion
- [ ] X25519MLKEM768 group negotiation confirmed
- [ ] Encrypted data exchange working
- [ ] Both server and client logs show successful handshake
- [ ] Performance acceptable for ESP32 platform

## Next Steps
1. **Analyze mbedTLS Group Support**: Study current group negotiation code
2. **Implement X25519MLKEM768**: Add group definition and key exchange
3. **Test Integration**: Use MCP tools to validate implementation
4. **Optimize for ESP32**: Ensure memory and performance requirements are met

## Testing Commands
```bash
# Run complete test
cd /home/david/repos/upqc-lab/hybrid/mcp && bash run.sh

# Run MCP server test
cd /home/david/repos/upqc-lab/hybrid/mcp && ./venv/bin/python test_mcp.py

# Use MCP tool directly in Cursor
mcp_hybrid-pqc-tester_run_fast_test
```

---
*This plan will be updated as we progress through the implementation process.*

## TLS 1.3 Hybrid Client Implementation (X25519MLKEM768 in mbedTLS)

### Roles Clarification
- Client (mbedTLS):
  - Generate ephemeral X25519 keypair
  - Generate ephemeral ML-KEM-768 keypair
  - Send ClientHello KeyShare with `key_exchange = ML-KEM pk (1184) || X25519 pk (32)`
  - Parse ServerHello KeyShare with `key_exchange = ML-KEM ct (1088) || X25519 pk_s (32)`
  - Compute secrets:
    - ML-KEM decapsulation with client ML-KEM sk and server ML-KEM ct → 32 bytes
    - X25519 ECDH with client X25519 sk and server X25519 pk_s → 32 bytes
    - Concatenate to 64B secret: `ML-KEM ss || X25519 ss` and feed to TLS 1.3 key schedule
- Server (OpenSSL 3.5+):
  - Parse client public `ML-KEM pk || X25519 pk_c`
  - Encapsulate ML-KEM (produce ct and ML-KEM ss)
  - Generate ephemeral X25519 and compute ECDH with X25519 pk_c → X25519 ss
  - Send ServerHello KeyShare with `ML-KEM ct || X25519 pk_s`

This matches `hybrid/linux_server/X25519MLKEM768_Implementation_Guide.md`:
- Public Key (client→server): 1216B = 1184 (ML-KEM pk) + 32 (X25519 pk)
- Ciphertext (server→client): 1120B = 1088 (ML-KEM ct) + 32 (X25519 pk_s)
- Shared Secret: 64B = 32 (ML-KEM ss) + 32 (X25519 ss)

### Integration Points in mbedTLS
- KeyShare write (ClientHello): `library/ssl_tls13_client.c` → `ssl_tls13_write_key_share_ext()`
  - For group `0x11EC`, generate both X25519 and ML-KEM-768 keypairs
  - Serialize key_exchange as `ML-KEM pk || X25519 pk`
  - Store ML-KEM sk and X25519 sk in handshake context
- KeyShare parse (ServerHello): `library/ssl_tls13_client.c` → `ssl_tls13_parse_key_share_ext()`
  - For group `0x11EC`, parse `ML-KEM ct || X25519 pk_s`
  - Compute ECDH and ML-KEM decapsulation; concatenate 64B secret and pass to TLS 1.3 key schedule
- HRR handling: `ssl_tls13_reset_key_share()` must securely free ML-KEM state and regenerate on retry
- Secret plumbing: replace the normal (EC)DHE secret with the 64B hybrid secret for TLS 1.3 key derivation

### Handshake Context Additions
- Add to handshake state:
  - `uint8_t *mlx_mlkem_sk` (2400B)
  - `size_t mlx_mlkem_sk_len`
  - `uint8_t x25519_priv[32]`
  - Ensure secure allocation/zeroization on success/error paths

### LibOQS Integration (Reuse from examples)
- Use `OQS_KEM_new(OQS_KEM_alg_ml_kem_768)`, `OQS_KEM_keypair()`, `OQS_KEM_decaps()`
- Link `liboqs` in ESP-IDF mbedTLS component; add include paths for `oqs/oqs.h`
- Gate with a build option (e.g., `UPQC_ENABLE_HYBRID_11EC`)

### Length and Validation
- ClientHello `key_exchange_len` must be 1216
- ServerHello `key_exchange_len` must be 1120
- Abort with `illegal_parameter` on mismatch

### Security & Zeroization
- Zeroize ML-KEM sk, ML-KEM ss, X25519 priv, and combined secret immediately after use
- Properly handle errors and HRR to avoid key reuse or leaks

### Test Plan
- Interop with OpenSSL server (X25519MLKEM768):
  - Confirm selection of group 0x11EC
  - Validate byte lengths and successful handshake
  - Confirm application data exchange completes
- Negative tests: bad lengths, missing fields, HRR path

### Action Items
- [ ] Add handshake fields for ML-KEM and X25519 client state
- [ ] Implement ClientHello hybrid key_share writer for 0x11EC
- [ ] Implement ServerHello hybrid key_share parser for 0x11EC
- [ ] Compute and inject 64B hybrid secret into TLS 1.3 key schedule
- [ ] HRR reset logic for hybrid assets
- [ ] Build system changes to link liboqs
- [ ] Zeroization and error-handling coverage
- [ ] Interoperability tests with OpenSSL server

## Client-Only Minimal Demo (mbedTLS + liboqs, outside TLS 1.3)

### Goal
Create a minimal, client-only demo that performs post-quantum key establishment using ML-KEM-768 encapsulation (no ML-KEM key generation on client), derives symmetric keys via HKDF, and exchanges AEAD-encrypted application data over a custom TCP channel. This runs entirely outside TLS 1.3, but mirrors the crypto flow needed later inside TLS.

### Scope and Constraints
- Client-only responsibilities:
  - Receive server’s ML-KEM-768 public key
  - Perform ML-KEM-768 encapsulation using liboqs (no KEM key generation on client)
  - Derive an application AEAD key via HKDF-SHA256
  - Send/receive encrypted messages with AES-256-GCM
- Reuse the exact ML-KEM implementation used by the existing target example
  - Location: `examples/target/main/crypto_backend_custom_pqc.c`
  - Configuration: `examples/shared/upqc_config.h` with `UPQC_KEM_LEVEL=768`
- Out of scope for this demo:
  - TLS 1.3 handshake state machine changes
  - Hybrid X25519 + ML-KEM combined secret within TLS
  - Certificate verification and record layer integration

### Why this demo
- Proves the PQC client-side primitive is viable on the target with realistic buffers
- Exercises liboqs ML-KEM-768 encapsulation only (client role)
- Validates HKDF + AEAD glue using mbedTLS primitives
- Provides a stepping stone to map into TLS 1.3 KeyShare logic later

### Architecture
- Transport: plain TCP socket
- Roles:
  - Server (host, Linux): generates ML-KEM-768 keypair; sends public key; decapsulates; echoes messages
  - Client (ESP-IDF, mbedTLS environment): encapsulates; derives symmetric key; encrypts application data
- Crypto primitives on client:
  - ML-KEM-768 (encapsulation only) via liboqs
  - HKDF-SHA256 (mbedTLS helper wrapper already present)
  - AES-256-GCM (mbedTLS helper wrapper already present)

### Wire Protocol (custom channel)
1) Server → Client: `MSG_TYPE_PUBLIC_KEY` + ML-KEM-768 public key (1184 bytes)
2) Client → Server: `MSG_TYPE_CIPHERTEXT` + ML-KEM-768 ciphertext (1088 bytes)
3) Thereafter: `MSG_TYPE_ENCRYPTED` framed messages (IV || ciphertext || tag), with AAD = sequence number (4 bytes, network order)

Message framing (big endian lengths):
- 1 byte: message type
- 4 bytes: payload length `N`
- N bytes: payload

### Implementation Plan
1. Select ML-KEM-768
   - Build with `-DUPQC_KEM_LEVEL=768` so `UPQC_OQS_KEM_ALG = OQS_KEM_alg_ml_kem_768`
   - Confirm buffer sizes match liboqs constants (pk=1184, sk=2400 on server, ct=1088, ss=32)
2. Client role only (encapsulation)
   - Initialize liboqs: `OQS_init()`
   - Create KEM: `OQS_KEM_new(UPQC_OQS_KEM_ALG)`
   - Receive server public key (1184 bytes)
   - Perform `OQS_KEM_encaps()` to obtain ciphertext (1088) and shared secret (32)
3. Key schedule glue
   - Use existing HKDF helper to derive AES-256 key from shared secret
   - Use existing AEAD helpers to encrypt/decrypt application data, with AAD = sequence number
4. Client demo flow
   - Connect to server (host-side demo present in `examples/host`)
   - Run handshake (receive pubkey → encapsulate → send ciphertext)
   - Exchange a few encrypted messages; log timings and sizes
5. Cleanup
   - Zeroize shared secret and AES key on shutdown
   - Free liboqs objects; call `OQS_destroy()`

### Files and Reuse
- Reuse (client side): `examples/target/main/crypto_backend_custom_pqc.c`
  - Functions already present: encapsulation path, HKDF/AEAD wrappers, send/recv framing
- Config: `examples/shared/upqc_config.h` (set `UPQC_KEM_LEVEL=768`)
- Client app entry: `examples/target/main/client.c` (already drives the handshake and echo)
- Host counterpart (for testing): `examples/host/server.c` (generates KEM keypair, decapsulates)

### Build and Run
- Host (server):
  - `cd examples/host && mkdir -p build && cd build`
  - `cmake -DCRYPTO_BACKEND_DEFAULT=openssl .. && make -j`
  - `./bin/server`
- Target (client on Linux mbedTLS env or ESP-IDF):
  - Ensure `UPQC_KEM_LEVEL=768` in build
  - `cd examples/target && idf.py build` (or run via existing MCP scripts)
  - Flash/monitor for ESP32, or run in the provided Linux target env

### Mapping to OpenSSL Hybrid Guide
- OpenSSL’s hybrid X25519MLKEM768 uses: `PublicKey = ML-KEM pk || X25519 pk` and `Ciphertext = ML-KEM ct || X25519 pk` with `SharedSecret = ML-KEM ss || X25519 ss` (64 bytes total)
- This minimal demo implements the ML-KEM portion only (client encapsulates ML-KEM, no ML-KEM keygen on client), which corresponds to the KEM side of the hybrid described in `hybrid/linux_server/X25519MLKEM768_Implementation_Guide.md`
- When moving to TLS 1.3 integration, we will:
  - Add X25519 ephemeral generation on client
  - Combine secrets (ML-KEM 32B || X25519 32B) before TLS 1.3 HKDF-Extract
  - Encode KeyShare consistent with OpenSSL’s hybrid layout

### Risks and Mitigations
- Memory footprint: ensure buffers (≥ 2400 bytes SK on server only, 1184/1088 on client peer) are allocated once and reused
- Timing and performance: log `OQS_KEM_encaps()` latency using `esp_timer`
- Interoperability: use the existing host demo as authoritative counterpart for the wire format

### Tasks
- [ ] Ensure `UPQC_KEM_LEVEL=768` in client build
- [ ] Verify client encapsulation path works end-to-end with host server
- [ ] Measure and log encapsulation latency and message sizes
- [ ] Zeroize secrets and validate no leaks
- [ ] Document results and promote next step to TLS 1.3 hybrid integration
