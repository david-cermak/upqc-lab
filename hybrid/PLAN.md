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
