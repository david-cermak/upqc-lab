# X25519MLKEM768 Hybrid Key Exchange Implementation Guide

## Overview

This document describes the implementation of the X25519MLKEM768 negotiable group in OpenSSL 3.5.0, which provides a hybrid post-quantum/classical key exchange mechanism for TLS 1.3. The algorithm combines X25519 (classical elliptic curve) with ML-KEM-768 (post-quantum lattice-based KEM) to provide both current security and future quantum resistance.

## Table of Contents

1. [Group Identification](#group-identification)
2. [Algorithm Components](#algorithm-components)
3. [Key Material Structure](#key-material-structure)
4. [Key Negotiation Process](#key-negotiation-process)
5. [Shared Secret Derivation](#shared-secret-derivation)
6. [Symmetric Channel Creation](#symmetric-channel-creation)
7. [Implementation Details](#implementation-details)
8. [Code References](#code-references)

## Group Identification

### TLS Group Identifier
- **Group ID**: `0x11EC` (4588 in decimal)
- **Name**: `X25519MLKEM768`
- **Definition**: `OSSL_TLS_GROUP_ID_X25519MLKEM768` in `include/internal/tlsgroups.h:63`

### Security Bits
- **Security Level**: 192 bits (ML-KEM-768 security level)
- **Definition**: `ML_KEM_768_SECBITS` in `include/crypto/ml_kem.h:109`

### Provider Registration
The group is registered in the capabilities system:
```c
/* 41 */ { OSSL_TLS_GROUP_ID_X25519MLKEM768, ML_KEM_768_SECBITS, TLS1_3_VERSION, 0, -1, -1, 1 }
```
**Reference**: `providers/common/capabilities.c:92`

## Algorithm Components

### Hybrid Structure
The X25519MLKEM768 algorithm combines two key exchange mechanisms:

1. **X25519 (Classical)**: Elliptic curve Diffie-Hellman over Curve25519
   - Public key size: 32 bytes
   - Private key size: 32 bytes
   - Shared secret size: 32 bytes

2. **ML-KEM-768 (Post-Quantum)**: Module-Lattice Key Encapsulation Mechanism
   - Public key size: 1184 bytes
   - Private key size: 2400 bytes
   - Ciphertext size: 1088 bytes
   - Shared secret size: 32 bytes

### Key Material Layout
The hybrid key material is structured as follows:

```
MLX_KEY Structure:
├── mkey (EVP_PKEY*) - ML-KEM-768 key pair
├── xkey (EVP_PKEY*) - X25519 key pair
├── minfo (ML_KEM_VINFO*) - ML-KEM variant info
└── xinfo (ECDH_VINFO*) - X25519 variant info
```

**Reference**: `providers/implementations/include/prov/mlx_kem.h:29-37`

## Key Material Structure

### Public Key Encoding
The public key is encoded as a concatenation:
```
Public Key = ML-KEM-768 Public Key (1184 bytes) || X25519 Public Key (32 bytes)
Total Size: 1216 bytes
```

### Private Key Encoding
The private key is encoded as a concatenation:
```
Private Key = ML-KEM-768 Private Key (2400 bytes) || X25519 Private Key (32 bytes)
Total Size: 2432 bytes
```

### Ciphertext Structure
The ciphertext contains both encapsulated secrets:
```
Ciphertext = ML-KEM-768 Ciphertext (1088 bytes) || X25519 Public Key (32 bytes)
Total Size: 1120 bytes
```

**Reference**: `providers/implementations/kem/mlx_kem.c:123-124`

## Key Negotiation Process

### 1. Key Generation
Both client and server generate hybrid key pairs:

```c
// ML-KEM-768 key generation
key->mkey = EVP_PKEY_Q_keygen(key->libctx, key->propq, "ML-KEM-768");

// X25519 key generation  
key->xkey = EVP_PKEY_Q_keygen(key->libctx, key->propq, "X25519");
```

**Reference**: `providers/implementations/keymgmt/mlx_kmgmt.c:707-711`

### 2. Encapsulation (Client Side)
The client performs hybrid encapsulation:

```c
// ML-KEM encapsulation
EVP_PKEY_encapsulate(ctx, cbuf, &encap_clen, sbuf, &encap_slen);

// X25519 key generation and ECDH
EVP_PKEY_keygen(ctx, &xkey);
EVP_PKEY_derive(ctx, sbuf, &encap_slen);
```

**Reference**: `providers/implementations/kem/mlx_kem.c:165-234`

### 3. Decapsulation (Server Side)
The server performs hybrid decapsulation:

```c
// ML-KEM decapsulation
EVP_PKEY_decapsulate(ctx, sbuf, &decap_slen, cbuf, decap_clen);

// X25519 ECDH
EVP_PKEY_derive(ctx, sbuf, &decap_slen);
```

**Reference**: `providers/implementations/kem/mlx_kem.c:285-322`

## Shared Secret Derivation

### Concatenated Shared Secrets
The final shared secret is the concatenation of both components:

```
Shared Secret = ML-KEM-768 Shared Secret (32 bytes) || X25519 Shared Secret (32 bytes)
Total Size: 64 bytes
```

**Reference**: `providers/implementations/kem/mlx_kem.c:124, 251`

### TLS 1.3 Key Derivation
The concatenated shared secret is used as input to the TLS 1.3 key derivation:

1. **Early Secret**: Derived from PSK or zero
2. **Handshake Secret**: `HKDF-Extract(early_secret, shared_secret)`
3. **Master Secret**: `HKDF-Extract(handshake_secret, derived_secret)`

**Reference**: `ssl/tls13_enc.c:164-239`

## Symmetric Channel Creation

### 1. Secret Generation
```c
int ssl_gensecret(SSL_CONNECTION *s, unsigned char *pms, size_t pmslen)
{
    if (SSL_CONNECTION_IS_TLS13(s)) {
        // Generate early secret
        tls13_generate_secret(s, ssl_handshake_md(s), NULL, NULL, 0, &s->early_secret);
        
        // Generate handshake secret from shared secret
        tls13_generate_handshake_secret(s, pms, pmslen);
    }
}
```

**Reference**: `ssl/s3_lib.c:4981-5004`

### 2. Key Derivation
The handshake secret is used to derive:
- **Client Handshake Traffic Secret**
- **Server Handshake Traffic Secret**  
- **Application Traffic Secret**

### 3. Symmetric Keys
From the traffic secrets, symmetric keys are derived:
- **Client Write Key/IV**
- **Server Write Key/IV**
- **Finished Keys**

## Implementation Details

### Slot Management
The hybrid algorithm uses a slot-based approach:

```c
typedef struct ecdh_vinfo_st {
    int ml_kem_slot;  // 0 or 1 - determines which slot ML-KEM uses
    // ... other fields
} ECDH_VINFO;
```

For X25519MLKEM768:
- `ml_kem_slot = 0` (ML-KEM uses slot 0)
- X25519 uses slot 1

**Reference**: `providers/implementations/keymgmt/mlx_kmgmt.c:46-53`

### Key Material Layout
```c
// Public key layout
pubkey[0:1184]     = ML-KEM-768 public key
pubkey[1184:1216]  = X25519 public key

// Private key layout  
prvkey[0:2400]     = ML-KEM-768 private key
prvkey[2400:2432]  = X25519 private key

// Ciphertext layout
ctext[0:1088]      = ML-KEM-768 ciphertext
ctext[1088:1120]   = X25519 public key

// Shared secret layout
shsec[0:32]        = ML-KEM-768 shared secret
shsec[32:64]       = X25519 shared secret
```

### Error Handling
The implementation includes comprehensive error handling:
- Buffer size validation
- Key material presence checks
- Cryptographic operation validation

**Reference**: `providers/implementations/kem/mlx_kem.c:119-163`

## Code References

### Core Implementation Files
1. **Key Management**: `providers/implementations/keymgmt/mlx_kmgmt.c`
2. **KEM Operations**: `providers/implementations/kem/mlx_kem.c`
3. **Header Definitions**: `providers/implementations/include/prov/mlx_kem.h`
4. **Group Definitions**: `include/internal/tlsgroups.h`
5. **Capabilities**: `providers/common/capabilities.c`

### TLS Integration Files
1. **Key Derivation**: `ssl/tls13_enc.c`
2. **Secret Generation**: `ssl/s3_lib.c`
3. **State Machine**: `ssl/statem/statem_srvr.c`, `ssl/statem/statem_clnt.c`

### Test Files
1. **API Tests**: `test/sslapitest.c` (Test 16)
2. **Group Selection**: `test/tls13groupselection_test.c`
3. **Trace References**: `test/recipes/75-test_quicapi_data/ssltraceref.txt`

### Configuration Files
1. **Provider Registration**: `providers/defltprov.c`, `providers/fips/fipsprov.c`
2. **Names and Descriptions**: `providers/implementations/include/prov/names.h`

## Security Considerations

### Post-Quantum Security
- ML-KEM-768 provides 192-bit security against quantum attacks
- X25519 provides 128-bit security against classical attacks
- Combined security is determined by the stronger component (192-bit)

### Key Material Protection
- Private keys are stored in secure memory when available
- Shared secrets are cleared after use
- Key material is validated before use

### Implementation Validation
- Comprehensive test suite in `test/sslapitest.c`
- Group selection tests in `test/tls13groupselection_test.c`
- Integration tests with QUIC protocol

## Default Configuration

The X25519MLKEM768 group is included in the default TLS group list:

```
?*X25519MLKEM768 / ?*X25519:?secp256r1 / ?X448:?secp384r1:?secp521r1 / ?ffdhe2048:?ffdhe3072
```

This means:
- X25519MLKEM768 is preferred (marked with `*`)
- X25519 is offered as fallback
- Other groups are available as alternatives

**Reference**: `ssl/t1_lib.c:205`, `CHANGES.md:117-121`

## Conclusion

The X25519MLKEM768 implementation provides a robust hybrid key exchange mechanism that combines classical and post-quantum security. The algorithm is well-integrated into OpenSSL's TLS 1.3 implementation and provides a clear path for post-quantum migration while maintaining compatibility with existing classical security assumptions.

The implementation follows OpenSSL's provider architecture and integrates seamlessly with the existing TLS 1.3 key derivation process, ensuring that the hybrid shared secret is properly used to establish secure symmetric channels.
