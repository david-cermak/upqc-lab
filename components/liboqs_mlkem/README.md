# liboqs_mlkem Component

## Overview

The `liboqs_mlkem` component provides an ESP-IDF wrapper for the ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) post-quantum cryptographic algorithm. ML-KEM is the standardized name for the algorithm previously known as CRYSTALS-Kyber, as specified in [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

This component implements ML-KEM using two underlying libraries:
- **liboqs**: The Open Quantum Safe library, providing a unified API for post-quantum cryptographic algorithms
- **Kyber Reference Implementation**: The official reference implementation of CRYSTALS-Kyber from the algorithm designers

## Purpose

This component is designed to provide a simple, easy-to-use API for ML-KEM operations in ESP32 applications, abstracting away the complexity of the underlying libraries while maintaining full compatibility with the NIST-standardized algorithm.

## Underlying Libraries

### liboqs (Open Quantum Safe)

**liboqs** is an open-source C library for quantum-safe cryptographic algorithms, developed as part of the [Open Quantum Safe (OQS) project](https://openquantumsafe.org/). It provides:

- A unified API for multiple post-quantum cryptographic algorithms
- Implementation of NIST-standardized algorithms (ML-KEM and ML-DSA)
- Support for experimental post-quantum algorithms
- Cross-platform compatibility

**License**: MIT  
**Source**: Located in `impl/liboqs/`

### Kyber Reference Implementation

The **CRYSTALS-Kyber reference implementation** is the official baseline implementation from the algorithm's designers. This component uses the reference implementation (`kyber/ref/`) which provides:

- Original reference code submitted to NIST's post-quantum cryptography standardization
- Multiple parameter sets (512, 768, 1024)
- Pure C implementation suitable for embedded systems

**Original Authors**:
- Joppe Bos
- Léo Ducas
- Eike Kiltz
- Tancrède Lepoint
- Vadim Lyubashevsky
- John Schanck
- Peter Schwabe
- Gregor Seiler
- Damien Stehlé

**Source**: Located in `src/kyber/ref/`

## API

The component provides a simplified C API for ML-KEM operations through `include/mlkem768.h`.

### Data Structures

```c
typedef struct {
    void *kem;              // Internal OQS_KEM instance
    uint8_t *public_key;    // Public key buffer
    uint8_t *secret_key;    // Secret key buffer
    uint8_t *ciphertext;    // Ciphertext buffer
    uint8_t *shared_secret; // Shared secret buffer
} mlkem768_ctx_t;
```

### Key Sizes (ML-KEM-768)

- **Public Key**: 1,184 bytes
- **Secret Key**: 2,400 bytes
- **Ciphertext**: 1,088 bytes
- **Shared Secret**: 32 bytes

### Functions

#### Initialization and Cleanup

```c
int mlkem768_init(mlkem768_ctx_t *ctx);
int mlkem768_cleanup(mlkem768_ctx_t *ctx);
```

- `mlkem768_init()`: Initialize the ML-KEM context and allocate memory for keys
- `mlkem768_cleanup()`: Free all allocated resources

#### Core Operations

```c
int mlkem768_keypair(mlkem768_ctx_t *ctx);
int mlkem768_encaps(mlkem768_ctx_t *ctx, const uint8_t *public_key);
int mlkem768_decaps(mlkem768_ctx_t *ctx, const uint8_t *ciphertext);
```

- `mlkem768_keypair()`: Generate a public/secret key pair
- `mlkem768_encaps()`: Encapsulate a shared secret using a public key
- `mlkem768_decaps()`: Decapsulate a shared secret using a ciphertext and secret key

#### Utility Functions

```c
const char* mlkem768_get_algorithm_name(void);
size_t mlkem768_get_public_key_len(void);
size_t mlkem768_get_secret_key_len(void);
size_t mlkem768_get_ciphertext_len(void);
size_t mlkem768_get_shared_secret_len(void);
```

Return algorithm information and key sizes.

### Return Values

All functions return:
- `0` on success
- `-1` on error (invalid parameters or operation failure)

## Configuration

The component supports two ML-KEM parameter sets, configurable via CMake cache variable:

```cmake
set(UPQC_KEM_LEVEL "768" CACHE STRING "Select ML-KEM parameter set: 512 or 768")
```

- **512**: ML-KEM-512 (NIST Level 1 security, equivalent to AES-128)
- **768**: ML-KEM-768 (NIST Level 3 security, equivalent to AES-192) - **Default**

The selected parameter set determines:
- The Kyber K value (2 for 512, 3 for 768)
- Which liboqs wrapper files are compiled (`kem_ml_kem_512.c` or `kem_ml_kem_768.c`)
- The key sizes and security level

## Component Structure

```
components/liboqs_mlkem/
├── CMakeLists.txt              # Component build configuration
├── mlkem768.c                  # Component wrapper implementation
├── randombytes.c               # Random number generation for ESP32
├── include/
│   ├── mlkem768.h              # Public API header
│   └── oqs/                    # liboqs headers
├── src/
│   ├── liboqs/                 # liboqs source files
│   │   └── src/
│   │       ├── common/         # Common liboqs utilities
│   │       └── kem/            # KEM implementations
│   │           ├── ml_kem/     # ML-KEM wrappers
│   │           └── kyber/      # Kyber-specific wrappers
│   └── kyber/
│       └── ref/                # Kyber reference implementation
│           ├── kem.c           # Main KEM operations
│           ├── indcpa.c        # IND-CPA encryption
│           ├── poly.c          # Polynomial operations
│           ├── polyvec.c       # Polynomial vector operations
│           ├── ntt.c           # Number Theoretic Transform
│           ├── fips202.c       # SHA-3 (FIPS 202) implementation
│           └── ...             # Other cryptographic primitives
├── examples/
│   └── simple/                 # Simple usage example
└── tests/
    └── performance/            # Performance benchmark test
```

## Usage Example

```c
#include "mlkem768.h"
#include "esp_log.h"

void app_main(void)
{
    mlkem768_ctx_t ctx;
    
    // Initialize context
    if (mlkem768_init(&ctx) != 0) {
        ESP_LOGE("APP", "Failed to initialize ML-KEM");
        return;
    }
    
    // Generate key pair
    if (mlkem768_keypair(&ctx) != 0) {
        ESP_LOGE("APP", "Failed to generate keypair");
        mlkem768_cleanup(&ctx);
        return;
    }
    
    // Encapsulate shared secret (sender side)
    if (mlkem768_encaps(&ctx, ctx.public_key) != 0) {
        ESP_LOGE("APP", "Failed to encapsulate");
        mlkem768_cleanup(&ctx);
        return;
    }
    
    // Decapsulate shared secret (receiver side)
    if (mlkem768_decaps(&ctx, ctx.ciphertext) != 0) {
        ESP_LOGE("APP", "Failed to decapsulate");
        mlkem768_cleanup(&ctx);
        return;
    }
    
    // Clean up
    mlkem768_cleanup(&ctx);
    
    ESP_LOGI("APP", "ML-KEM operations completed successfully");
}
```

## Implementation Details

### Architecture

1. **Component Wrapper (`mlkem768.c`)**: Provides a simplified ESP-IDF-specific API
2. **liboqs Layer**: Provides the unified KEM interface and algorithm management
3. **Kyber Reference**: Implements the actual cryptographic operations

The component uses liboqs as an abstraction layer that internally calls the Kyber reference implementation for the cryptographic operations.

### Memory Management

- All key buffers are dynamically allocated during `mlkem768_init()`
- Buffers are automatically freed in `mlkem768_cleanup()`
- Keys are accessible through the context structure for use by the application

### Random Number Generation

The component includes `randombytes.c` which provides cryptographically secure random number generation using ESP32's hardware RNG (`esp_random()`).

## Examples and Tests

- **Simple Example**: `examples/simple/` - Basic usage demonstration
- **Performance Test**: `tests/performance/` - Comprehensive performance benchmarks including timing, stack usage, and heap usage

## Flash Memory Usage

The component's flash memory footprint (for ML-KEM-768):

- **Total**: 10,756 bytes
- **Flash Code (.text)**: 10,308 bytes
- **Flash Data (.rodata)**: 448 bytes
- **RAM**: No static RAM usage (all allocation is dynamic via heap)

See `tests/performance/README.md` for detailed performance metrics.

## Security Considerations

- This implementation uses the reference implementation which prioritizes correctness over performance
- The component provides NIST Level 3 security (equivalent to AES-192) for ML-KEM-768
- All operations are designed to be constant-time where applicable
- Random number generation uses ESP32's hardware RNG

## License

This component integrates code from multiple sources with different licenses:

- **Port Layer** (ESP-IDF wrapper): Apache License 2.0
- **liboqs**: MIT License
- **Kyber Reference**: Public Domain (CC0) OR Apache License 2.0

For complete license information and details, see [LICENSE.txt](LICENSE.txt) in this directory.

All licenses are compatible, allowing the combined work to be distributed under the terms of each respective license.

## References

- [NIST FIPS 203 - ML-KEM Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [liboqs Documentation](https://github.com/open-quantum-safe/liboqs)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)

