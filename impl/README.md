# Post-Quantum Cryptography Implementation Repositories

This directory contains submodules of different implementation and testing repositories for Post-Quantum Cryptography (PQC) algorithms, with a focus on embedded systems and edge devices.

## Repository Overview

### 1. PQClean
**Purpose**: Clean, portable, tested implementations of post-quantum cryptographic schemes

**Description**: PQClean is a collection of standalone implementations of NIST post-quantum cryptography schemes. It provides clean C code that can be easily integrated into libraries, benchmarking frameworks, and embedded platforms. The implementations are designed to be:
- Highly portable across different platforms
- Suitable for formal verification
- Easy to integrate into other projects
- Well-tested and validated

**Key Features**:
- Clean C99 implementations with no dynamic memory allocation
- Multiple parameter sets for each algorithm
- Optimized versions (AVX2, AArch64) alongside reference implementations
- Comprehensive test suites and validation
- Namespaced APIs to avoid symbol conflicts

**ML-KEM-512 Implementation**: Located in `crypto_kem/ml-kem-512/`, this contains the clean reference implementation of ML-KEM-512 (formerly CRYSTALS-Kyber-512). The implementation includes:
- **API**: Standard KEM interface with keypair generation, encapsulation, and decapsulation
- **Key Sizes**: 800 bytes public key, 1632 bytes secret key, 768 bytes ciphertext
- **Security Level**: NIST Level 1 (equivalent to AES-128)
- **Multiple Variants**: Clean reference, AVX2 optimized, and AArch64 optimized versions

### 2. liboqs (Open Quantum Safe)
**Purpose**: Comprehensive C library providing a unified API for quantum-safe cryptographic algorithms

**Description**: liboqs is the flagship library of the Open Quantum Safe project, providing a common API for quantum-resistant key encapsulation mechanisms (KEMs) and digital signature algorithms. It serves as the foundation for higher-level protocol integrations like TLS, SSH, and X.509.

**Key Features**:
- Unified API for all supported PQC algorithms
- Integration with OpenSSL, OpenSSH, and other protocols
- Language bindings for C++, Python, Rust, and Java
- Comprehensive benchmarking and testing tools
- Support for both NIST standardized and experimental algorithms

**ML-KEM-512 Implementation**: Located in `src/kem/ml_kem/`, this provides the liboqs wrapper around ML-KEM-512 implementations. Features include:
- **Multiple Backends**: Native implementations, CUDA support, and various optimizations
- **API Integration**: Seamless integration with liboqs' unified KEM API
- **Performance Variants**: Reference, x86_64 optimized, and AArch64 optimized versions
- **FIPS 203 Compliance**: Implements the finalized NIST standard

### 3. kyber (Official Reference)
**Purpose**: Official reference implementation of the CRYSTALS-Kyber key encapsulation mechanism

**Description**: This is the original reference implementation from the CRYSTALS-Kyber team, providing the baseline implementation that was submitted to NIST's post-quantum cryptography standardization project. It includes both reference and AVX2-optimized versions.

**Key Features**:
- Official reference implementation from algorithm designers
- Multiple parameter sets (512, 768, 1024)
- AVX2 optimized versions for x86_64 platforms
- Comprehensive test suites and benchmarking tools
- Shared library support

**ML-KEM-512 Implementation**: Located in `ref/`, this is the original Kyber-512 implementation that forms the basis for ML-KEM-512. The API provides:
- **Key Sizes**: 800 bytes public key, 1632 bytes secret key, 768 bytes ciphertext
- **Functions**: `pqcrystals_kyber512_ref_keypair()`, `pqcrystals_kyber512_ref_enc()`, `pqcrystals_kyber512_ref_dec()`
- **Performance**: Reference implementation optimized for clarity, not speed

### 4. kybesp32 (ESP32 Optimization)
**Purpose**: Efficient implementation of CRYSTALS-KYBER on ESP32 microcontrollers

**Description**: This is a research project focused on optimizing Kyber for the ESP32 platform, demonstrating practical implementation techniques for resource-constrained embedded systems. It includes optimizations for dual-core processing and hardware accelerators.

**Key Features**:
- ESP32-specific optimizations using FreeRTOS
- Dual-core processing support
- Hardware accelerator utilization (SHA, AES)
- Performance benchmarking on ESP32-S3
- Component-based architecture for modular integration

**ML-KEM-512 Implementation**: The project implements Kyber-512 (90s variant) with ESP32-specific optimizations:
- **Performance Results** (ESP32-S3 @ 160MHz):
  - Single-core: ~2.4M cycles (keygen), ~2.7M cycles (encaps/decaps)
  - Dual-core: ~2.0M cycles (keygen), ~2.2M cycles (encaps), ~2.5M cycles (decaps)
  - Dual-core + accelerators: ~1.4M cycles (keygen), ~1.5M cycles (encaps), ~1.8M cycles (decaps)
- **Speedup**: Up to 1.72x improvement with dual-core and hardware acceleration
- **Memory**: Optimized for ESP32's memory constraints

## ML-KEM-512 Algorithm Details

ML-KEM-512 (Module-Lattice-Based Key-Encapsulation Mechanism) is the NIST-standardized version of CRYSTALS-Kyber-512, providing:

- **Security Level**: NIST Level 1 (equivalent to AES-128)
- **Key Sizes**: 
  - Public Key: 800 bytes
  - Secret Key: 1632 bytes
  - Ciphertext: 768 bytes
  - Shared Secret: 32 bytes
- **Mathematical Foundation**: Module Learning With Errors (MLWE) over polynomial rings
- **Performance**: Fast key generation, encapsulation, and decapsulation suitable for embedded systems
- **Standardization**: FIPS 203 (finalized August 2024)

## Usage Recommendations

1. **For Research and Development**: Use PQClean for clean, well-tested reference implementations
2. **For Production Applications**: Use liboqs for comprehensive library integration and protocol support
3. **For Embedded Systems**: Study kybesp32 for ESP32-specific optimization techniques
4. **For Algorithm Understanding**: Use the official kyber repository for the original reference implementation

## Getting Started

Each repository contains its own build instructions and documentation. For ML-KEM-512 specifically:

1. **PQClean**: Extract the `ml-kem-512/clean/` directory for a standalone implementation
2. **liboqs**: Use the unified KEM API with `OQS_KEM_ml_kem_512_new()`
3. **kyber**: Use the reference functions `pqcrystals_kyber512_ref_*()`
4. **kybesp32**: Follow ESP-IDF build instructions for ESP32 deployment

## Performance Comparison

| Implementation | Platform | Key Generation | Encapsulation | Decapsulation | Notes |
|----------------|----------|----------------|---------------|---------------|-------|
| PQClean (clean) | Generic | ~0.65M cycles | ~0.96M cycles | ~0.96M cycles | Cortex-M4 @ 24MHz |
| kybesp32 (optimized) | ESP32-S3 | ~1.4M cycles | ~1.5M cycles | ~1.8M cycles | 160MHz, dual-core + accelerators |
| liboqs (native) | x86_64 | Varies | Varies | Varies | Platform-optimized |

*Note: Performance varies significantly based on platform, compiler optimizations, and specific implementation choices.*
