# upqc-lab
A playground for post-quantum cryptography (PQC) on embedded systems and edge devices

## Description

This repository serves as a comprehensive research and development platform for post-quantum cryptography implementation on embedded systems and edge devices. It includes working examples, hybrid PQC implementations, and testing frameworks for evaluating quantum-resistant cryptographic algorithms in resource-constrained environments.

## Overview

Post-quantum cryptography (PQC) has emerged as a critical security technology as organizations prepare for the quantum computing threat. With NIST's finalization of the first PQC standards in August 2024, the field is rapidly transitioning from research to practical implementation, particularly in embedded systems and edge devices where resource constraints present unique challenges.

### The Quantum Threat

The rise of quantum computing threatens all current public-key schemes (RSA, ECC, etc.). Shor's algorithm can break these by efficiently solving factorization or discrete-logarithm problems, making "harvest-now, decrypt-later" attacks a real concern for long-lived IoT data once quantum hardware matures. Embedded devices often use weaker crypto already and remain in service for many years, making the upgrade to quantum-resistant algorithms essential.

### NIST Standards and Algorithm Families

NIST has selected four primary algorithms for standardization:

- **FIPS 203 (ML-KEM)**: Module-Lattice-Based Key-Encapsulation Mechanism, derived from CRYSTALS-Kyber
- **FIPS 204 (ML-DSA)**: Module-Lattice-Based Digital Signature Algorithm based on CRYSTALS-Dilithium  
- **FIPS 205 (SLH-DSA)**: Stateless Hash-Based Digital Signature Algorithm derived from SPHINCS+
- **FIPS 206 (FN-DSA)**: Based on the FALCON algorithm (expected late 2024)

These represent five main mathematical approaches: lattice-based, code-based, hash-based, isogeny-based, and multivariate cryptography. Lattice-based algorithms dominate due to their balance of security, performance, and manageable key sizes.

### Embedded Systems Challenges

**Resource Constraints**: PQC algorithms impose significant resource requirements compared to classical cryptography. While ECC requires only ~32 bytes for keys, ML-KEM-768 needs 1,184 bytes for public keys and up to 2,400 bytes for complete secret keys. Fast implementations of ML-DSA can consume 50 KiB of RAM, problematic for devices with as little as 8-16 KiB available.

**Performance Impact**: Embedded systems face substantial computational overhead. For example, CRYSTALS-Kyber-512 on a 24 MHz Cortex-M4 requires ≈0.65M CPU cycles for keygen and ≈0.96M for decapsulation, using ~9 KB RAM. Highly optimized assembly can cut this roughly in half and reduce RAM to ~2.5 KB. In contrast, hash-based signatures like SPHINCS+ can take tens of seconds to minutes to generate signatures, making them impractical for many IoT uses.

### Key Algorithm Performance on Embedded Systems

| Algorithm | Type | Key/Signature Sizes | Performance Notes |
|-----------|------|-------------------|-------------------|
| **CRYSTALS-Kyber-512** | KEM | Pub Key ~800B; Ciphertext ~768B | Fast (~0.5M cycles decaps on Cortex-M4); low RAM (~2-3KB optimized) |
| **CRYSTALS-Dilithium-2** | Signature | Pub Key ~1300B; Signature ~2420B | Moderate speed: sign ~6.15M cycles, verify ~1.46M cycles on M4; RAM ~12-14KB |
| **Falcon-1024** | Signature | Pub Key ~1.3KB; Signature ~690B | Small signatures but heavy FFT math; slower than Dilithium |
| **SPHINCS+-128f** | Signature | Pub Key ~32B; Signature ~8-10KB | Very large signatures; extremely slow signing (seconds to minutes) |

### Available Tools and Libraries

**Open Quantum Safe (OQS)**: Provides the most comprehensive toolkit with liboqs library offering a unified C API for quantum-resistant algorithms, supporting all NIST-selected standards plus alternative candidates.

**Commercial Solutions**: wolfSSL/wolfCrypt leads with strong early PQC support, implementing ML-KEM (Kyber), ML-DSA (Dilithium), SPHINCS+, plus LMS/HSS and XMSS. It's optimized for x86 and ARM with small footprints and integrates into (D)TLS 1.3, MQTT, SSH.

**Hardware Vendor Solutions**: STMicroelectronics has integrated PQC algorithms into MCUs through X-CUBE-PQC software library. Microchip's MEC175xB MCU family includes immutable hardware engines for ML-DSA, LMS, and ML-KEM.

### Migration Strategies

**Hybrid Approaches**: Combine traditional and PQC algorithms to hedge against both classical and quantum attacks. For key exchange, this involves combining ML-KEM with ECDH. Digital signatures require dual signing with both classical and PQC schemes.

**Cryptographic Agility**: Enable systems to easily update cryptographic algorithms without major architectural changes. This requires standardized interfaces, firmware update capabilities, and hardware roots of trust.

**Edge Computing Offloading**: Leverage edge computing to address IoT device limitations, allowing devices to offload cryptographic tasks to post-quantum edge servers while maintaining local capabilities for critical operations.

### Government Migration Timelines

- **United Kingdom**: Discovery phases by 2028, high-priority migrations by 2031, full transitions by 2035
- **Canada**: Migration plans by April 2026, high-priority systems by end of 2031, remaining systems by 2035  
- **United States**: CNSA 2.0 sets aggressive timelines with exclusive use requirements ranging from 2025 for software/firmware signing to 2033 for legacy equipment

### Market Outlook

The PQC market is experiencing explosive growth, valued at $297.82 million in 2024 and projected to reach $2.49 billion by 2030 with a 42.5% CAGR. This growth is driven by increasing awareness of quantum threats, government mandates, and the "harvest now, decrypt later" attack vector.

### Recommendations for Embedded Developers

1. **Begin cryptographic asset discovery immediately**, prioritizing systems with long data lifespans or critical security functions
2. **Focus on cryptographic agility**, hybrid implementations, and collaboration with hardware vendors
3. **Test PQC libraries on target hardware** (possibly in hybrid mode)
4. **Follow evolving standards** such as NIST's and industry consortium recommendations
5. **Plan for hybrid/rollback paths** until PQC is fully trusted

The window for proactive migration is narrowing - with quantum computers potentially arriving in the early 2030s, organizations must act decisively to protect their digital infrastructure against future quantum threats.

## Host Example & Crypto Backends

A minimal TCP client/server demonstrating ML-KEM-512 + AES-256-GCM lives in `examples/host` (see its README for details). It uses liboqs for KEM and supports OpenSSL or mbedTLS for HKDF and AEAD (AES-GCM).

Build quickstart:

```
cd examples/host && mkdir -p build && cd build
cmake -DCRYPTO_BACKEND_DEFAULT=openssl .. && make -j
# or use mbedTLS for HKDF + AES-GCM
cmake -DUSE_OPENSSL_BACKEND=OFF -DUSE_MBEDTLS_BACKEND=ON -DCRYPTO_BACKEND_DEFAULT=mbedtls .. && make -j
```

Runtime switching is available via `crypto_set_operation_backend(...)` in the example code.

# Repository Coding Guidelines

## Project Structure & Module Organization
- `examples/host/`: TCP client/server demo using ML-KEM-512 + AES-256-GCM; CMake project producing `bin/server`, `bin/client`, `bin/test_backends`.
- `impl/`: third‑party PQC libraries and embedded implementations:
  - `liboqs/` (Open Quantum Safe), `mbedtls/`, `kybesp32/` (ESP‑IDF project with `components/*` and `main/`).
- Docs and notes: `README.md`, `impl/README.md`, `research*.md`.

## Build, Test, and Development Commands
- Host demo (CMake):
  - `cd examples/host && mkdir -p build && cd build`
  - `cmake ..` (requires CMake ≥3.15, a C compiler, OpenSSL dev headers)
  - `make -j` (builds server, client, tests)
  - Run: `./bin/server` and `./bin/client` in separate shells.
  - Options: `cmake -DUSE_MBEDTLS_BACKEND=OFF ..`, `cmake -DCRYPTO_BACKEND_DEFAULT=mbedtls ..`.
- ESP32 (optional): `cd impl/kybesp32 && idf.py build flash monitor` (requires ESP‑IDF).

## Coding Style & Naming Conventions
- C99 with warnings: `-Wall -Wextra`. Prefer 4‑space indentation, K&R braces.
- Names: snake_case for functions/files, UPPER_CASE for macros, `typedef` suffixed `_t`.
- Headers expose public APIs; source files keep internals static. Use header guards and minimal includes.

## Testing Guidelines
- Build tests with the host demo and run `./bin/test_backends` from `examples/host/build`.
- Add focused tests next to sources (e.g., `test_*.c`) and wire them in `examples/host/CMakeLists.txt`.
- Cover new crypto paths, error handling, and backend selection logic.

## Commit & Pull Request Guidelines
- Conventional Commits style: `feat:`, `fix:`, `docs:`, `build:`, `demo:`; include scope when helpful (e.g., `fix(mbedtls): ...`).
- PRs include: clear summary, rationale, how to test, logs/screenshots if relevant, and affected paths (e.g., `examples/host/*`).
- Keep changes minimal and self‑contained; link related issues.

## Security & Configuration Tips
- Never commit secrets or private keys. Zeroize sensitive buffers on error paths.
- OpenSSL is required for the OpenSSL backend; `liboqs` and `mbedtls` build from `impl/` via CMake.

## Agent‑Specific Instructions
- Do not edit generated files (e.g., `examples/host/build/*`).
- Prefer minimal diffs consistent with current structure; update docs when behavior changes.

## How to Run

### Main Application (MCP Server)

To run the main MCP server for hybrid PQC testing:

```bash
cd hybrid/mcp
python fast_server.py
```

This starts the Model Context Protocol (MCP) server that provides tools for running fast hybrid PQC TLS tests between OpenSSL server and mbedTLS client.

### Host Demo (C/C++)

To run the C/C++ host demo:

```bash
cd examples/host && mkdir -p build && cd build
cmake -DCRYPTO_BACKEND_DEFAULT=openssl .. && make -j
# Run server in one terminal
./bin/server
# Run client in another terminal  
./bin/client
```

### ESP32 Target

To build and flash the ESP32 target:

```bash
cd examples/target
idf.py build flash monitor
```

## How to Test

### MCP Server Testing

To test the MCP server functionality:

```bash
cd hybrid/mcp
python test_mcp.py
```

This runs a comprehensive test of the hybrid PQC TLS implementation, including:
- OpenSSL server startup
- mbedTLS client build and execution
- Handshake testing
- Output collection and analysis

### Host Demo Testing

To run the backend tests:

```bash
cd examples/host/build
./bin/test_backends
```

### Unit Testing

Add focused unit tests as `test_*.c` files next to source files and wire them in `examples/host/CMakeLists.txt`. Tests should cover:
- New crypto paths
- Error handling
- Backend selection logic
- Performance benchmarks

