# Repository Guidelines

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

