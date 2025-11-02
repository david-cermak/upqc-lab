#!/usr/bin/env bash

set -euo pipefail

# Deploy vendored liboqs + kyber sources into this component's src/ tree
# and rewrite CMakeLists.txt to use the vendored paths.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMP_DIR="$SCRIPT_DIR"
REPO_ROOT="$(cd "$COMP_DIR/../.." && pwd)"

LIBOQS_DIR="$REPO_ROOT/impl/liboqs"
KYBER_DIR="$REPO_ROOT/impl/kyber"
SRC_DIR="$REPO_ROOT/impl"
DEST_DIR="$COMP_DIR/src"

echo "[deploy_src] repo_root: $REPO_ROOT"
echo "[deploy_src] component: $COMP_DIR"

if [[ ! -d "$LIBOQS_DIR" ]]; then
  echo "[deploy_src] ERROR: liboqs sources not found at: $LIBOQS_DIR" >&2
  exit 1
fi
if [[ ! -d "$KYBER_DIR" ]]; then
  echo "[deploy_src] ERROR: kyber sources not found at: $KYBER_DIR" >&2
  exit 1
fi

echo "[deploy_src] Cleaning destination: $DEST_DIR"
rm -rf "$DEST_DIR/liboqs" "$DEST_DIR/kyber"

if [[ "${1-}" == "CLEAN" ]]; then
  echo "[deploy_src] CLEAN option specified, exiting after clean."
  exit 0
fi

mkdir -p "$DEST_DIR/liboqs/src/kem" "$DEST_DIR/kyber"
mkdir -p "$DEST_DIR/liboqs/src/common"
mkdir -p "$DEST_DIR/liboqs/src/kem/ml_kem"
mkdir -p "$DEST_DIR/liboqs/src/kem/kyber"
mkdir -p "$DEST_DIR/kyber/ref"

echo "[deploy_src] Copying liboqs sources..."

FILES=(
        liboqs/src/kem/kem.c
        liboqs/src/common/common.c
        liboqs/src/kem/ml_kem/kem_ml_kem_768.c
        liboqs/src/kem/kyber/kem_kyber_768.c
        liboqs/src/kem/ml_kem/kem_ml_kem_512.c
        liboqs/src/kem/kyber/kem_kyber_512.c)

for FILE in "${FILES[@]}"; do
  cp "$SRC_DIR/$FILE" "$DEST_DIR/$FILE"
done

echo "[deploy_src] Copying liboqs sources..."

FILES=(
    kyber/ref/kem.c
    kyber/ref/kem.h
    kyber/ref/fips202.c
    kyber/ref/symmetric-shake.c
    kyber/ref/symmetric.h
    kyber/ref/indcpa.c
    kyber/ref/poly.c
    kyber/ref/poly.h
    kyber/ref/polyvec.h
    kyber/ref/params.h
    kyber/ref/cbd.h
    kyber/ref/fips202.h
    kyber/ref/indcpa.h
    kyber/ref/polyvec.c
    kyber/ref/ntt.c
    kyber/ref/ntt.h
    kyber/ref/randombytes.h
    kyber/ref/reduce.h
    kyber/ref/verify.c
    kyber/ref/verify.h
    kyber/ref/reduce.c
    kyber/ref/cbd.c
)

for FILE in "${FILES[@]}"; do
  cp "$SRC_DIR/$FILE" "$DEST_DIR/$FILE"
done
