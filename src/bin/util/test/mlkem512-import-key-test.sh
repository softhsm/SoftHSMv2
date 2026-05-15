#! /bin/bash
# This file is in the public domain

CI_TEST_ENABLED="${MLKEM_TEST}"
ALGO_NAME="ML-KEM"
OPENSSL_ALGO="ML-KEM-512"
TOKEN_DIR_NAME="tokens-mlkem-512"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/import-key-test-common.sh"