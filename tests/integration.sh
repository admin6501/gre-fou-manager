#!/usr/bin/env bash
set -euo pipefail
TEST_DIR=$(cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$TEST_DIR/integration.py"
