#!/usr/bin/env bash
set -euo pipefail

# Suppress all Python warnings during test runs (ensures clean test output)
export PYTHONWARNINGS="ignore"

python -m pytest tests/ "$@"
