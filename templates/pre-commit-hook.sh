#!/bin/sh
# g0 pre-commit hook — scans AI agent code for security vulnerabilities
# Install: g0 init --hooks
# Remove: rm .git/hooks/pre-commit

set -e

echo "[g0] Running security scan on staged files..."

# Run g0 gate with minimum score threshold
g0 gate . --min-score 70 --no-critical

echo "[g0] Security scan passed."
