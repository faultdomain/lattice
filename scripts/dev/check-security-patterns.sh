#!/usr/bin/env bash
# Check for common security anti-patterns in Rust code
# Usage: ./scripts/check-security-patterns.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd "$PROJECT_ROOT"

echo "Running security pattern checks..."
echo ""

VIOLATIONS=0

# Check 1: Hardcoded secrets patterns
echo "=== Checking for potential hardcoded secrets ==="
# Note: This check has high false positive rate - review results manually
# Excludes: test files, assert statements, mock data
SECRETS_FOUND=0

# Check for hardcoded credentials (excluding test patterns)
SECRETS_PATTERNS='(password|secret|api_key|apikey|credential)\s*=\s*"[^"]+"'
MATCHES=$(grep -rniE "$SECRETS_PATTERNS" crates --include="*.rs" 2>/dev/null | grep -v '_test\.rs\|test_\|tests::\|#\[test\]\|assert\|mock\|Mock\|sample\|Sample\|example\|Example\|fixture' || true)
if [[ -n "$MATCHES" ]]; then
    echo "$MATCHES" | head -10
    SECRETS_FOUND=1
fi

# Check for private keys in non-test code (excluding test files entirely)
PRIVATE_KEY_PATTERN='BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY'
PK_MATCHES=$(grep -rniE "$PRIVATE_KEY_PATTERN" crates --include="*.rs" 2>/dev/null | grep -v '_test\.rs' | grep -v 'assert\|mock\|Mock\|sample\|Sample' || true)
if [[ -n "$PK_MATCHES" ]]; then
    echo "$PK_MATCHES" | head -10
    SECRETS_FOUND=1
fi

if [[ "$SECRETS_FOUND" -eq 1 ]]; then
    echo -e "${YELLOW}WARNING: Potential hardcoded secrets found (review manually - may be test data)${NC}"
else
    echo -e "${GREEN}PASSED: No obvious hardcoded secrets${NC}"
fi
echo ""

# Check 2: Weak crypto algorithms
echo "=== Checking for weak cryptographic algorithms ==="
# Use word boundaries to avoid false positives (e.g., "nodes" matching "des")
WEAK_CRYPTO='\b(md5|sha1|sha-1|des|3des|rc4|arcfour|blowfish)\b'
WEAK_MATCHES=$(grep -rniE "$WEAK_CRYPTO" crates --include="*.rs" 2>/dev/null | grep -v '#\[cfg(test)\]' | grep -v '_test\|test_\|tests::' | grep -v '// \|/// \|//!' | head -10 || true)
if [[ -n "$WEAK_MATCHES" ]]; then
    echo "$WEAK_MATCHES"
    echo -e "${RED}FAILED: Weak cryptographic algorithms found${NC}"
    VIOLATIONS=$((VIOLATIONS + 1))
else
    echo -e "${GREEN}PASSED: No weak cryptographic algorithms${NC}"
fi
echo ""

# Check 3: Verify FIPS crypto backend
echo "=== Checking FIPS crypto configuration ==="
if grep -q 'features.*=.*\["aws-lc-rs"' Cargo.toml && grep -q 'aws-lc-rs' Cargo.toml; then
    echo -e "${GREEN}PASSED: aws-lc-rs FIPS backend configured${NC}"
else
    echo -e "${RED}FAILED: aws-lc-rs FIPS backend not properly configured${NC}"
    VIOLATIONS=$((VIOLATIONS + 1))
fi
echo ""

# Check 4: Unsafe blocks
echo "=== Checking for unsafe blocks ==="
UNSAFE_COUNT=$(grep -rcE 'unsafe\s*\{' crates --include="*.rs" 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}' | tr -d '[:space:]' || echo "0")
if [[ "$UNSAFE_COUNT" -gt 0 ]]; then
    echo -e "${YELLOW}WARNING: $UNSAFE_COUNT unsafe block(s) found (review manually):${NC}"
    grep -rnE 'unsafe\s*\{' crates --include="*.rs" 2>/dev/null | head -10 || true
else
    echo -e "${GREEN}PASSED: No unsafe blocks${NC}"
fi
echo ""

# Check 5: SQL/Command injection patterns (template strings with user input)
echo "=== Checking for potential injection vulnerabilities ==="
# Use gawk to properly track test modules (like check-error-handling.sh)
INJECTION_AWK='
BEGINFILE { in_test_mod = 0 }
/^[[:space:]]*#\[cfg\(test\)\]/ { in_test_mod = 1 }
!in_test_mod && /format!\s*\([^)]*\$\{|execute\s*\(\s*&format!/ {
    print FILENAME ":" FNR ": " $0
}
'
INJECTION_MATCHES=$(find crates -name "*.rs" -not -path "*/tests/*" -print0 2>/dev/null | xargs -0 gawk "$INJECTION_AWK" 2>/dev/null | head -10 || true)
if [[ -n "$INJECTION_MATCHES" ]]; then
    echo "$INJECTION_MATCHES"
    echo -e "${YELLOW}WARNING: Potential injection vulnerability patterns found (review manually)${NC}"
else
    echo -e "${GREEN}PASSED: No obvious injection patterns${NC}"
fi
echo ""

# Check 6: Verify TLS configuration
echo "=== Checking TLS configuration ==="
# Check workspace Cargo.toml and individual crate configs
HAS_RUSTLS=$(grep -rE 'rustls-tls|tls-rustls' Cargo.toml crates/*/Cargo.toml 2>/dev/null || true)
HAS_NATIVE=$(grep -rE 'native-tls' Cargo.toml crates/*/Cargo.toml 2>/dev/null || true)
if [[ -n "$HAS_RUSTLS" ]] && [[ -z "$HAS_NATIVE" ]]; then
    echo -e "${GREEN}PASSED: Using rustls-tls (not native-tls)${NC}"
elif [[ -n "$HAS_NATIVE" ]]; then
    echo -e "${YELLOW}WARNING: native-tls found - prefer rustls-tls${NC}"
    echo "$HAS_NATIVE"
else
    echo -e "${YELLOW}WARNING: No TLS configuration found${NC}"
fi
echo ""

# Summary
echo "=== Security Check Summary ==="
if [[ "$VIOLATIONS" -eq 0 ]]; then
    echo -e "${GREEN}All critical security checks passed${NC}"
    exit 0
else
    echo -e "${RED}$VIOLATIONS critical security violation(s) found${NC}"
    exit 1
fi
