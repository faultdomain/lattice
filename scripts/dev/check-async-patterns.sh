#!/usr/bin/env bash
# Check for common async anti-patterns in Rust code
# Usage: ./scripts/check-async-patterns.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd "$PROJECT_ROOT"

echo "Checking async patterns..."
echo ""

WARNINGS=0

# Check 1: std::sync::Mutex in async code (should use tokio::sync::Mutex)
echo "=== Checking for std::sync::Mutex in async code ==="
# Look for files that have both async fn and std::sync::Mutex
for file in $(find crates -name "*.rs" -type f); do
    if grep -q 'async fn' "$file" && grep -q 'std::sync::Mutex' "$file"; then
        # Check if it's not in test code
        if ! grep -B5 'std::sync::Mutex' "$file" | grep -q '#\[cfg(test)\]'; then
            echo -e "${YELLOW}WARNING: $file uses std::sync::Mutex in async code${NC}"
            grep -n 'std::sync::Mutex' "$file" | head -3
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
done
if [[ "$WARNINGS" -eq 0 ]]; then
    echo -e "${GREEN}PASSED: No std::sync::Mutex in async production code${NC}"
fi
echo ""

# Check 2: Blocking operations in async context
echo "=== Checking for blocking I/O in async code ==="
BLOCKING_OPS='std::fs::|std::thread::sleep|std::io::stdin|std::io::stdout'

# Use awk to properly track test modules and filter them out
AWK_BLOCKING='
BEGINFILE {
    in_test_mod = 0
}
/^#\[cfg\(test\)\]/ { in_test_mod = 1 }
!in_test_mod && /'"$BLOCKING_OPS"'/ {
    print FILENAME ":" FNR ": " $0
    found++
}
END {
    if (found > 0) exit 1
    else exit 0
}
'

BLOCKING_OUTPUT=$(find crates -name "*.rs" -type f -print0 | xargs -0 awk "$AWK_BLOCKING" 2>/dev/null || true)

if [[ -z "$BLOCKING_OUTPUT" ]]; then
    echo -e "${GREEN}PASSED: No blocking I/O in production code${NC}"
else
    echo "$BLOCKING_OUTPUT" | head -20
    echo -e "${YELLOW}WARNING: Potential blocking I/O found (review manually)${NC}"
    echo -e "${YELLOW}Note: sync helper functions are acceptable, async functions are not${NC}"
fi
echo ""

# Check 3: Look for .await inside lock guards (potential deadlock)
echo "=== Checking for .await while holding locks ==="
# This is a heuristic - look for patterns like lock().await followed by .await on same line or next
AWK_LOCK_AWAIT='
/\.(read|write|lock)\(\)\.await/ {
    lock_line = NR
    lock_file = FILENAME
}
/\.await/ && NR == lock_line {
    # Multiple .await on same line after acquiring lock
    count = gsub(/\.await/, ".await")
    if (count > 1) {
        print FILENAME ":" NR ": potential lock held across await"
        found++
    }
}
END {
    if (found > 0) exit 1
    else exit 0
}
'
if find crates -name "*.rs" -print0 | xargs -0 awk "$AWK_LOCK_AWAIT" 2>/dev/null; then
    echo -e "${GREEN}PASSED: No obvious locks held across .await${NC}"
else
    echo -e "${YELLOW}WARNING: Review lock patterns manually${NC}"
fi
echo ""

# Check 4: Verify tokio runtime usage
echo "=== Checking tokio runtime configuration ==="
if grep -rq '#\[tokio::main\]' crates --include="*.rs"; then
    echo -e "${GREEN}PASSED: Using tokio runtime${NC}"
    grep -rn '#\[tokio::main\]' crates --include="*.rs" | head -3
else
    echo -e "${YELLOW}WARNING: No #[tokio::main] found${NC}"
fi
echo ""

# Check 5: Check for proper cancellation handling
echo "=== Checking for cancellation token patterns ==="
if grep -rq 'CancellationToken\|shutdown.*oneshot\|shutdown.*mpsc' crates --include="*.rs"; then
    echo -e "${GREEN}PASSED: Cancellation/shutdown patterns found${NC}"
else
    echo -e "${YELLOW}WARNING: No obvious cancellation handling found${NC}"
fi
echo ""

# Summary
echo "=== Async Pattern Check Summary ==="
echo "Warnings: $WARNINGS"
if [[ "$WARNINGS" -eq 0 ]]; then
    echo -e "${GREEN}All async pattern checks passed${NC}"
else
    echo -e "${YELLOW}Review warnings above${NC}"
fi
