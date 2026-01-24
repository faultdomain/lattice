#!/usr/bin/env bash
# Check for .expect(), .unwrap(), and panic!() in production Rust code
# Usage: ./scripts/check-error-handling.sh [--verbose]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERBOSE="${1:-}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd "$PROJECT_ROOT"

echo "Checking error handling patterns in production code..."
echo ""

# Create a temporary awk script for reuse
AWK_SCRIPT='
BEGINFILE {
    in_test_mod = 0
    in_test_fn = 0
    brace_depth = 0
}

# Track #[cfg(test)] modules
/^[[:space:]]*#\[cfg\(test\)\]/ { in_test_mod = 1 }

# Track #[test] functions (they end when brace depth returns to 0)
/^[[:space:]]*#\[test\]/ { in_test_fn = 1; brace_depth = 0 }

# Track brace depth for test functions
in_test_fn && /{/ { brace_depth += gsub(/{/, "{") }
in_test_fn && /}/ {
    brace_depth -= gsub(/}/, "}")
    if (brace_depth <= 0) in_test_fn = 0
}

# Check for patterns outside test code
!in_test_mod && !in_test_fn {
    if (/\.expect\(/) {
        expect_prod++
        if (verbose) print FILENAME ":" FNR ": [expect] " $0
    }
    if (/\.unwrap\(\)/) {
        unwrap_prod++
        if (verbose) print FILENAME ":" FNR ": [unwrap] " $0
    }
    if (/panic!\(/) {
        panic_prod++
        if (verbose) print FILENAME ":" FNR ": [panic] " $0
    }
}

# Count test code occurrences
in_test_mod || in_test_fn {
    if (/\.expect\(/) expect_test++
    if (/\.unwrap\(\)/) unwrap_test++
    if (/panic!\(/) panic_test++
}

END {
    print ""
    print "=== Error Handling Pattern Summary ==="
    print ""
    printf "%-12s %12s %12s\n", "Pattern", "Production", "Test Code"
    printf "%-12s %12s %12s\n", "--------", "----------", "---------"
    printf "%-12s %12d %12d\n", ".expect()", expect_prod+0, expect_test+0
    printf "%-12s %12d %12d\n", ".unwrap()", unwrap_prod+0, unwrap_test+0
    printf "%-12s %12d %12d\n", "panic!()", panic_prod+0, panic_test+0
    print ""

    total_prod = expect_prod + unwrap_prod + panic_prod
    if (total_prod > 0) {
        print "FAILED: " total_prod " violation(s) found in production code"
        exit 1
    } else {
        print "PASSED: No violations in production code"
        exit 0
    }
}
'

# Run the check
if [[ "$VERBOSE" == "--verbose" || "$VERBOSE" == "-v" ]]; then
    find crates -name "*.rs" -print0 | xargs -0 awk -v verbose=1 "$AWK_SCRIPT"
else
    find crates -name "*.rs" -print0 | xargs -0 awk -v verbose=0 "$AWK_SCRIPT"
fi
