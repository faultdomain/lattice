#!/usr/bin/env bash
# Check for .expect(), .unwrap(), and panic!() in production Rust code
# Usage: ./scripts/check-error-handling.sh [--verbose]
# Requires: gawk (GNU awk) for BEGINFILE support

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
VERBOSE="${1:-}"

cd "$PROJECT_ROOT"

# Check for gawk
if ! command -v gawk &> /dev/null; then
    echo "Error: gawk is required but not installed."
    echo "Install with: apt-get install gawk (Ubuntu) or brew install gawk (macOS)"
    exit 1
fi

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
# Note: .expect() is allowed as it documents the invariant
# Only .unwrap() and panic!() are flagged as violations
!in_test_mod && !in_test_fn {
    if (/\.expect\(/) {
        expect_prod++
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

    # Only unwrap and panic are violations; expect is allowed (documents invariants)
    total_violations = unwrap_prod + panic_prod
    if (total_violations > 0) {
        print "FAILED: " total_violations " violation(s) found in production code"
        print "(.expect() is allowed as it documents invariants)"
        exit 1
    } else {
        print "PASSED: No violations in production code"
        print "(.expect() count: " expect_prod+0 " - allowed)"
        exit 0
    }
}
'

# Run the check using gawk (GNU awk) for BEGINFILE support
# Exclude: build.rs (compile-time), tests/ (E2E tests), benches/ (benchmarks)
if [[ "$VERBOSE" == "--verbose" || "$VERBOSE" == "-v" ]]; then
    find crates -name "*.rs" \
        -not -name "build.rs" \
        -not -path "*/tests/*" \
        -not -path "*/benches/*" \
        -print0 | xargs -0 gawk -v verbose=1 "$AWK_SCRIPT"
else
    find crates -name "*.rs" \
        -not -name "build.rs" \
        -not -path "*/tests/*" \
        -not -path "*/benches/*" \
        -print0 | xargs -0 gawk -v verbose=0 "$AWK_SCRIPT"
fi
