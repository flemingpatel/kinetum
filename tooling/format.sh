#!/usr/bin/env bash
# Kinetum Platform - Code Formatter
#
# Applies .clang-format from project root to all C/C++ source files.
#
# Usage:
#   ./tooling/format.sh          # Format all files in-place
#   ./tooling/format.sh --check  # Check only (no changes, exit 1 if dirty)
#   ./tooling/format.sh --diff   # Show unified diff of what would change (no changes)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Verify .clang-format exists
if [[ ! -f "$PROJECT_ROOT/.clang-format" ]]; then
    echo "error: .clang-format not found in $PROJECT_ROOT" >&2
    exit 1
fi

# Verify clang-format is installed
if ! command -v clang-format &>/dev/null; then
    echo "error: clang-format not found. Install with:" >&2
    echo "  Ubuntu:  sudo apt install clang-format" >&2
    echo "  macOS:   brew install llvm" >&2
    exit 1
fi

# Find helper: null-safe find for all source files
find_sources() {
    find "$PROJECT_ROOT/include" "$PROJECT_ROOT/src" "$PROJECT_ROOT/tests" "$PROJECT_ROOT/validation/native" \
        "$PROJECT_ROOT/tooling/release/packaging" "$PROJECT_ROOT/tooling/release/verification" \
        -type f \( -name '*.hpp' -o -name '*.cpp' -o -name '*.h' -o -name '*.c' \) -print0
}

TOTAL=$(find_sources | tr -cd '\0' | wc -c | tr -d ' ')

MODE="${1:---format}"

case "$MODE" in
    --check)
        echo "Checking $TOTAL files against .clang-format (c++20)..."
        DIRTY=0
        while IFS= read -r -d '' f; do
            if ! clang-format --dry-run --Werror "$f" 2>/dev/null; then
                DIRTY=$((DIRTY + 1))
                echo "  needs formatting: ${f#$PROJECT_ROOT/}"
            fi
        done < <(find_sources)
        if [[ $DIRTY -eq 0 ]]; then
            echo "All $TOTAL files are formatted correctly."
            exit 0
        else
            echo "$DIRTY/$TOTAL files need formatting. Run: ./tooling/format.sh"
            exit 1
        fi
        ;;
    --diff)
        echo "Checking $TOTAL files for formatting differences..."
        HAS_DIFF=0
        while IFS= read -r -d '' f; do
            PATCH=$(diff -u "$f" <(clang-format "$f") || true)
            if [[ -n "$PATCH" ]]; then
                echo "$PATCH"
                HAS_DIFF=1
            fi
        done < <(find_sources)
        if [[ $HAS_DIFF -eq 0 ]]; then
            echo "No formatting differences found."
        fi
        ;;
    --format|"")
        echo "Formatting $TOTAL files..."
        find_sources | xargs -0 clang-format -i
        echo "Done. $TOTAL files formatted."
        ;;
    *)
        echo "Usage: $0 [--check|--diff|--format]" >&2
        exit 1
        ;;
esac
