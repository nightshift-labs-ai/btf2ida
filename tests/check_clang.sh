#!/bin/sh
# Parse btf2c's output with clang, the front end of IDA 9.5's default type parser (TYPE_PARSER = "clang").
#
# usage: tests/check_clang.sh kernel.elf [kernel.elf ...]
#   CLANG=/path/to/clang (default: clang)    CLANG_INCLUDE=dir with stdbool.h (optional; added with -isystem)
#   TARGETS="x86_64-linux-gnu aarch64-linux-gnu" (default)    PYTHON=python3 (default)
#
# For each kernel: btf2c writes the header, the prototypes and the --asserts file; then, for each target,
#   1. clang -fsyntax-only -x c on header + prototypes (what the plugin sends to IDA, in one file)
#   2. clang -fsyntax-only -x c on the _Static_assert file (every struct/union size and member offset)
# One line per (kernel, target, check) with the clang error count; exit 1 if any count is not 0.
# clang only, not IDA: whether IDA's conversion of clang's AST keeps everything is not checked here.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
CLANG=${CLANG:-clang}
PYTHON=${PYTHON:-python3}
TARGETS=${TARGETS:-"x86_64-linux-gnu aarch64-linux-gnu"}
INC=""
[ -n "${CLANG_INCLUDE:-}" ] && INC="-isystem $CLANG_INCLUDE"
[ $# -ge 1 ] || { echo "usage: $0 kernel.elf [kernel.elf ...]" >&2; exit 2; }
"$CLANG" --version | head -1
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
total=0
n=0
for kernel in "$@"; do
    n=$((n + 1))
    d="$WORK/$n"
    mkdir -p "$d"
    # python3 -I drops the script's directory from sys.path, so put the source dir back explicitly.
    if ! "$PYTHON" -I -c 'import sys,runpy; d=sys.argv[1]; sys.path.insert(0,d); sys.argv=[d+"/btf2c.py"]+sys.argv[2:]; runpy.run_path(d+"/btf2c.py", run_name="__main__")' \
            "$HERE" "$kernel" "$d/h.h" --prototypes "$d/p.txt" --asserts "$d/asserts.c" 2>"$d/btf2c.err"; then
        echo "FAIL $kernel: btf2c failed"; cat "$d/btf2c.err"; total=$((total + 1)); continue
    fi
    cat "$d/h.h" "$d/p.txt" > "$d/all.c"
    asserts=$(grep -c '^_Static_assert' "$d/asserts.c")
    for target in $TARGETS; do
        for check in all asserts; do
            # shellcheck disable=SC2086
            (cd "$d" && "$CLANG" -target "$target" -fsyntax-only -ferror-limit=0 $INC -include stdbool.h -x c "$check.c") \
                > "$d/$check.$target.log" 2>&1
            errors=$(grep -c ' error: ' "$d/$check.$target.log")
            warnings=$(grep -c ' warning: ' "$d/$check.$target.log")
            label="header+prototypes"
            [ "$check" = asserts ] && label="asserts($asserts)"
            echo "$(basename "$kernel") $target $label: errors=$errors warnings=$warnings"
            grep ' error: ' "$d/$check.$target.log" | head -5
            total=$((total + errors))
        done
    done
done
echo "check_clang: total errors $total"
[ "$total" -eq 0 ]
