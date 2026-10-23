#!/usr/bin/env bash
set -euo pipefail

header_dir="${1:-headers}"
standard="${2:-c++17}"
compiler="${CXX:-g++}"
work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT

total=0
while IFS= read -r -d '' header; do
    total=$((total + 1))
    source_file="$work_dir/header-$total.cpp"
    log_file="$work_dir/header-$total.log"
    printf '#include "%s"\nint main() { return 0; }\n' "$header" > "$source_file"
    if ! "$compiler" -std="$standard" -I. -fsyntax-only "$source_file" >"$log_file" 2>&1; then
        echo "[FAIL] $header"
        cat "$log_file"
        exit 1
    fi
done < <(find "$header_dir" -type f -name '*.h' ! -name '*_c.h' -print0)

echo "[PASS] $total generated C++ headers compile as $standard"
