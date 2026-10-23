#!/usr/bin/env bash
set -euo pipefail

ir="${1:-ir/dui70.json}"
out="${2:-target/generated-verification}"
stem="${3:-dui70}"
rm -rf "$out"
mkdir -p "$out"

cargo run --locked -- emit-headers --ir "$ir" --out "$out/headers"
cargo run --locked -- emit-rust --ir "$ir" --out "$out/rust"
cargo run --locked -- emit-syms --ir "$ir" --out "$out/syms" --name "$stem"

bash tests/verify_all_headers.sh "$out/headers" c++17
for standard in c++17 c++20 c++23 c++2c; do
    printf '#include "%s"\nint main() { return 0; }\n' "$out/headers/$stem.h" > "$out/cpp-$standard.cpp"
    clang++ -std="$standard" -I. -fsyntax-only "$out/cpp-$standard.cpp"
done
printf '#include "%s"\n#include "%s"\nstatic_assert(WINDISSECT_C20_PROFILE == 1);\nint main() { return 0; }\n' \
    "$out/headers/${stem}_c.h" "$out/syms/${stem}_syms.h" > "$out/c20-bridge.cpp"
clang++ -std=c++20 -I. -fsyntax-only "$out/c20-bridge.cpp"
printf '#include "%s"\nint main() { return 0; }\n' \
    "$out/headers/windissect_vcalls.h" > "$out/vcalls.cpp"
clang++ -std=c++20 -Wall -Wextra -Werror -I. -fsyntax-only "$out/vcalls.cpp"
printf '#include "%s"\nint main() { return 0; }\n' \
    "$out/headers/windissect_calls.h" > "$out/calls.cpp"
clang++ -std=c++20 -Wall -Wextra -Werror -I. -fsyntax-only "$out/calls.cpp"
printf '#include "%s"\n#include "%s"\nint main(void) { return 0; }\n' \
    "$out/headers/${stem}_c.h" "$out/syms/${stem}_syms.h" > "$out/c-smoke.c"
for standard in c17 c23 c2y; do
    clang -std="$standard" -I. -fsyntax-only "$out/c-smoke.c"
done
RUSTFLAGS="-D warnings" cargo check --manifest-path "$out/rust/Cargo.toml" --offline

echo "[PASS] C17/C23/C26-draft, C++17/20/23/26-draft, Windissect C20, and Rust outputs verified"
