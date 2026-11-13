#!/usr/bin/env bash
# Rebuilds wasm/tree-sitter-rust.wasm from tree-sitter-rust v0.24.2 plus
# patch-grammar.py. Needs git, python3, Node and either Emscripten 4.0.4
# (emcc on PATH) or Docker; tree-sitter-cli 0.25.10 runs through npx.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cli=(npx --yes tree-sitter-cli@0.25.10)

git clone --quiet --depth 1 --branch v0.24.2 https://github.com/tree-sitter/tree-sitter-rust.git "$work/grammar"
python3 "$here/patch-grammar.py" "$work/grammar/grammar.js"
cd "$work/grammar"
"${cli[@]}" generate
"${cli[@]}" test
"${cli[@]}" build --wasm -o "$repo/wasm/tree-sitter-rust.wasm" .
sha256sum "$repo/wasm/tree-sitter-rust.wasm"
