#!/usr/bin/env bash
# Rebuilds wasm/tree-sitter-typescript.wasm and wasm/tree-sitter-tsx.wasm from
# tree-sitter-typescript v0.23.2 plus patch-grammar.py. Needs git, python3,
# Node and either Emscripten 4.0.4 (emcc on PATH) or Docker; tree-sitter-cli
# 0.25.10 runs through npx.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cli=(npx --yes tree-sitter-cli@0.25.10)

git clone --quiet --depth 1 --branch v0.23.2 https://github.com/tree-sitter/tree-sitter-typescript.git "$work/grammar"
python3 "$here/patch-grammar.py" "$work/grammar/common/define-grammar.js"
# the grammar extends tree-sitter-javascript (pinned to the release's lock file)
(cd "$work/grammar" && npm install --no-save --ignore-scripts --no-audit --no-fund tree-sitter-javascript@0.23.1 >/dev/null)
for dialect in typescript tsx; do
  (cd "$work/grammar/$dialect" && "${cli[@]}" generate)
done
cd "$work/grammar"
"${cli[@]}" test
for dialect in typescript tsx; do
  "${cli[@]}" build --wasm -o "$repo/wasm/tree-sitter-$dialect.wasm" "$dialect"
done
sha256sum "$repo/wasm/tree-sitter-typescript.wasm" "$repo/wasm/tree-sitter-tsx.wasm"
