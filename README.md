# sentinel-ir

Structural IR for AI reasoning over code.

`sentinel-ir` turns a JavaScript or TypeScript source file into a small, structural JSON
description — routes, exports, imports, environment reads, network /
filesystem / process / crypto calls, dangerous syntax and a risk level — built
from the [tree-sitter](https://tree-sitter.github.io/) AST. You send that IR to
an LLM instead of the raw file.

**Supported languages:**

| `language` | grammar | picked for `target` ending in |
|---|---|---|
| `javascript` (default) | `tree-sitter-javascript` | `.js` `.mjs` `.cjs` `.jsx`, or no / unknown extension |
| `typescript` | `tree-sitter-typescript` 0.23.2 | `.ts` `.mts` `.cts` (incl. `.d.ts`) |
| `tsx` | `tree-sitter-tsx` 0.23.2 | `.tsx` |

Other languages are not supported. An explicit unsupported `language`
(e.g. `"python"`) is reported as `analysisStatus: "incomplete"` instead of
being parsed with the wrong grammar. Source that does not parse falls back to
text heuristics and the IR says so (`facts.ast: false`).

## Why send IR instead of the raw file

- **Fewer tokens.** The compressed IR has a roughly fixed size of about
  400 characters plus the facts the file actually has, so the larger the file,
  the larger the saving. Measured with `node examples/basic.js <file>` on this
  package's own sources:

  | file | raw chars | IR chars |
  |---|---:|---:|
  | `src/ast-facts.js` | 21,823 | 449 |
  | `src/sentinel-ir.js` | 9,123 | 515 |
  | `src/tree-parser.js` | 4,393 | 465 |
  | `examples/basic.js` | 600 | 461 |

  For very small files the IR is about as large as the source; it does not pay
  off there. These are character counts, not billed tokens of any specific model.

- **Less untrusted text in the prompt.** Comments, string bodies and function
  bodies are not copied into the IR, so instructions hidden there do not reach
  the model through it. The IR does still contain identifiers and some
  literals taken from the code (route paths, module specifiers, export names,
  environment variable names, callee names), so it *reduces* the
  prompt-injection surface; it does not remove it. Treat model output as
  untrusted either way.

- **Facts, not guesses.** Every structural claim comes from AST nodes: a route
  is a call on `app`/`router`/`server`/`api` with a string path, `exec` is only
  process spawning when it is bound to a spawning module, and a function named
  `evaluate` is not `eval`. Each risk signal keeps the syntax and line that
  produced it (`dynamic_code:eval@2`). `facts.ast: true` means a missing
  category is a proven absence in the parsed file.

The trade-off: the IR is lossy by design. It is meant for reasoning *about* a
file (what it touches, how risky a change is, what to look at), not for an LLM
to rewrite code it can no longer see.

## Install

```sh
npm install sentinel-ir
```

Requires Node.js 20 or newer. The native `tree-sitter` packages are optional dependencies. When no parser has been initialized, `analyze()` attempts to initialize the native parser and does not automatically fall back to WebAssembly if that fails. Use `analyzeAsync()` to initialize the bundled WebAssembly parser before analysis.

## Usage

```js
const { analyzeAsync, compress } = require("sentinel-ir");

const code = `
const express = require("express");
const fs = require("fs");
const app = express();
app.post("/upload", (req, res) => { fs.writeFileSync("/tmp/x", req.body); res.end(); });
app.listen(process.env.PORT);
`;

async function main() {
  const ir = await analyzeAsync(code, { target: "src/server.js" });
  console.log(JSON.stringify(compress(ir), null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

Output:

```json
{
  "analysisStatus": "complete",
  "language": "javascript",
  "mission": { "target": "src/server.js", "objective": "filesystem_simplification" },
  "world": { "pressure": 0.5, "confidence": 0.75, "budget": 0.015, "risk": "medium" },
  "constraints": ["preserve_api", "avoid_breaking_changes"],
  "forbidden": [],
  "summary": { "size": 205, "lines": 7, "hasCrypto": false, "hasFilesystem": true, "hasNetwork": true },
  "facts": {
    "ast": true,
    "routes": ["POST /upload"],
    "imports": ["express", "fs"],
    "env": ["PORT"],
    "operations": ["inboundHttp", "diskWrite"],
    "calls": { "network": ["app.listen", "app.post"], "filesystem": ["fs.writeFileSync"] },
    "riskSignals": ["disk_write:fs.writeFileSync@5", "inbound_http:app.listen@6"]
  }
}
```

Run `npm run example -- path/to/file.js` to see the IR of any file and its size
next to the raw source.

## WebAssembly parser

`analyzeAsync()` initializes the bundled WebAssembly parser automatically.
To initialize it explicitly without analyzing source:

```js
const { initializeWasm } = require("sentinel-ir");

initializeWasm().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
```

Only the JavaScript grammar is loaded by default. The TypeScript and TSX
grammars (about 1.4 MB each, uncompressed) are loaded on first use by
`analyzeAsync()`, or up front with
`initializeWasm({ languages: ["typescript", "tsx"] })`.

## TypeScript

TypeScript and TSX produce the same IR shape and the same fact categories as
JavaScript. TypeScript-specific handling:

- `import type { X } from "m"`, `import { type X } from "m"` and
  `typeof import("m")` in type positions are erased at compile time and are not
  counted as runtime imports.
- `import cp = require("child_process")` is a runtime require.
- `x as T`, `x satisfies T`, `x!` and `<T>x` do not hide a call:
  `(cp as any).exec(...)` is still process spawning.
- Types, interfaces, type parameters and `declare` blocks are skipped; they
  never run. Exported types, interfaces and enums are listed in `exports`.
- `.ts` and `.tsx` are different grammars: JSX in a `.ts` file, or `<T>x` in a
  `.tsx` file, is a parse error and gives `analysisStatus: "incomplete"`.

Not covered: framework decorators (`@Get("/x")`) are not read as routes, and
path aliases from `tsconfig.json` are not resolved.

## API

### `analyze(content, options?)` → `ir`

Synchronous analysis. If no parser has been initialized, it attempts to
load the optional native `tree-sitter` packages. If loading fails, the
result is `analysisStatus: "incomplete"` and uses text-based fallback
heuristics. It does not automatically switch to WebAssembly.

Use `analyzeAsync()` for analysis with the bundled WebAssembly parser.
Both APIs return the full IR, including raw AST facts under `ir.facts`.

All options are optional. The library keeps no state between calls; these are
your own signals, passed through into `world` and used for `objective` /
`constraints`:

| option | type | default | effect |
|---|---|---|---|
| `target` | string | `null` | file path; shown in `mission.target`; its extension selects the language when `language` is not given; a path containing `crypto` raises low risk to medium and adds `preserve_security` |
| `language` | string | from `target`, else `"javascript"` | `javascript` / `js`, `typescript` / `ts`, `tsx`; overrides the extension |
| `pressure` | number in [0, 1] | `0.5` | copied to `world.pressure` |
| `confidence` | number in [0, 1] | `0.75` | copied to `world.confidence` |
| `budget` | number ≥ 0 | `0.015` | copied to `world.budget` |
| `consecutiveFailures` | number ≥ 0 | `0` | `> 0` sets objective `stability_repair` when no structural objective applies; `> 2` adds `minimize_scope` |

A value that is not a finite number in its range (`"0.4"`, `NaN`, `Infinity`,
`-1`, `1.5`, `{}`) is ignored and the default is used; it is not clamped. Zero
is a valid value. The defaults are exported as `DEFAULTS`.

### `analyzeAsync(content, options?)` → `Promise<ir>`

Initializes the bundled WebAssembly parser for the selected language and then
analyzes the source. Use it on platforms where the optional native parser is unavailable.
Parser initialization failures reject the promise; source-analysis failures
are represented by `analysisStatus: "incomplete"`.

### `initializeWasm({ languages }?)` → `Promise<void>`

Initializes the bundled WebAssembly parsers without analyzing source
(default: `["javascript"]`). Needed before the synchronous `analyze()` on
TypeScript; without it `analyze()` returns `analysisStatus: "incomplete"` for
TypeScript. Use `analyzeAsync()` for the usual one-step workflow. Rejects for
an unsupported language.

### `LANGUAGES`

`["javascript", "typescript", "tsx"]`.

### `compress(ir)` → `{ analysisStatus, language, mission, world, constraints, forbidden, summary, facts }`

The compact projection meant for the prompt. `facts` is `compressFacts(ir.facts)`.

### `compressFacts(facts)`

Keeps only enabled operations and non-empty categories, and renders risk
signals as `signal:evidence@line`. For source that did not parse it returns
`{ ast: false, reason }`.

### `expandDecision(decision, ir)`

Joins an LLM decision with the IR it was made on:
`{ action, patch, target, objective, confidence, pressure }`. Only
`decision.action` and `decision.patch` are copied from the decision.

### Field reference

- `world.risk` (from the AST): `critical` for dynamic code, process spawning or
  `child_process`; `high` for file deletion; `medium` for file writes, network,
  crypto or secret comparison; otherwise `low`.
- `forbidden`: dangerous capabilities found in the file (`eval`,
  `child_process`, `process_spawn`, …).
- `mission.objective`: `security_refactor` | `filesystem_simplification` |
  `network_stability` | `stability_repair` | `general_optimization`.

## Limitations

- JavaScript and TypeScript only; one file at a time — capabilities split across files are not
  combined.
- Facts are syntactic. Aliases the AST cannot resolve (values passed through
  other modules, computed property names) are not followed.
- The text fallback for unparseable source is a substring heuristic and can be
  wrong in both directions; it is marked `facts.ast: false`.

## Origin

Extracted from the Sentinel project, where it is the input layer for an LLM
advisor. This package contains adapted versions of `src/ast-facts.js` and
`src/tree-parser.js` for its parser backends. `src/sentinel-ir.js` adapts the
surrounding logic to use caller-supplied `options` instead of Sentinel's
internal memory model.

## Development

```sh
npm ci
npm test
```

## Releasing

1. Bump `version` in `package.json` (and `package-lock.json`, `npm install`).
2. Push a tag `v<version>` (tags `v*` are protected).
3. The `publish` CI job runs the tests, checks the tag matches the version and
   runs `npm publish --provenance` with the protected `NPM_TOKEN` variable.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

## Analysis status

`analyze()` and `compress()` expose `analysisStatus`:

- `complete`: AST extraction succeeded and the source parsed without syntax errors.
- `incomplete`: AST extraction was unavailable or the source did not parse cleanly; analysis may rely on text heuristics.

The `risk` field remains a risk estimate, not a guarantee of safety. When
`analysisStatus` is `incomplete`, a result such as `risk: "low"` must not be
treated as evidence that the source is safe. Consumers making automated
decisions should abstain or require additional analysis in this state.

`analysisStatus` (0.1.3) and `language` (0.2.0) are additive fields in the
public output. Consumers that validate exact object keys may need to account
for them.
