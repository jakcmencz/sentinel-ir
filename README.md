# sentinel-ir

Structural IR for AI reasoning over code.

`sentinel-ir` turns a JavaScript source file into a small, structural JSON
description — routes, exports, imports, environment reads, network /
filesystem / process / crypto calls, dangerous syntax and a risk level — built
from the [tree-sitter](https://tree-sitter.github.io/) AST. You send that IR to
an LLM instead of the raw file.

**Supported language: JavaScript only** (CommonJS and ESM, via
`tree-sitter-javascript`). TypeScript, JSX-heavy code and other languages are
not supported; source that does not parse falls back to text heuristics and
the IR says so (`facts.ast: false`).

## Why send IR instead of the raw file

- **Fewer tokens.** The compressed IR has a roughly fixed size of about
  400 characters plus the facts the file actually has, so the larger the file,
  the larger the saving. Measured with `node examples/basic.js <file>` on this
  package's own sources:

  | file | raw chars | IR chars |
  |---|---:|---:|
  | `src/ast-facts.js` | 21,823 | 421 |
  | `src/sentinel-ir.js` | 8,680 | 439 |
  | `src/tree-parser.js` | 3,084 | 412 |
  | `examples/basic.js` | 537 | 428 |

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

Requires Node.js 20 or newer; `tree-sitter` builds a native binding on install.

## Usage

```js
const { analyze, compress } = require("sentinel-ir");

const code = `
const express = require("express");
const fs = require("fs");
const app = express();
app.post("/upload", (req, res) => { fs.writeFileSync("/tmp/x", req.body); res.end(); });
app.listen(process.env.PORT);
`;

const ir = analyze(code, { target: "src/server.js" });
console.log(JSON.stringify(compress(ir), null, 2));
```

Output:

```json
{
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

## API

### `analyze(content, options?)` → `ir`

Parses `content` (a JavaScript source string) and returns the full IR,
including the raw AST facts under `ir.facts`.

All options are optional. The library keeps no state between calls; these are
your own signals, passed through into `world` and used for `objective` /
`constraints`:

| option | type | default | effect |
|---|---|---|---|
| `target` | string | `null` | file path; shown in `mission.target`; a path containing `crypto` raises low risk to medium and adds `preserve_security` |
| `pressure` | number in [0, 1] | `0.5` | copied to `world.pressure` |
| `confidence` | number in [0, 1] | `0.75` | copied to `world.confidence` |
| `budget` | number ≥ 0 | `0.015` | copied to `world.budget` |
| `consecutiveFailures` | number ≥ 0 | `0` | `> 0` sets objective `stability_repair` when no structural objective applies; `> 2` adds `minimize_scope` |

A value that is not a finite number in its range (`"0.4"`, `NaN`, `Infinity`,
`-1`, `1.5`, `{}`) is ignored and the default is used; it is not clamped. Zero
is a valid value. The defaults are exported as `DEFAULTS`.

### `compress(ir)` → `{ mission, world, constraints, forbidden, summary, facts }`

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

- JavaScript only; one file at a time — capabilities split across files are not
  combined.
- Facts are syntactic. Aliases the AST cannot resolve (values passed through
  other modules, computed property names) are not followed.
- The text fallback for unparseable source is a substring heuristic and can be
  wrong in both directions; it is marked `facts.ast: false`.

## Origin

Extracted from the Sentinel project, where it is the input layer for an LLM
advisor. `src/ast-facts.js` and `src/tree-parser.js` are unchanged copies;
`src/sentinel-ir.js` is the same logic with Sentinel's internal memory model
replaced by the `options` argument.

## Development

```sh
npm ci
npm test
```

## License

MIT — see [LICENSE](LICENSE).
