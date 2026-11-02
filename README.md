# sentinel-ir

Structural IR for AI reasoning over code.

`sentinel-ir` turns a JavaScript, TypeScript or Python source file into a small, structural JSON
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
| `python` (alias `py`) | `tree-sitter-python` 0.25.0 | `.py` `.pyi` |

Other languages are not supported. An explicit unsupported `language`
(e.g. `"ruby"`) is reported as `analysisStatus: "incomplete"` instead of
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
grammars (about 1.4 MB each, uncompressed) and the Python grammar (about
0.46 MB) are loaded on first use by `analyzeAsync()`, or up front with
`initializeWasm({ languages: ["typescript", "tsx", "python"] })`.

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

## Python

Python produces the same IR shape and the same fact categories as JavaScript
and TypeScript. Calls are resolved through the file's own imports and simple
assignments, so `import subprocess as sp; sp.run(...)`,
`from os import system as sh` and `run = os.popen` are all recognized, and a
name rebound in the file (`def eval(...)`, a parameter, a local assignment, an
import from another module) is not mistaken for the builtin.

| fact | Python syntax |
|---|---|
| `routes`, `inboundHttp` | Flask / FastAPI / Quart / Sanic decorators such as `@app.route("/x", methods=[...])`, `@router.post("/x")`; `http.server.HTTPServer` |
| `outboundHttp` | `requests.*`, `httpx.*`, their `Session()` / `Client()` / `AsyncClient()`, `aiohttp.ClientSession()`, `urllib.request.urlopen`, `URLopener().open()`, `socket.socket` |
| `processSpawn` (critical) | `subprocess.run / Popen / call / check_*`, `os.system / popen / exec* / spawn*`, `pty.spawn`, `asyncio.create_subprocess_*`; Python 2 `os.popen2/3/4`, `popen2.*`, `commands.*` |
| `childProcess` (critical) | `import subprocess` / `import pty`, like `child_process` in JavaScript |
| `dynamicEval` (critical) | `eval`, `exec`, `compile` |
| `unsafeDeserialization` (critical) | `pickle` / `_pickle` / `dill` / `marshal` `load(s)` and `Unpickler`, `shelve.open`, `jsonpickle.decode`, `joblib.load`, `pandas.read_pickle`, `yaml.load` without a safe `Loader`, `yaml.unsafe_load`, `numpy.load(..., allow_pickle=True)`, `torch.load` with `weights_only` other than `True`/`None` or with a `pickle_module` |
| `nativeCode` (critical) | `ctypes.CDLL / PyDLL / WinDLL / OleDLL`, `ctypes.cdll / windll / oledll / pydll / pythonapi.*`, calls into a loaded library, `CFUNCTYPE`, `memmove / memset / string_at / cast / from_address`, `cffi` `dlopen / verify / memmove` (see [Native code](#native-code)) |
| `diskDelete` (high) | `os.remove / unlink / rmdir`, `shutil.rmtree`, `Path(...).unlink() / rmdir()` |
| `diskWrite` | `open(..., "w" / "a" / "x" / "+")` or a non-literal mode, `shutil.copy / move`, `os.rename / mkdir`, `Path(...).write_text()` … |
| `env` | `os.environ["X"]`, `os.environ.get("X")`, `os.getenv("X")` |
| `cryptoUse`, `secretComparison` | `hashlib`, `hmac`, `secrets`, `crypt`, `cryptography`, `bcrypt`, `jwt` …; `==` / `!=` on a secret-looking name |
| `exports` | `__all__` when it is a literal list, otherwise public top-level `def` and `class` |

`unsafeDeserialization` is new in 0.3.0. It is part of `facts.operations`
for every language (always `false` for JavaScript and TypeScript), and adds
`unsafe_deserialization` to `forbidden` / `dangerous`.

Also resolved (0.3.1): `from m import *`, `six.moves.*`,
`getattr(os, "system")` and `__import__("os")` / `importlib.import_module("os")`
with string literals, and `os` / `subprocess` / `pickle` / `marshal` / `shelve` /
`shutil` used without an import (a snippet cut from a larger file).

A bare `torch.load(f)` is not reported: PyTorch 2.6+ loads it with
`weights_only=True`. It does unpickle on PyTorch below 2.6, or when
`TORCH_FORCE_NO_WEIGHTS_ONLY_LOAD=1` is set; sentinel-ir sees the source
file, not the installed version or the environment. (Bandit B614 reports
the bare call.)

Not covered: names passed through other modules, attributes set at runtime
(`setattr`, `globals()`), `__import__` / `importlib` with a computed name, and
comprehension scopes. The grammar also accepts some
Python 2 syntax (`print "x"`); Python 2 `exec "..."` counts as dynamic code.

### Measured detection (0.3.1)

- **Bandit 1.8.6 `examples/`** (independent): of 254 Bandit findings in the
  categories above, 242 get the matching signal on the same line (95%).
  Two are intentional differences: bare `torch.load()` (B614, see above).
  The other 10 are `httpx.Client()` / `URLopener()` constructors; the
  `.get()` / `.open()` calls made with them are reported. Checked in CI by
  `scripts/python-recall.js`, which names each intentional difference.
- **70+ labeled snippets** in `test/fixtures/python-labeled.js`, including
  hard negatives (comments, strings, shadowed names, `model.eval()`,
  `re.compile`, safe YAML loaders). Written by the analyzer's author, so
  they test intent, not an independent ground truth.
- Not measured: precision on a labeled real-world corpus.

## Native code

New in 0.4.0, hardened in 0.4.1 and 0.4.2. Native code runs outside the language runtime: it can read and
write any memory of the process (including an agent's keys, tokens and
prompts) and do anything the other facts describe without showing up as them.
The Python `ctypes` documentation says it can "compromise the running
process". `nativeCode` is in `facts.operations` for every language; when it is
`true` the risk is `critical` and `forbidden` / `dangerous` contain
`native_code`. Each call is a `native_code` signal with its line.

| language | reported |
|---|---|
| Python | loading a library: `ctypes.CDLL / PyDLL / WinDLL / OleDLL / LibraryLoader`, `ctypes.cdll / windll / oledll / pydll .LoadLibrary` or attribute (`windll.kernel32`), `_ctypes.dlopen`; calling into it: `libc.system(...)`, `windll.kernel32.VirtualAlloc(...)`, `ctypes.pythonapi.*`; function pointers: `CFUNCTYPE / WINFUNCTYPE / PYFUNCTYPE`; raw memory: `memmove`, `memset`, `string_at`, `wstring_at`, `cast`, `<type>.from_address` (also on a `ctypes.Structure` subclass); `cffi` `FFI().dlopen / verify / memmove`, `ffi.cast` to a pointer type and calls into a `dlopen` result; `mmap.mmap` with `PROT_EXEC`; `win32api.LoadLibrary(Ex)`, `numpy.ctypeslib.load_library`, `llvmlite.binding.create_mcjit_compiler` |
| JavaScript / TypeScript | `process.dlopen`, `process.binding` / `process._linkedBinding` (Node internals; `process.binding("spawn_sync")` spawns without `child_process`), also through an alias (`const p = process`, `const { dlopen } = process`, `globalThis.process`, `require("process")`, `import ... from "node:process"`) or as a value (`process.dlopen.call(...)`, `Reflect.apply(process.dlopen, ...)`, `(0, process.dlopen)(...)`); `Deno.dlopen`; `require` / `import` / `module.require` / a `createRequire` function of a `*.node` addon, including built paths (`"./build/" + name + ".node"`, `path.join(dir, "addon.node")`); calls (and `new`) through `koffi`, `ffi-napi` (also scoped forks such as `@napi-ffi/ffi-napi`), `ffi`, `ffi-rs`, `ref-napi`, `bun:ffi`, `bindings`, `node-gyp-build` |

Not reported: `import ctypes` (or `require("koffi")`) on its own, `ctypes`
types, `sizeof`, `create_string_buffer`, `Structure`, `ctypes.util.find_library`.
Names are resolved like the other facts (aliases, `from ctypes import CDLL as
load`, `getattr(ctypes, "CDLL")`, `__import__("ctypes")`, `sys.modules["ctypes"]`,
`vars(ctypes)["CDLL"]`, `ctypes.__dict__["CDLL"]`, `cdll["libc.so.6"]`,
`n = "CDLL"; getattr(ctypes, n)`). A member name built at run time
(`getattr(ctypes, "CD" + "LL")`, `process["dl" + "open"](...)`, `process[n](...)`)
is reported, because it can be any loader; `getattr(ctypes, "c_" + kind)` picks
a C type and is not. A
parameter or local variable that shadows `process` or an FFI binding (`function
f(koffi) { koffi.load() }`) is not counted. Not covered: out-of-bounds
pointer indexing (`ctypes.pointer(x)[1000] = 5`), compiling C with
`ffi.compile()` / `set_source`, Python C extension modules (`import _mymodule`
from a `.so`), `importlib` loaders, WebAssembly, and native code reached
through another file. Code passed to `exec` / `eval` is already critical as
dynamic code.

Source that does not parse (`analysisStatus: "incomplete"`) falls back to text
matching, which is stricter: a `ctypes` loader or memory function, any
`dlopen(`, `process.dlopen` / `binding`, a `*.node` path or an FFI module
import (`koffi`, `ffi-napi`, `bun:ffi`, ...) is enough for `native_code`, since
an incomplete parse cannot show that the import is unused.

Bandit has no rule for `ctypes` / `cffi`, so this fact is measured only on the
labeled cases in `test/native-code.test.js` and `test/fixtures/python-labeled.js`,
and on a generated matrix (`test/native-matrix.test.js`): every `ctypes` API in
16 access forms, every `process` native method in 22 forms and every FFI module
in 12 import forms, each in JavaScript, TypeScript and TSX, plus the same forms
with a harmless member that must not be reported.

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
TypeScript or Python; without it `analyze()` returns `analysisStatus: "incomplete"` for
them. Use `analyzeAsync()` for the usual one-step workflow. Rejects for
an unsupported language.

### `LANGUAGES`

`["javascript", "typescript", "tsx", "python"]`.

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

- `world.risk` (from the AST): `critical` for dynamic code, process spawning,
  `child_process` / `subprocess`, unsafe deserialization or native code; `high` for file deletion; `medium` for file writes, network,
  crypto or secret comparison; otherwise `low`.
- `forbidden`: dangerous capabilities found in the file (`eval`,
  `child_process`, `process_spawn`, `unsafe_deserialization`, `native_code`, …).
- `mission.objective`: `security_refactor` | `filesystem_simplification` |
  `network_stability` | `stability_repair` | `general_optimization`.

## Limitations

- JavaScript, TypeScript and Python only; one file at a time — capabilities split across files are not
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

`analysisStatus` (0.1.3), `language` (0.2.0) and `operations.nativeCode`
(0.4.0) are additive fields in the
public output. Consumers that validate exact object keys may need to account
for them.
