# sentinel-ir

Structural IR for AI reasoning over code.

`sentinel-ir` turns a JavaScript, TypeScript, Python or Rust source file into a small, structural JSON
description — routes, exports, imports, environment reads, network /
filesystem / process / crypto calls, dangerous syntax and a risk level — built
from the [tree-sitter](https://tree-sitter.github.io/) AST. You send that IR to
an LLM instead of the raw file.

- npm: <https://www.npmjs.com/package/sentinel-ir>
- GitLab (main repository): <https://gitlab.com/jakubrojicek11/sentinel-ir>
- GitHub (mirror): <https://github.com/jakcmencz/sentinel-ir>
- MCP server for AI agents: [`sentinel-ir-mcp`](https://github.com/jakcmencz/sentinel-ir-mcp)
- Try it in your browser, nothing to install: <https://sentinel-ir-playground-dc30c8.gitlab.io/>

**Supported languages:**

| `language` | grammar | picked for `target` ending in |
|---|---|---|
| `javascript` (default) | `tree-sitter-javascript` | `.js` `.mjs` `.cjs` `.jsx`, or no / unknown extension |
| `typescript` | `tree-sitter-typescript` 0.23.2 | `.ts` `.mts` `.cts` (incl. `.d.ts`) |
| `tsx` | `tree-sitter-tsx` 0.23.2 | `.tsx` |
| `python` (alias `py`) | `tree-sitter-python` 0.25.0 | `.py` `.pyi` |
| `rust` (alias `rs`) | `tree-sitter-rust` 0.24.2, patched (see [Rust](#rust)) | `.rs` |

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
grammars (about 1.4 MB each, uncompressed), the Python grammar (about
0.46 MB) and the Rust grammar (about 1.4 MB) are loaded on first use by
`analyzeAsync()`, or up front with
`initializeWasm({ languages: ["typescript", "tsx", "python", "rust"] })`.

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

## Rust

New in 0.5.0. Rust produces the same IR shape and the same fact categories as
the other languages. Paths are resolved through the file's own `use`
declarations (including `as` aliases, `{...}` lists, `self` and `*` globs) and
`extern crate`, so `use std::process::Command as Cmd; Cmd::new("sh")` and
`use std::fs::*; remove_dir_all(p)` are recognized. `crate::`, `self::`,
`super::` and a local `mod fs` are not mistaken for the standard library.

| fact | Rust syntax |
|---|---|
| `processSpawn` (critical) | `Command::new` of `std::process`, `tokio::process`, `async_std::process`, `async_process`, `smol::process`; `nix::unistd::exec*` / `fork`, `nix::spawn::posix_spawn*`; `libc::system / popen / fork / exec* / posix_spawn*`; `subprocess::Exec / Popen`; `duct::cmd`, `xshell::cmd!`, `cmd_lib` macros |
| `childProcess` (critical) | `use` of one of those `Command` types, or a `*` glob of their module |
| `nativeCode` (critical) | `unsafe` blocks, `unsafe fn`, `unsafe impl`, `unsafe trait`, `extern "ABI" { ... }` (also `unsafe extern`), `extern "C" fn`, `#[no_mangle]` / `#[export_name]` / `#[link_section]` (also inside `#[unsafe(...)]`), `asm!` / `global_asm!` / `naked_asm!`, `libloading` / `dlopen2` / `libc::dlopen`, `LoadLibrary*` / `GetProcAddress` from `windows`, `windows-sys`, `winapi`; C/C++ built or linked at build time: `cc::Build`, `cmake`, `pkg_config::probe_library`, `vcpkg::find_package`, `println!("cargo:rustc-link-lib=...")` / `rustc-link-search` in `build.rs` |
| `dynamicEval` (critical) | embedded interpreters: `rhai::Engine`, `mlua::Lua`, `rlua::Lua`, `boa_engine::Context`, `deno_core::JsRuntime`, `v8::Isolate / Script::compile`, `pyo3::Python::run / eval` |
| `processExit` | `std::process::exit / abort`, `libc::exit / _exit / abort` |
| `diskDelete` (high) | `remove_file`, `remove_dir`, `remove_dir_all` of `std::fs`, `tokio::fs`, `async_std::fs`, `fs_err` |
| `diskWrite` / `diskRead` | `write`, `create_dir(_all)`, `rename`, `copy`, `hard_link`, `set_permissions`, `File::create(_new)`, symlinks, `tempfile`; `read`, `read_to_string`, `read_dir`, `read_link`, `File::open`, `walkdir`, `include_str!` / `include_bytes!` / `include!`, `#[path = "..."] mod`; `OpenOptions` by its `.write / .append / .create / .truncate / .read` chain (a builder that is not opened in place counts as both) |
| `outboundHttp` | `reqwest`, `ureq`, `surf`, `isahc`, `attohttpc`, `hyper` / `hyper_util` clients, `curl`, `awc`, `tungstenite`, `std::net` / `tokio::net` / `async_std::net` `TcpStream::connect`, `UdpSocket::bind` |
| `inboundHttp` and `routes` | `TcpListener::bind`, `UnixListener::bind`, `axum::serve`, `actix_web::HttpServer::new`, `hyper::Server`, `warp::serve`, `tiny_http`, `rocket::build`, `tide`, `poem`, `salvo`; routes from axum `.route("/p", get(h).post(h))`, actix `.route("/p", web::get())` and actix / rocket / ntex attributes `#[get("/p")]` |
| `env` | `std::env::var / var_os / set_var / remove_var` and `dotenvy` / `dotenv` `var` with a literal name, `env!`, `option_env!`; secret-like names are a `secret_access` signal, and so are `std::env::vars()` / `vars_os()` (every variable) and `dotenvy` / `dotenv` loading a `.env` file (also `diskRead`) |
| `cryptoUse` / `secretComparison` | calls into `sha1`, `sha2`, `sha3`, `md5`, `hmac`, `ring`, `openssl`, `aes(-gcm)`, `chacha20poly1305`, `rsa`, `ed25519-dalek`, `argon2`, `bcrypt`, `jsonwebtoken`, `blake2/3` and others; `==` / `!=` on a secret-like name; `subtle::ConstantTimeEq::ct_eq`, `constant_time_eq`, `ring::constant_time`, `openssl::memcmp::eq` |

Rust also has code that runs while it is being compiled, which is a common way
to attack through a dependency: a `target` named `build.rs` adds a
`build_script` signal (not `src/build.rs`, `tests/build.rs`, `examples/build.rs`
or `benches/build.rs`, which are a module and test targets), and `#[proc_macro]`, `#[proc_macro_derive]` and
`#[proc_macro_attribute]` add a `compile_time_code` signal. Neither changes
the risk on its own; what the code does (for example `Command::new` in
`build.rs`) does. In such a file, reading or writing files at run time, the
network or a secret-like environment variable is at least `high`, because it
happens on the developer's machine during `cargo build`. `include!` /
`include_str!` / `#[path]` (read by the compiler) and Cargo's own variables
such as `OUT_DIR` or `CARGO_CFG_*` do not raise it.

Exports are top-level items marked plain `pub` (not `pub(crate)`), names
re-exported with `pub use` and `#[macro_export]` macros.

**Macros.** A macro call's arguments, a `macro_rules!` body and a `macro`
2.0 body are token trees, not syntax. Paths called inside them
(`println!("{:?}", Command::new("id"))`), `env::var("NAME")` names and
`unsafe { }` inside them are still found, but what a macro expands to is
not: a call that only exists after expansion, or a procedural macro's output,
is not reported. Seeing that needs the Rust compiler (`cargo expand`), which a
source-only analyzer does not run.

**Grammar.** The bundled grammar is tree-sitter-rust v0.24.2 with a patch
(`scripts/rust-grammar/patch-grammar.py`; `scripts/rust-grammar/build.sh`
rebuilds the same file byte for byte) for syntax the release rejects:
wasm-bindgen `pub type X;` in `extern` blocks (all of `web-sys` and `js-sys`),
`safe fn` / `safe static`, `safe` and `auto` as names and type names, `const impl`,
`const trait`, `[const]` / `~const` bounds, trait aliases, `macro` 2.0,
negative const generic arguments, `f16` / `f128`, `super let`, `const`
closures, attributes on expressions, `Type::<T>` in types, `fn(&_)` and
edition-2015 `try!`.

Not covered: method calls on values whose type is not visible (`cmd.spawn()`
on a `Command` from another function is covered only by its `Command::new`),
`std::mem::transmute` and raw pointer use outside an `unsafe` block (they
cannot exist there), trait objects, and anything `cfg`-gated is reported
regardless of the target platform.

### Measured (0.5.0)

- **Parsing:** all 15,238 `.rs` files of 424 crate versions from crates.io (the
  `tokio`, `reqwest`, `axum`, `actix-web`, `nix`, `libc`, `libloading`, `ring`,
  `web-sys`, `js-sys`, ... dependency tree) and all 2,874 files of the Rust
  standard library's own sources parse completely. With the unpatched v0.24.2
  grammar it was 13,693 (1,476 of the missing ones were generated `web-sys` /
  `js-sys` bindings) and 2,724 (the rest used unstable syntax). On the files
  both grammars parse, the facts are identical.
- **`unsafe` against syn:** on the 15,237 files that
  [syn](https://crates.io/crates/syn), the parser behind `cargo-geiger`,
  parses, every `unsafe impl` (2,839), `unsafe trait` (160) and `extern` block
  (6,266) it counts is reported, with no extra ones, and every `unsafe fn`
  (10,137); the 12 extra `unsafe fn` are declared inside wasm-bindgen
  `extern` blocks, which the syn counter does not visit. `unsafe` blocks:
  37,167 against syn's 35,428; the extra ones are inside macro bodies and
  macro arguments, where syn does not look. All 4,857 files syn finds `unsafe`
  in are flagged.
- **49 labeled snippets** in `test/fixtures/rust-labeled.js`, the syntax
  cases in `test/rust-grammar.test.js`, plus 2,950 randomly broken real files
  that never crash and never report a dangerous operation from an incomplete
  parse.

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
| Python | loading a library: `ctypes.CDLL / PyDLL / WinDLL / OleDLL / LibraryLoader`, `ctypes.cdll / windll / oledll / pydll .LoadLibrary` or attribute (`windll.kernel32`), `_ctypes.dlopen`; calling into it: `libc.system(...)`, `windll.kernel32.VirtualAlloc(...)`, `ctypes.pythonapi.*`; function pointers: `CFUNCTYPE / WINFUNCTYPE / PYFUNCTYPE`; raw memory: `memmove`, `memset`, `string_at`, `wstring_at`, `cast`, `<type>.from_address` (also on a `ctypes.Structure` subclass), indexing a `ctypes.pointer` / `POINTER(...)` result other than `p[0]` (`p[1000] = 5`, `p[:n]`); `cffi` `FFI().dlopen / verify / memmove`, compiling C with `ffi.set_source` / `ffi.compile`, `ffi.cast` to a pointer type and calls into a `dlopen` result; `mmap.mmap` with `PROT_EXEC`; `win32api.LoadLibrary(Ex)`, `numpy.ctypeslib.load_library`, `llvmlite.binding.create_mcjit_compiler` |
| JavaScript / TypeScript | `process.dlopen`, `process.binding` / `process._linkedBinding` (Node internals; `process.binding("spawn_sync")` spawns without `child_process`), also through an alias (`const p = process`, `const { dlopen } = process`, `globalThis.process`, `require("process")`, `import ... from "node:process"`) or as a value (`process.dlopen.call(...)`, `Reflect.apply(process.dlopen, ...)`, `(0, process.dlopen)(...)`); `Deno.dlopen`; `require` / `import` / `module.require` / a `createRequire` function of a `*.node` addon, including built paths (`"./build/" + name + ".node"`, `path.join(dir, "addon.node")`); calls (and `new`) through `koffi`, `ffi-napi` (also scoped forks such as `@napi-ffi/ffi-napi`), `ffi`, `ffi-rs`, `ref-napi`, `bun:ffi`, `bindings`, `node-gyp-build` |
| Rust | `unsafe` blocks / `fn` / `impl` / `trait`, `extern` blocks and `extern "C" fn`, `#[no_mangle]` / `#[export_name]` / `#[link_section]`, `asm!`, `libloading` / `dlopen2` / `libc::dlopen`, Windows `LoadLibrary*` / `GetProcAddress` (see [Rust](#rust)) |

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
f(koffi) { koffi.load() }`) is not counted. Not covered: Python C extension modules (`import _mymodule`
from a `.so`), indexing a pointer that was not created by `pointer()` /
`POINTER(T)()` in the same file, `importlib` loaders, WebAssembly, and native code reached
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
TypeScript, Python or Rust; without it `analyze()` returns `analysisStatus: "incomplete"` for
them. Use `analyzeAsync()` for the usual one-step workflow. Rejects for
an unsupported language.

### `LANGUAGES`

`["javascript", "typescript", "tsx", "python", "rust"]`.

### `compress(ir)` → `{ analysisStatus, language, mission, world, constraints, forbidden, summary, facts }`

The compact projection meant for the prompt. `facts` is `compressFacts(ir.facts)`.

### `compressFacts(facts)`

Keeps only enabled operations and non-empty categories, and renders risk
signals as `signal:evidence@line`. For source that did not parse it returns
`{ ast: false, reason }`, plus `parseError` when the parser located an error.

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

- JavaScript, TypeScript, Python and Rust only; one file at a time — capabilities split across files are not
  combined.
- Facts are syntactic. Aliases the AST cannot resolve (values passed through
  other modules, computed property names) are not followed.
- Since 0.4.4, `fs` calls are recognised through any local name bound in the
  same file: `require("fs").writeFileSync(...)`, `const files = require("fs")`,
  `const { unlinkSync: del } = require("fs")`, `import { writeFile } from "fs/promises"`,
  `require("fs").promises`. A local variable or parameter that shadows the name
  is not counted. `fs-extra` and `graceful-fs` count as `fs`, including
  `fs-extra` methods (`outputFile`, `writeJson`, `move` are writes; `remove`,
  `emptyDir` are deletes).
- Since 0.4.4, outbound HTTP is recognised the same way for `http`, `https`,
  `http2`, `axios`, `got`, `superagent`, `request`, `node-fetch`, `undici`,
  `cross-fetch`, `isomorphic-fetch`, `ky` and `needle`: `const net = require("https"); net.get(u)`,
  `require("axios").get(u)`, `import { request } from "undici"`, `got(u)`,
  `axios.create().get(u)` through a variable. Counted calls are the clients'
  request methods (HTTP verbs, `request`, `fetch`, `stream`, `got.paginate`,
  `axios.postForm`, `undici.upgrade`, …); helpers such as `axios.isAxiosError`
  or `undici.setGlobalDispatcher` are not.
- A module received directly by a `.then` callback is followed
  (`import("fs").then(m => m.writeFileSync(...))`, `.then(({ rmSync }) => ...)`);
  a module passed on to another function or stored elsewhere is not.
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

## Contributing

Development, CI and npm releases run on
[GitLab](https://gitlab.com/jakubrojicek11/sentinel-ir). The
[GitHub repository](https://github.com/jakcmencz/sentinel-ir) is a mirror that
GitLab updates on every push to `main` and every tag. Issues are welcome on
either; a pull request opened on GitHub is applied on GitLab, and the mirror
then brings it back.

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

Since 0.4.3, when the source parsed with syntax errors, `facts.parseError`
gives where the first error region starts, for example
`{ "line": 42, "column": 1, "kind": "missing", "expected": "}" }`.
`kind` is `missing` (the parser expected a token that is absent; `expected`
names it), `unexpected` (the parser could not use the text at that
position) or, since 0.4.5 and for Python only, `unclosed` (the bracket at that
position is never closed; `expected` names the closing bracket). It never
contains source text. It does not say whether the code
is wrong or uses syntax the grammar does not support, for example TypeScript
`export type *` or variance annotations such as `in T`.

Since 0.4.5, Python errors point where CPython reports them in most cases:
the bracket that is never closed, the end of an `if`/`def`/`class`/… header
without `:`, or a closing bracket without a match. Before, tree-sitter's error
region often started at the beginning of the statement or file, so the result
was line 1, column 1. On 4 320 broken copies of standard-library files (one
bracket, comma or colon removed or added), the reported line matches CPython
in 81 % of cases (0.4.4: 67 %) and the column too in 67 % (0.4.4: 29 %).
JavaScript and TypeScript positions are unchanged.

`analysisStatus` (0.1.3), `language` (0.2.0), `operations.nativeCode`
(0.4.0) and `parseError` (0.4.3) are additive fields in the
public output. Consumers that validate exact object keys may need to account
for them.
