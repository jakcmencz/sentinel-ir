"use strict";

/**
 * Structural facts for Python, in the same shape as AstFacts.extract() gives
 * for JavaScript and TypeScript. Names are resolved through the file's own
 * imports and simple assignments, so a call is judged by what it refers to:
 *   import subprocess as sp; sp.run(...)        -> subprocess.run
 *   from os import system as sh; sh("...")      -> os.system
 *   p = Path("x"); p.unlink()                   -> pathlib.Path().unlink
 * A name bound locally to something else (def eval(): ...) is not the builtin.
 */

const TreeParser = require("./tree-parser");
const { emptyFacts, dangerousOf } = require("./ast-facts");

const SECRETISH = /(token|secret|signature|api[_-]?key|apikey|password|passwd|credential|auth|hmac|digest)/i;

const BUILTINS = new Set(["eval", "exec", "compile", "open", "exit", "quit", "__import__", "getattr"]);

// Standard-library modules that are taken as themselves when the file uses
// them without importing them (a snippet cut out of a larger file).
const IMPLICIT_MODULES = new Set([
    "os", "subprocess", "pty", "pickle", "_pickle", "cPickle", "marshal", "shelve", "shutil", "commands", "popen2", "ctypes"
]);

const IMPORT_CALLS = new Set(["builtins.__import__", "importlib.import_module"]);

const PROCESS_MODULES = new Set(["subprocess", "pty", "commands", "popen2"]);
const PROCESS_CALLS = new Set([
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
    "subprocess.Popen", "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen", "os.startfile", "os.posix_spawn", "os.posix_spawnp",
    "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve", "os.spawnvp", "os.spawnvpe",
    "pty.spawn", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
    // Python 2
    "os.popen2", "os.popen3", "os.popen4", "popen2.popen2", "popen2.popen3", "popen2.popen4",
    "popen2.Popen3", "popen2.Popen4", "commands.getoutput", "commands.getstatusoutput", "commands.getstatus"
]);

const DYNAMIC_CALLS = new Set(["builtins.eval", "builtins.exec", "builtins.compile"]);

const DESERIALIZE_CALLS = new Set([
    "pickle.load", "pickle.loads", "pickle.Unpickler", "_pickle.load", "_pickle.loads",
    "cPickle.load", "cPickle.loads", "cPickle.Unpickler", "dill.load", "dill.loads", "dill.Unpickler",
    "marshal.load", "marshal.loads", "shelve.open", "jsonpickle.decode", "jsonpickle.loads",
    "jsonpickle.unpickler.decode", "jsonpickle.unpickler.Unpickler", "joblib.load", "pandas.read_pickle",
    "yaml.unsafe_load", "yaml.unsafe_load_all"
]);
// Native code through ctypes / cffi: loading a shared library, calling into it,
// building a C function pointer, or reading and writing raw memory addresses.
const NATIVE_CALLS = new Set([
    "ctypes.CDLL", "ctypes.PyDLL", "ctypes.WinDLL", "ctypes.OleDLL", "ctypes.LibraryLoader",
    "ctypes.CFUNCTYPE", "ctypes.WINFUNCTYPE", "ctypes.PYFUNCTYPE",
    "ctypes.memmove", "ctypes.memset", "ctypes.string_at", "ctypes.wstring_at", "ctypes.cast",
    "_ctypes.dlopen", "_ctypes.LoadLibrary", "_ctypes.call_function", "_ctypes.call_cdeclfunction",
    "cffi.FFI().dlopen", "cffi.FFI().verify", "cffi.FFI().memmove",
    "numpy.ctypeslib.load_library", "win32api.LoadLibrary", "win32api.LoadLibraryEx",
    "llvmlite.binding.create_mcjit_compiler"
]);
const NATIVE_LIBRARY = /^(ctypes\.(cdll|windll|oledll|pydll|pythonapi)\.|ctypes\.(CDLL|PyDLL|WinDLL|OleDLL|LibraryLoader)\(\)\.|cffi\.FFI\(\)\.dlopen\(\)\.)/;

// The "()" a library loader returns; any other "()" in a name is a call on a
// value a native function returned (lib.f().decode), which is plain Python.
const NATIVE_LOADER_RESULT = /\b(CDLL|PyDLL|WinDLL|OleDLL|LibraryLoader|LoadLibrary|FFI|dlopen)\(\)/g;

// cdll["libc.so.6"] is cdll.libc.so.6; sys.modules["ctypes"] is ctypes.
const NATIVE_SUBSCRIPT = /^ctypes\.(cdll|windll|oledll|pydll)$/;

const DYNAMIC_NAME = "<dynamic>";
const NATIVE_DYNAMIC_BASE = /^(_?ctypes(\.(cdll|windll|oledll|pydll|pythonapi))?|cffi\.FFI\(\))$/;

// getattr(ctypes, "c_" + kind) picks a C type, not a loader.
function isCtypesTypeName(node) {
    const first = node?.type === "binary_operator" ? field(node, "left") : node;
    const literal = node?.type === "string" ? text(node) : first?.type === "string" ? text(first) : "";
    return /^[a-z]*["']c_/i.test(literal);
}

function isNativeCall(q, call, positional, usesCtypes) {
    if (NATIVE_CALLS.has(q)) return true;
    if (q.includes(`.${DYNAMIC_NAME}`)) return true;
    if (NATIVE_LIBRARY.test(q)) return !q.replace(NATIVE_LOADER_RESULT, "").includes("()");
    // ffi.cast("char *", address) turns an integer into a pointer.
    if (q === "cffi.FFI().cast") return (stringLiteral(positional[0]) || "").includes("*");
    if (q === "mmap.mmap") return text(call).includes("PROT_EXEC");
    // Structure subclasses: class S(ctypes.Structure) ... S.from_address(a).
    return q.endsWith(".from_address") && (q.startsWith("ctypes.") || usesCtypes());
}

const YAML_LOAD_CALLS = new Set(["yaml.load", "yaml.load_all"]);
const SAFE_YAML_LOADER = /^yaml\.(SafeLoader|CSafeLoader|BaseLoader|CBaseLoader)$/;

const EXIT_CALLS = new Set(["sys.exit", "os._exit", "builtins.exit", "builtins.quit"]);

const PATH = "pathlib.Path()";
const PATH_FACTORY = /^pathlib\.(Path|PurePath|PosixPath|WindowsPath|PurePosixPath|PureWindowsPath)(\.(home|cwd))?$/;
const PATH_RETURNING = new Set([
    "resolve", "absolute", "expanduser", "with_name", "with_suffix", "with_stem", "joinpath", "relative_to"
]);

const FS_DELETE = new Set(["os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree", `${PATH}.unlink`, `${PATH}.rmdir`]);
const FS_WRITE = new Set([
    "os.rename", "os.renames", "os.replace", "os.makedirs", "os.mkdir", "os.chmod", "os.chown",
    "os.link", "os.symlink", "os.truncate", "os.write",
    "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.move", "shutil.chown",
    `${PATH}.write_text`, `${PATH}.write_bytes`, `${PATH}.mkdir`, `${PATH}.touch`, `${PATH}.rename`,
    `${PATH}.replace`, `${PATH}.chmod`, `${PATH}.symlink_to`, `${PATH}.hardlink_to`
]);
const FS_READ = new Set([
    "os.listdir", "os.scandir", "os.walk", "glob.glob", "glob.iglob",
    `${PATH}.read_text`, `${PATH}.read_bytes`, `${PATH}.iterdir`, `${PATH}.glob`, `${PATH}.rglob`
]);
// Functions whose mode argument decides read or write: position of that argument.
const OPEN_CALLS = new Map([["builtins.open", 1], ["io.open", 1], ["codecs.open", 1], ["os.fdopen", 1], [`${PATH}.open`, 0]]);

const HTTP_MODULES = new Set(["requests", "httpx"]);
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send", "urlopen"]);
const HTTP_CLIENTS = new Set(["requests.Session", "requests.session", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession", "urllib3.PoolManager"]);
const URL_OPENERS = new Set(["urllib.request.URLopener", "urllib.request.FancyURLopener"]);
const URL_OPENER_METHODS = new Set(["open", "retrieve"]);
const NETWORK_CALLS = new Set([
    "urllib.request.urlopen", "urllib.request.urlretrieve", "socket.socket", "socket.create_connection",
    "http.client.HTTPConnection", "http.client.HTTPSConnection", "ftplib.FTP", "ftplib.FTP_TLS",
    "smtplib.SMTP", "smtplib.SMTP_SSL", "telnetlib.Telnet", "aiohttp.request"
]);
const SERVER_CALLS = new Set([
    "http.server.HTTPServer", "http.server.ThreadingHTTPServer", "socketserver.TCPServer",
    "socketserver.ThreadingTCPServer", "wsgiref.simple_server.make_server"
]);

const ROUTE_HOSTS = new Set(["app", "router", "server", "api", "bp", "blueprint"]);
const ROUTE_FACTORIES = new Set(["flask.Flask", "flask.Blueprint", "fastapi.FastAPI", "fastapi.APIRouter", "quart.Quart", "sanic.Sanic"]);
const ROUTE_METHODS = new Set(["route", "get", "post", "put", "patch", "delete", "head", "options", "websocket", "api_route"]);

const CRYPTO_MODULES = new Set(["hashlib", "hmac", "secrets", "crypt", "cryptography", "Crypto", "Cryptodome", "nacl", "bcrypt", "jwt", "passlib"]);
const CONSTANT_COMPARE = new Set(["hmac.compare_digest", "secrets.compare_digest"]);

const SCOPE_TYPES = new Set(["function_definition", "lambda", "class_definition"]);

function text(node) {
    return node ? node.text : "";
}

function line(node) {
    return node.startPosition.row + 1;
}

function field(node, name) {
    return node ? node.childForFieldName(name) : null;
}

function walk(node, visit) {
    visit(node);
    for (const child of node.namedChildren) walk(child, visit);
}

// Content of a plain string literal; f-strings and concatenations are not literals.
function stringLiteral(node) {
    if (!node || node.type !== "string") return null;
    if (node.namedChildren.some(child => child.type === "interpolation")) return null;
    return node.namedChildren
        .filter(child => child.type === "string_content")
        .map(child => child.text)
        .join("");
}

function scopeOf(node) {
    for (let current = node.parent; current; current = current.parent) {
        if (SCOPE_TYPES.has(current.type)) return current;
    }
    return null;
}

// A def/class name binds in the scope around the definition, not inside it.
function bindingScopeOf(node) {
    const scope = scopeOf(node);
    if (scope && (field(scope, "name")?.id === node.id)) return scopeOf(scope);
    return scope;
}

// six.moves.X is X (six.moves.urllib.request.urlopen -> urllib.request.urlopen).
function canonical(q) {
    return q.startsWith("six.moves.") ? q.slice("six.moves.".length) : q;
}

function moduleName(node) {
    return node.type === "relative_import" ? node.text : text(node);
}

function collectBindings(root) {
    const scopes = new Map();
    const add = (scope, name, entry) => {
        const key = scope ? scope.id : 0;
        if (!scopes.has(key)) scopes.set(key, new Map());
        const names = scopes.get(key);
        if (!names.has(name)) names.set(name, []);
        names.get(name).push(entry);
    };

    const bindTarget = (target, scope, value) => {
        if (!target) return;
        if (target.type === "identifier") {
            add(scope, target.text, value ? { kind: "alias", value } : { kind: "other" });
            return;
        }
        if (["pattern_list", "tuple_pattern", "list_pattern", "tuple", "list", "list_splat_pattern"].includes(target.type)) {
            for (const child of target.namedChildren) bindTarget(child, scope, null);
        }
    };

    const stars = [];

    walk(root, node => {
        switch (node.type) {
            case "import_statement":
                for (const name of node.namedChildren) {
                    if (name.type === "dotted_name") {
                        const first = name.namedChildren[0].text;
                        add(bindingScopeOf(node), first, { kind: "import", q: first });
                    } else if (name.type === "aliased_import") {
                        add(bindingScopeOf(node), text(field(name, "alias")), { kind: "import", q: text(field(name, "name")) });
                    }
                }
                break;
            case "import_from_statement": {
                const source = field(node, "module_name");
                const base = moduleName(source);
                for (const name of node.namedChildren) {
                    if (name.id === source?.id) continue;
                    if (name.type === "wildcard_import") stars.push(base);
                    if (name.type === "dotted_name") {
                        add(bindingScopeOf(node), name.text, { kind: "import", q: `${base}.${name.text}` });
                    } else if (name.type === "aliased_import") {
                        add(bindingScopeOf(node), text(field(name, "alias")), { kind: "import", q: `${base}.${text(field(name, "name"))}` });
                    }
                }
                break;
            }
            case "function_definition":
            case "class_definition": {
                const name = field(node, "name");
                if (name) add(scopeOf(node), name.text, { kind: "other" });
                if (node.type === "function_definition") {
                    for (const param of field(node, "parameters")?.namedChildren || []) {
                        const id = param.type === "identifier" ? param : (field(param, "name") || param.namedChildren.find(c => c.type === "identifier"));
                        if (id?.type === "identifier") add(node, id.text, { kind: "other" });
                    }
                }
                break;
            }
            case "lambda":
                for (const param of field(node, "parameters")?.namedChildren || []) {
                    const id = param.type === "identifier" ? param : field(param, "name");
                    if (id?.type === "identifier") add(node, id.text, { kind: "other" });
                }
                break;
            case "assignment": {
                const left = field(node, "left");
                const right = field(node, "right");
                bindTarget(left, scopeOf(node), left?.type === "identifier" && right && right.type !== "assignment" ? right : null);
                break;
            }
            case "augmented_assignment":
                bindTarget(field(node, "left"), scopeOf(node), null);
                break;
            case "named_expression":
                bindTarget(field(node, "name"), scopeOf(node), field(node, "value"));
                break;
            case "for_statement":
            case "for_in_clause":
                bindTarget(field(node, "left"), scopeOf(node), null);
                break;
            case "as_pattern": {
                const alias = field(node, "alias");
                const target = alias?.namedChildren.find(c => c.type === "identifier") || (alias?.type === "identifier" ? alias : null);
                const value = node.namedChildren[0];
                const inWith = node.parent?.type === "with_item";
                if (target) add(scopeOf(node), target.text, inWith && value ? { kind: "alias", value } : { kind: "other" });
                break;
            }
            default:
                break;
        }
    });

    return { scopes, stars };
}

function createResolver(root) {
    const { scopes, stars } = collectBindings(root);

    // Python looks a name up in the innermost scope, then enclosing functions
    // (class bodies are skipped), then the module.
    function lookup(name, node) {
        const chain = [];
        let scope = scopeOf(node);
        let first = true;
        while (scope) {
            if (first || scope.type !== "class_definition") chain.push(scope.id);
            first = false;
            scope = scopeOf(scope);
        }
        chain.push(0);
        for (const key of chain) {
            const entries = scopes.get(key)?.get(name);
            if (entries) return entries;
        }
        return null;
    }

    // A literal, or a name bound only to literals: n = "CDLL"; getattr(ctypes, n).
    function attributeNames(node) {
        const literal = stringLiteral(node);
        if (literal) return [literal];
        if (node.type !== "identifier") return null;
        const entries = lookup(node.text, node);
        if (!entries || !entries.every(e => e.kind === "alias" && stringLiteral(e.value))) return null;
        return entries.map(e => stringLiteral(e.value));
    }

    function callResult(q) {
        if (PATH_FACTORY.test(q)) return PATH;
        const dot = q.lastIndexOf(".");
        if (q.startsWith(`${PATH}.`) && PATH_RETURNING.has(q.slice(dot + 1))) return PATH;
        return `${q}()`;
    }

    // Memoized per node; a name whose value refers back to itself
    // (x = x.parent) resolves to nothing on the cyclic path.
    const memo = new Map();
    function resolve(node, depth = 0) {
        if (!node || depth > 20) return new Set();
        const cached = memo.get(node.id);
        if (cached) return cached;
        const out = new Set();
        memo.set(node.id, out);
        switch (node.type) {
            case "identifier": {
                const entries = lookup(node.text, node);
                if (!entries) {
                    if (BUILTINS.has(node.text)) out.add(`builtins.${node.text}`);
                    if (IMPLICIT_MODULES.has(node.text)) out.add(node.text);
                    // from m import * may have bound it to m.<name>.
                    for (const module of stars) out.add(canonical(`${module}.${node.text}`));
                    break;
                }
                for (const entry of entries) {
                    if (entry.kind === "import") out.add(canonical(entry.q));
                    else if (entry.kind === "alias") for (const q of resolve(entry.value, depth + 1)) out.add(q);
                }
                break;
            }
            case "attribute": {
                const attribute = text(field(node, "attribute"));
                for (const q of resolve(field(node, "object"), depth + 1)) {
                    out.add(q === PATH && (attribute === "parent") ? PATH : canonical(`${q}.${attribute}`));
                }
                break;
            }
            case "call": {
                const { positional, keywords } = callArguments(node);
                for (const q of resolve(field(node, "function"), depth + 1)) {
                    // __import__("os") / importlib.import_module("os") is the module;
                    // getattr(os, "system") is os.system.
                    const name = stringLiteral(positional[0] || keywords.get("name"));
                    if (IMPORT_CALLS.has(q) && name) {
                        out.add(canonical(q === "builtins.__import__" ? name.split(".")[0] : name));
                    } else if (q === "builtins.getattr" && positional[1]) {
                        const names = attributeNames(positional[1]);
                        for (const base of resolve(positional[0], depth + 1)) {
                            if (names) for (const n of names) out.add(canonical(`${base}.${n}`));
                            // getattr(ctypes, name) with a name built at run time can be any loader.
                            else if (NATIVE_DYNAMIC_BASE.test(base) && !isCtypesTypeName(positional[1])) out.add(`${base}.${DYNAMIC_NAME}`);
                        }
                    } else {
                        out.add(callResult(q));
                    }
                }
                break;
            }
            case "subscript": {
                const name = stringLiteral(field(node, "subscript"));
                if (!name) break;
                const value = field(node, "value");
                // vars(ctypes)["CDLL"] / ctypes.__dict__["CDLL"] is ctypes.CDLL.
                const varsOf = value?.type === "call" && text(field(value, "function")) === "vars" && !lookup("vars", value)
                    ? callArguments(value).positional[0] : null;
                for (const base of varsOf ? resolve(varsOf, depth + 1) : []) out.add(canonical(`${base}.${name}`));
                for (const q of resolve(value, depth + 1)) {
                    if (q.endsWith(".__dict__")) out.add(canonical(`${q.slice(0, -".__dict__".length)}.${name}`));
                    else if (NATIVE_SUBSCRIPT.test(q)) out.add(`${q}.${name}`);
                    else if (q === "sys.modules") out.add(canonical(name));
                }
                break;
            }
            case "binary_operator":
                if (text(field(node, "operator")) === "/") {
                    for (const q of resolve(field(node, "left"), depth + 1)) if (q === PATH) out.add(PATH);
                }
                break;
            case "parenthesized_expression":
            case "await":
                for (const q of resolve(node.namedChildren[0], depth + 1)) out.add(q);
                break;
            default:
                break;
        }
        return out;
    }

    return { resolve };
}

function callArguments(call) {
    const positional = [];
    const keywords = new Map();
    for (const arg of field(call, "arguments")?.namedChildren || []) {
        if (arg.type === "keyword_argument") keywords.set(text(field(arg, "name")), field(arg, "value"));
        else if (arg.type !== "comment") positional.push(arg);
    }
    return { positional, keywords };
}

// PyTorch >= 2.6 defaults weights_only to True unless pickle_module is given
// (and rejects weights_only=True with a pickle_module). Before 2.6, or with
// TORCH_FORCE_NO_WEIGHTS_ONLY_LOAD=1, a bare torch.load() unpickles too; the
// installed version and environment are not visible here.
function torchLoadUnpickles(positional, keywords) {
    const given = node => Boolean(node) && text(node) !== "None";
    const weightsOnly = keywords.get("weights_only");
    if (given(weightsOnly) && text(weightsOnly) === "True") return false;
    return given(weightsOnly) || given(keywords.get("pickle_module") || positional[2]);
}

function rootModule(q) {
    return q.split(".")[0].replace(/\(\)$/, "");
}

function extract(content) {
    const ast = TreeParser.parse(String(content || ""), "python");
    try {
        return extractFrom(ast);
    } finally {
        TreeParser.release(ast);
    }
}

function extractFrom(ast) {
    const facts = emptyFacts();

    if (!ast.ok || !ast.root || ast.metrics?.hasError) {
        facts.error = ast.error || "source did not parse cleanly";
        return facts;
    }

    facts.ast = true;
    const root = ast.root;
    const { resolve } = createResolver(root);
    const ops = facts.operations;
    const routes = new Set();
    const imports = new Set();
    const env = new Set();
    const calls = { network: new Set(), filesystem: new Set(), process: new Set(), crypto: new Set(), dynamic: new Set() };
    const signals = [];
    const signal = (name, evidence, node) => signals.push({ signal: name, evidence, line: line(node) });

    const addEnv = (name, node) => {
        env.add(name);
        if (SECRETISH.test(name)) signal("secret_access", `os.environ.${name}`, node);
    };

    const visitImport = (module, node) => {
        imports.add(module);
        const top = module.split(".")[0];
        if (PROCESS_MODULES.has(top)) {
            ops.childProcess = true;
            calls.process.add(`import(${top})`);
            signal("child_process_import", `import(${top})`, node);
        }
    };

    const visitRoute = (decorator) => {
        const call = decorator.namedChildren[0];
        if (call?.type !== "call") return;
        const callee = field(call, "function");
        if (callee?.type !== "attribute") return;
        const method = text(field(callee, "attribute"));
        if (!ROUTE_METHODS.has(method)) return;
        const host = field(callee, "object");
        const hostIsApp = [...resolve(host)].some(q => ROUTE_FACTORIES.has(q.replace(/\(\)$/, "")) && q.endsWith("()")) ||
            (host?.type === "identifier" && ROUTE_HOSTS.has(host.text));
        if (!hostIsApp) return;
        const { positional, keywords } = callArguments(call);
        const routePath = stringLiteral(positional[0]) ?? stringLiteral(keywords.get("path") || keywords.get("rule"));
        if (routePath === null) return;
        let verbs = method === "route" || method === "api_route" ? ["GET"] : [method.toUpperCase()];
        const listed = keywords.get("methods");
        if (listed && (listed.type === "list" || listed.type === "tuple")) {
            const names = listed.namedChildren.map(stringLiteral).filter(Boolean).map(v => v.toUpperCase());
            if (names.length > 0) verbs = names;
        }
        for (const verb of verbs) routes.add(`${verb} ${routePath}`);
        ops.inboundHttp = true;
        calls.network.add(`${text(host)}.${method}`);
        signal("inbound_http", `${text(host)}.${method}`, decorator);
    };

    const usesCtypes = () => [...imports].some(m => m === "ctypes" || m === "_ctypes" || m.startsWith("ctypes."));

    const visitCall = (call) => {
        const { positional, keywords } = callArguments(call);
        const fn = field(call, "function");
        // class S(ctypes.Structure) ... S.from_address(address): S resolves to nothing.
        if (fn?.type === "attribute" && text(field(fn, "attribute")) === "from_address" &&
            resolve(fn).size === 0 && usesCtypes()) {
            ops.nativeCode = true;
            calls.dynamic.add(`${text(field(fn, "object"))}.from_address`);
            signal("native_code", `${text(field(fn, "object"))}.from_address`, call);
        }
        for (const q of resolve(field(call, "function"))) {
            const dot = q.lastIndexOf(".");
            const head = q.slice(0, dot);
            const tail = q.slice(dot + 1);

            if (PROCESS_CALLS.has(q)) {
                ops.processSpawn = true;
                calls.process.add(q);
                signal("process_spawn", q, call);
            } else if (isNativeCall(q, call, positional, usesCtypes)) {
                ops.nativeCode = true;
                calls.dynamic.add(q);
                signal("native_code", q, call);
            } else if (DYNAMIC_CALLS.has(q)) {
                const evidence = q.slice("builtins.".length);
                ops.dynamicEval = true;
                calls.dynamic.add(evidence);
                signal("dynamic_code", evidence, call);
            } else if (DESERIALIZE_CALLS.has(q) ||
                (YAML_LOAD_CALLS.has(q) && ![...resolve(keywords.get("Loader") || positional[1])].some(l => SAFE_YAML_LOADER.test(l))) ||
                (q === "numpy.load" && text(keywords.get("allow_pickle")) === "True") ||
                (q === "torch.load" && torchLoadUnpickles(positional, keywords))) {
                ops.unsafeDeserialization = true;
                calls.dynamic.add(q);
                signal("unsafe_deserialization", q, call);
            } else if (EXIT_CALLS.has(q)) {
                ops.processExit = true;
                calls.process.add(q.replace(/^builtins\./, ""));
                signal("process_exit", q.replace(/^builtins\./, ""), call);
            } else if (FS_DELETE.has(q)) {
                ops.diskDelete = true;
                calls.filesystem.add(q);
                signal("destructive_fs", q, call);
            } else if (FS_WRITE.has(q)) {
                ops.diskWrite = true;
                calls.filesystem.add(q);
                signal("disk_write", q, call);
            } else if (FS_READ.has(q)) {
                ops.diskRead = true;
                calls.filesystem.add(q);
            } else if (OPEN_CALLS.has(q)) {
                const modeNode = keywords.get("mode") || positional[OPEN_CALLS.get(q)];
                const mode = modeNode ? stringLiteral(modeNode) : "r";
                const evidence = q.replace(/^builtins\./, "");
                calls.filesystem.add(evidence);
                if (mode === null || /[wax+]/.test(mode)) {
                    ops.diskWrite = true;
                    signal("disk_write", evidence, call);
                }
                if (mode === null || !/[wax]/.test(mode) || mode.includes("+")) ops.diskRead = true;
            } else if (NETWORK_CALLS.has(q) ||
                (HTTP_MODULES.has(head) && HTTP_METHODS.has(tail)) ||
                (head.endsWith("()") && HTTP_CLIENTS.has(head.slice(0, -2)) && HTTP_METHODS.has(tail)) ||
                (head.endsWith("()") && URL_OPENERS.has(head.slice(0, -2)) && URL_OPENER_METHODS.has(tail))) {
                ops.outboundHttp = true;
                calls.network.add(q);
                signal("outbound_http", q, call);
            } else if (SERVER_CALLS.has(q)) {
                ops.inboundHttp = true;
                calls.network.add(q);
                signal("inbound_http", q, call);
            } else if (q === "os.getenv" || q === "os.environ.get" || q === "os.environ.setdefault") {
                const name = stringLiteral(positional[0]);
                if (name) addEnv(name, call);
            } else if (CRYPTO_MODULES.has(rootModule(q)) && !q.includes("()")) {
                ops.cryptoUse = true;
                calls.crypto.add(q);
                if (CONSTANT_COMPARE.has(q)) signal("secret_comparison", q, call);
                else signal("crypto_use", q, call);
            }
        }
    };

    walk(root, node => {
        switch (node.type) {
            case "import_statement":
                for (const name of node.namedChildren) {
                    imports.add(text(name.type === "aliased_import" ? field(name, "name") : name));
                    visitImport(text(name.type === "aliased_import" ? field(name, "name") : name), node);
                }
                break;
            case "import_from_statement":
                visitImport(moduleName(field(node, "module_name")), node);
                break;
            case "exec_statement":
                ops.dynamicEval = true;
                calls.dynamic.add("exec");
                signal("dynamic_code", "exec", node);
                break;
            case "decorator":
                visitRoute(node);
                break;
            case "call":
                visitCall(node);
                break;
            case "subscript": {
                const value = field(node, "value");
                if ([...resolve(value)].includes("os.environ")) {
                    const name = stringLiteral(field(node, "subscript"));
                    if (name) addEnv(name, node);
                }
                break;
            }
            case "comparison_operator": {
                const operators = node.children.filter(c => !c.isNamed).map(c => c.type);
                if (!operators.some(op => op === "==" || op === "!=")) break;
                const sides = node.namedChildren.map(text);
                if (sides.some(side => SECRETISH.test(side))) {
                    ops.secretComparison = true;
                    signal("secret_comparison", text(node).replace(/\s+/g, " ").slice(0, 80), node);
                }
                break;
            }
            default:
                break;
        }
    });

    facts.routes = [...routes];
    facts.exports = exportsOf(root);
    facts.imports = [...imports].sort();
    facts.env = [...env].sort();
    facts.calls = {
        network: [...calls.network].sort(),
        filesystem: [...calls.filesystem].sort(),
        process: [...calls.process].sort(),
        crypto: [...calls.crypto].sort(),
        dynamic: [...calls.dynamic].sort()
    };
    facts.dangerous = dangerousOf(ops);
    facts.riskSignals = signals;
    return facts;
}

// Python has no export statement: `__all__` when it is a literal list or
// tuple, otherwise the public (no leading underscore) top-level defs and classes.
function exportsOf(root) {
    const names = new Set();
    let explicit = null;
    for (const statement of root.namedChildren) {
        const definition = statement.type === "decorated_definition" ? field(statement, "definition") : statement;
        if (definition && (definition.type === "function_definition" || definition.type === "class_definition")) {
            const name = text(field(definition, "name"));
            if (name && !name.startsWith("_")) names.add(name);
        }
        const assignment = statement.type === "expression_statement" ? statement.namedChildren[0] : null;
        if (assignment?.type === "assignment" && text(field(assignment, "left")) === "__all__") {
            const right = field(assignment, "right");
            if (right && (right.type === "list" || right.type === "tuple")) {
                explicit = right.namedChildren.map(stringLiteral).filter(v => v !== null);
            }
        }
    }
    return [...(explicit || names)].sort();
}

module.exports = { extract };
