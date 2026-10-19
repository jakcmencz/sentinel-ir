/**
 * SENTINEL AUTONOMOUS AGENT SYSTEM
 * MODULE: libs/core/ast-facts.js
 *
 * Purpose:
 * Extract STRUCTURAL FACTS from the tree-sitter AST instead of guessing them
 * from substrings. Sentinel-IR used to answer "does this file touch the
 * network?" with `content.includes("axios")`, which reads an Express server as
 * network-free and a function called `evaluate` as `eval`. Everything here is
 * derived from real nodes: a call is a call_expression, a route is a call on
 * `app`/`router`/`server` with a string path, an env read is a member access on
 * `process.env`.
 *
 * JavaScript
 *      ↓
 * TreeParser (tree-sitter)
 *      ↓
 * AstFacts   <- this module: routes / exports / imports / env / calls / risk
 *      ↓
 * Sentinel-IR
 *
 * Deterministic, local and dependency-free (tree-sitter is already a runtime
 * dependency). No network, no LLM, no I/O.
 */

const TreeParser = require("./tree-parser");

const ROUTE_HOSTS = new Set(["app", "router", "server", "api"]);
const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "all"]);

const FS_WRITE = new Set([
    "writeFile", "writeFileSync", "appendFile", "appendFileSync", "mkdir", "mkdirSync",
    "copyFile", "copyFileSync", "rename", "renameSync", "createWriteStream", "write",
    "writeSync", "chmod", "chmodSync", "symlink", "symlinkSync"
]);
const FS_DELETE = new Set([
    "rm", "rmSync", "rmdir", "rmdirSync", "unlink", "unlinkSync", "truncate", "truncateSync"
]);
const FS_READ = new Set([
    "readFile", "readFileSync", "readdir", "readdirSync", "existsSync", "stat", "statSync",
    "createReadStream", "realpathSync", "access", "accessSync"
]);

const HTTP_CLIENTS = new Set(["axios", "got", "superagent", "request"]);
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "head", "request"]);
const NODE_HTTP = new Set(["http", "https", "http2"]);

const SPAWN_FUNCTIONS = new Set([
    "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork", "execFileAsync"
]);

// `regex.exec(input)` and `cluster.fork()` share their names with the
// child_process API, so these two are only process spawning when the callee is
// bound to a spawning module. The rest of SPAWN_FUNCTIONS is unambiguous enough
// to flag on the bare name.
const SPAWN_ONLY_WHEN_BOUND = new Set(["exec", "fork"]);

const SPAWN_MODULES = new Set([
    "child_process", "node:child_process", "cross-spawn", "execa", "shelljs", "zx"
]);

const CHILD_PROCESS_MODULES = new Set(["child_process", "node:child_process"]);

const CRYPTO_METHODS = new Set([
    "createHash", "createHmac", "createCipheriv", "createDecipheriv", "pbkdf2", "pbkdf2Sync",
    "scrypt", "scryptSync", "randomBytes", "randomUUID", "sign", "verify", "timingSafeEqual",
    "publicEncrypt", "privateDecrypt", "generateKeyPairSync"
]);

const SECRETISH = /(token|secret|signature|api[_-]?key|apikey|password|passwd|credential|auth|hmac|digest)/i;

// ---------------------------------------------------------------------------
// Small AST helpers
// ---------------------------------------------------------------------------

function walk(node, visit) {
    if (!node) return;
    visit(node);
    const children = node.namedChildren || node.children || [];
    for (const child of children) walk(child, visit);
}

function text(node) {
    return node && typeof node.text === "string" ? node.text : "";
}

function line(node) {
    const row = node?.startPosition?.row;
    return typeof row === "number" ? row + 1 : null;
}

function field(node, name) {
    if (!node || typeof node.childForFieldName !== "function") return null;
    try {
        return node.childForFieldName(name);
    } catch {
        return null;
    }
}

function stringLiteral(node) {
    if (!node) return null;
    if (node.type === "string" || node.type === "template_string") {
        const raw = text(node);
        return raw.replace(/^["'`]/, "").replace(/["'`]$/, "");
    }
    return null;
}

// A call target split into `object.property`, e.g. fs.writeFileSync or
// crypto.createHmac. `object` is null for a bare identifier call like eval(x).
function callTarget(callNode) {
    const callee = field(callNode, "function") || (callNode.namedChildren || [])[0];
    if (!callee) return { object: null, property: null, raw: "" };

    // `import("child_process")` is its own node type, not an identifier.
    if (callee.type === "identifier" || callee.type === "import") {
        return { object: null, property: text(callee), raw: text(callee) };
    }

    if (callee.type === "member_expression") {
        const object = field(callee, "object");
        const property = field(callee, "property");
        // Normalise chains (crypto.createHmac(...).update(...)) to their tail
        // object text so `fs.promises.writeFile` still reads as filesystem.
        return {
            object: object ? text(object).split("\n")[0] : null,
            property: property ? text(property) : null,
            raw: text(callee).split("\n")[0]
        };
    }

    if (callee.type === "subscript_expression") {
        const object = field(callee, "object");
        const index = field(callee, "index");
        return {
            object: object ? text(object).split("\n")[0] : null,
            property: stringLiteral(index),
            raw: text(callee).split("\n")[0]
        };
    }

    return { object: null, property: null, raw: text(callee).split("\n")[0] };
}

function args(callNode) {
    const list = field(callNode, "arguments");
    return list ? (list.namedChildren || []) : [];
}

function rootObjectOf(objectText) {
    return String(objectText || "").split(".")[0].replace(/\(.*$/, "").trim();
}


// Resolve whether a bare dynamic-code name is shadowed by a local binding.
// This is a conservative AST-based scope check, not a complete JS resolver.
const FUNCTION_SCOPE_TYPES = new Set([
    "function_declaration", "function_expression", "arrow_function",
    "generator_function_declaration", "generator_function", "method_definition"
]);

const LEXICAL_SCOPE_TYPES = new Set([
    "program", "statement_block", "switch_body", "catch_clause",
    "for_statement", "for_in_statement", "for_of_statement"
]);

function bindingPatternHasName(node, name) {
    if (!node) return false;

    if (node.type === "identifier" ||
        node.type === "shorthand_property_identifier_pattern") {
        return text(node) === name;
    }

    // Default parameter: only its left side declares a binding.
    if (node.type === "assignment_pattern") {
        const left = field(node, "left") ||
            (node.namedChildren || [])[0];
        return bindingPatternHasName(left, name);
    }

    // Object destructuring: the value side is the bound name.
    if (node.type === "pair_pattern") {
        const value = field(node, "value");
        const children = node.namedChildren || [];
        return bindingPatternHasName(
            value || children[children.length - 1], name
        );
    }

    return (node.namedChildren || []).some(
        child => bindingPatternHasName(child, name)
    );
}

function declarationNameIs(node, name) {
    return text(field(node, "name")) === name;
}

function lexicalDeclarationHasName(node, name) {
    if (!node) return false;

    if (node.type === "variable_declarator") {
        return bindingPatternHasName(field(node, "name"), name);
    }

    if (FUNCTION_SCOPE_TYPES.has(node.type) ||
        node.type === "class_expression") {
        return false;
    }

    return (node.namedChildren || []).some(
        child => lexicalDeclarationHasName(child, name)
    );
}


function importStatementHasBinding(statement, name) {
    const clause = (statement.namedChildren || []).find(
        child => child.type === "import_clause"
    );

    if (!clause) return false;

    for (const child of clause.namedChildren || []) {
        // Default import: import Function from "module"
        if (child.type === "identifier" && text(child) === name) {
            return true;
        }

        // Namespace import: import * as Function from "module"
        if (child.type === "namespace_import") {
            const children = child.namedChildren || [];
            const local = field(child, "alias") ||
                children[children.length - 1];

            if (local && text(local) === name) return true;
        }

        // Named imports: import { run as Function } from "module"
        if (child.type === "named_imports") {
            for (const specifier of child.namedChildren || []) {
                if (specifier.type !== "import_specifier") continue;

                const children = specifier.namedChildren || [];
                const local = field(specifier, "alias") ||
                    (children.length >= 2
                        ? children[children.length - 1]
                        : field(specifier, "name") || children[0]);

                if (local && text(local) === name) return true;
            }
        }
    }

    return false;
}

function lexicalScopeHasBinding(scope, name) {
    if (scope.type === "catch_clause") {
        const parameter = field(scope, "parameter") ||
            (scope.namedChildren || []).find(
                child => child.type === "identifier" ||
                         child.type === "catch_formal_parameter"
            );

        if (bindingPatternHasName(parameter, name)) return true;
    }

    function scan(node) {
        for (const child of node.namedChildren || []) {
            if (child.type === "import_statement" &&
                importStatementHasBinding(child, name)) {
                return true;
            }
            if (FUNCTION_SCOPE_TYPES.has(child.type)) {
                if (child.type === "function_declaration" &&
                    declarationNameIs(child, name)) {
                    return true;
                }
                continue;
            }

            if (child.type === "class_declaration") {
                if (declarationNameIs(child, name)) return true;
                continue;
            }

            // These create their own lexical scopes.
            if (LEXICAL_SCOPE_TYPES.has(child.type)) continue;

            if (child.type === "lexical_declaration" &&
                lexicalDeclarationHasName(child, name)) {
                return true;
            }

            if (scan(child)) return true;
        }

        return false;
    }

    return scan(scope);
}

function varScopeHasBinding(scope, name) {
    function scan(node) {
        for (const child of node.namedChildren || []) {
            // A nested function has its own var scope.
            if (FUNCTION_SCOPE_TYPES.has(child.type)) continue;

            if (child.type === "variable_declarator") {
                if (bindingPatternHasName(field(child, "name"), name)) {
                    let parent = child.parent;

                    while (parent && parent !== scope) {
                        if (parent.type === "lexical_declaration") break;
                        if (parent.type === "variable_declaration") return true;
                        parent = parent.parent;
                    }
                }
                continue;
            }

            if (scan(child)) return true;
        }

        return false;
    }

    return scan(scope);
}

function functionScopeHasBinding(scope, name) {
    // A method name is a property name, not a lexical binding.
    // Named function declarations and expressions do create bindings.
    if (
        ["function_declaration", "function_expression",
         "generator_function_declaration", "generator_function"]
            .includes(scope.type) &&
        declarationNameIs(scope, name)
    ) {
        return true;
    }

    const parameters = field(scope, "parameters") ||
        field(scope, "parameter");

    if (bindingPatternHasName(parameters, name)) return true;

    for (const child of scope.namedChildren || []) {
        if (child.type === "formal_parameters" &&
            bindingPatternHasName(child, name)) {
            return true;
        }
    }

    return varScopeHasBinding(scope, name);
}

function isNameShadowed(reference, name) {
    let current = reference;

    while (current) {
        if (FUNCTION_SCOPE_TYPES.has(current.type) &&
            functionScopeHasBinding(current, name)) {
            return true;
        }

        if (LEXICAL_SCOPE_TYPES.has(current.type) &&
            lexicalScopeHasBinding(current, name)) {
            return true;
        }

        // Top-level var declarations also shadow the global name.
        if (current.type === "program" &&
            varScopeHasBinding(current, name)) {
            return true;
        }

        current = current.parent;
    }

    return false;
}


function isUnshadowedGlobalThis(callee) {
    if (!callee ||
        (callee.type !== "member_expression" &&
         callee.type !== "subscript_expression")) {
        return false;
    }

    const receiver = field(callee, "object");

    return receiver?.type === "identifier" &&
        text(receiver) === "globalThis" &&
        !isNameShadowed(receiver, "globalThis");
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

function emptyFacts() {
    return {
        ast: false,
        routes: [],
        exports: [],
        imports: [],
        env: [],
        calls: { network: [], filesystem: [], process: [], crypto: [], dynamic: [] },
        operations: {
            inboundHttp: false,
            outboundHttp: false,
            diskRead: false,
            diskWrite: false,
            diskDelete: false,
            dynamicEval: false,
            processSpawn: false,
            childProcess: false,
            processExit: false,
            cryptoUse: false,
            secretComparison: false
        },
        dangerous: [],
        riskSignals: []
    };
}

// tree-sitter recovers from broken syntax by inserting ERROR nodes, and the
// node itself is the only reliable place to ask.
function hasParseError(ast) {
    if (ast.metrics?.hasError) return true;
    const root = ast.root;
    if (typeof root.hasError === "function") return Boolean(root.hasError());
    return Boolean(root.hasError);
}

function extract(content) {
    const facts = emptyFacts();
    const ast = TreeParser.parse(String(content || ""));

    // A partial parse would report proven absences that are really parser gaps,
    // so anything with an ERROR node is handed back to the text fallback.
    if (!ast.ok || !ast.root || hasParseError(ast)) {
        facts.error = ast.error || "source did not parse cleanly";
        return facts;
    }

    facts.ast = true;

    const spawnBindings = spawnBindingsOf(ast.root);
    const routes = new Set();
    const exportsFound = new Set();
    const imports = new Set();
    const env = new Set();
    const calls = { network: new Set(), filesystem: new Set(), process: new Set(), crypto: new Set(), dynamic: new Set() };
    const signals = [];

    const signal = (name, evidence, node) => {
        signals.push({ signal: name, evidence, line: line(node) });
    };

    walk(ast.root, node => {
        switch (node.type) {
            case "call_expression":
                visitCall(node, { facts, routes, imports, calls, signal, spawnBindings });
                break;
            case "new_expression": {
                const constructor = field(node, "constructor");
                const constructorObject = constructor && field(constructor, "object");
                const constructorProperty = constructor && field(constructor, "property");
                const constructorIndex = constructor && field(constructor, "index");

                const directFunction =
                    constructor?.type === "identifier" &&
                    text(constructor) === "Function" &&
                    !isNameShadowed(constructor, "Function");

                const globalFunction =
                    constructor?.type === "member_expression" &&
                    text(constructorObject) === "globalThis" &&
                    isUnshadowedGlobalThis(constructor) &&
                    text(constructorProperty) === "Function";

                const computedGlobalFunction =
                    constructor?.type === "subscript_expression" &&
                    text(constructorObject) === "globalThis" &&
                    isUnshadowedGlobalThis(constructor) &&
                    stringLiteral(constructorIndex) === "Function";

                if (directFunction || globalFunction || computedGlobalFunction) {
                    const evidence = "new " + text(constructor);
                    facts.operations.dynamicEval = true;
                    calls.dynamic.add(evidence);
                    signal("dynamic_code", evidence, node);
                }
                break;
            }
            case "member_expression":
                visitMember(node, { facts, env, signal });
                break;
            case "subscript_expression":
                visitSubscript(node, { env });
                break;
            case "assignment_expression":
                visitAssignment(node, { exportsFound });
                break;
            case "export_statement":
                visitExport(node, { exportsFound });
                break;
            case "import_statement": {
                const source = stringLiteral(field(node, "source"));
                if (source) {
                    imports.add(source);
                    if (CHILD_PROCESS_MODULES.has(source)) {
                        const evidence = "import(child_process)";
                        facts.operations.childProcess = true;
                        calls.process.add(evidence);
                        signal("child_process_import", evidence, node);
                    }
                }
                break;
            }
            case "binary_expression":
                visitComparison(node, { facts, signal });
                break;
            default:
                break;
        }
    });

    facts.routes = [...routes];
    facts.exports = [...exportsFound].sort();
    facts.imports = [...imports].sort();
    facts.env = [...env].sort();
    facts.calls = {
        network: [...calls.network].sort(),
        filesystem: [...calls.filesystem].sort(),
        process: [...calls.process].sort(),
        crypto: [...calls.crypto].sort(),
        dynamic: [...calls.dynamic].sort()
    };
    facts.dangerous = dangerousOf(facts.operations);
    facts.riskSignals = signals;

    return facts;
}

// Local names that resolve to a process-spawning module, collected before the
// main walk so a call is judged by what its callee is, not by its spelling:
//   const cp = require("child_process")     -> modules: cp
//   const { exec: sh } = require("child_process") -> functions: sh
//   import { spawn } from "node:child_process"    -> functions: spawn
function spawnBindingsOf(root) {
    const modules = new Set();
    const functions = new Set();

    const bindNames = (target, source) => {
        if (!target || !SPAWN_MODULES.has(source)) return;
        if (target.type === "identifier") {
            modules.add(text(target));
            return;
        }
        // Destructuring: every bound local name is a spawn function.
        walk(target, node => {
            if (node.type === "shorthand_property_identifier_pattern") functions.add(text(node));
            if (node.type === "pair_pattern") {
                // `{ exec: sh }` binds the local name, which is the pattern's tail.
                const children = node.namedChildren || [];
                const value = children[children.length - 1];
                if (value && value.type === "identifier") functions.add(text(value));
            }
        });
    };

    walk(root, node => {
        if (node.type === "variable_declarator") {
            // `await import("child_process")` binds exactly like `require`.
            let value = field(node, "value");
            if (value && value.type === "await_expression") {
                value = field(value, "argument") || (value.namedChildren || [])[0];
            }
            if (value && value.type === "call_expression") {
                const { object, property } = callTarget(value);
                if (!object && (property === "require" || property === "import")) {
                    bindNames(field(node, "name"), stringLiteral(args(value)[0]));
                }
            }
            return;
        }

        if (node.type === "import_statement") {
            const source = stringLiteral(field(node, "source"));
            if (!source || !SPAWN_MODULES.has(source)) return;
            walk(node, child => {
                if (child.type === "import_specifier") {
                    const alias = field(child, "alias") || field(child, "name");
                    if (alias) functions.add(text(alias));
                } else if (child.type === "namespace_import" || child.type === "import_clause") {
                    const name = field(child, "name") || (child.namedChildren || [])[0];
                    if (name && name.type === "identifier") modules.add(text(name));
                }
            });
        }
    });

    return { modules, functions };
}

function isSpawnCall({ object, property, raw }, host, spawnBindings) {
    if (!property) return false;

    // Anything imported from a spawning module spawns, whatever it is called.
    if (object ? spawnBindings.modules.has(host) : spawnBindings.functions.has(property)) return true;

    if (!SPAWN_FUNCTIONS.has(property)) return false;

    if (object) {
        // require("child_process").exec(...), childProcess.spawn(...)
        if (/child_process/.test(raw)) return true;
        return !SPAWN_ONLY_WHEN_BOUND.has(property) && /^(child_?process|cp)$/i.test(host);
    }

    return !SPAWN_ONLY_WHEN_BOUND.has(property);
}

function visitCall(node, { facts, routes, imports, calls, signal, spawnBindings }) {
    const { object, property, raw } = callTarget(node);
    const callArgs = args(node);
    const host = rootObjectOf(object);

    // require("child_process") / import("fs") / require("fs") -> imports
    const importer = !object && (property === "require" || property === "import");
    if (importer) {
        const source = stringLiteral(callArgs[0]);
        if (source) {
            imports.add(source);
            if (CHILD_PROCESS_MODULES.has(source)) {
                const evidence = `${property}(child_process)`;
                facts.operations.childProcess = true;
                calls.process.add(evidence);
                signal("child_process_import", evidence, node);
            }
        }
        return;
    }

    // Express-style routes: app.get("/health", handler)
    if (object && ROUTE_HOSTS.has(host) && property && ROUTE_METHODS.has(property)) {
        const routePath = stringLiteral(callArgs[0]);
        if (routePath && routePath.startsWith("/")) {
            routes.add(`${property.toUpperCase()} ${routePath}`);
            facts.operations.inboundHttp = true;
            calls.network.add(`${host}.${property}`);
            return;
        }
    }

    // Inbound HTTP surface: app.listen(...), http.createServer(...)
    if (property === "listen" || property === "createServer" || (!object && property === "createServer")) {
        facts.operations.inboundHttp = true;
        calls.network.add(raw || String(property));
        signal("inbound_http", raw || String(property), node);
        return;
    }

    // Outbound HTTP: axios.post(...), fetch(...), https.request(...)
    if (object && (HTTP_CLIENTS.has(host) || NODE_HTTP.has(host)) && property && HTTP_METHODS.has(property)) {
        facts.operations.outboundHttp = true;
        calls.network.add(`${host}.${property}`);
        signal("outbound_http", `${host}.${property}`, node);
        return;
    }
    if (!object && (property === "fetch" || property === "axios")) {
        facts.operations.outboundHttp = true;
        calls.network.add(String(property));
        signal("outbound_http", String(property), node);
        return;
    }

    // Filesystem, classified by the method that is actually called
    if (object && (host === "fs" || host === "fsp" || host === "fileSystem")) {
        const name = `${object}.${property}`;
        calls.filesystem.add(name);
        if (FS_DELETE.has(property)) {
            facts.operations.diskDelete = true;
            signal("destructive_fs", name, node);
        } else if (FS_WRITE.has(property)) {
            facts.operations.diskWrite = true;
            signal("disk_write", name, node);
        } else if (FS_READ.has(property)) {
            facts.operations.diskRead = true;
        }
        return;
    }

    // Process spawning, whether destructured or called through child_process
    if (isSpawnCall({ object, property, raw }, host, spawnBindings)) {
        facts.operations.processSpawn = true;
        calls.process.add(object ? `${object}.${property}` : String(property));
        signal("process_spawn", object ? `${object}.${property}` : String(property), node);
        return;
    }

    // Dynamic code execution. Do not flag arbitrary object methods named eval.
    if (
        (!object && property === "eval" &&
         !isNameShadowed(field(node, "function"), "eval")) ||
        (object === "globalThis" && property === "eval" &&
         isUnshadowedGlobalThis(field(node, "function")))
    ) {
        const evidence = raw || "eval";
        facts.operations.dynamicEval = true;
        calls.dynamic.add(evidence);
        signal("dynamic_code", evidence, node);
        return;
    }

    // Function(...) can construct executable code even without the new keyword.
    if (
        (!object && property === "Function" &&
         !isNameShadowed(field(node, "function"), "Function")) ||
        (object === "globalThis" && property === "Function" &&
         isUnshadowedGlobalThis(field(node, "function")))
    ) {
        const evidence = raw || "Function";
        facts.operations.dynamicEval = true;
        calls.dynamic.add(evidence);
        signal("dynamic_code", evidence, node);
        return;
    }

    // process.exit(1)
    if (object === "process" && property === "exit") {
        facts.operations.processExit = true;
        calls.process.add("process.exit");
        signal("process_exit", "process.exit", node);
        return;
    }

    // Crypto / secret handling
    if (property && CRYPTO_METHODS.has(property) && (host === "crypto" || host === "webcrypto" || SECRETISH.test(raw))) {
        facts.operations.cryptoUse = true;
        calls.crypto.add(`${host || "crypto"}.${property}`);
        if (property === "timingSafeEqual") {
            facts.operations.secretComparison = true;
            signal("secret_comparison", "crypto.timingSafeEqual", node);
        } else {
            signal("crypto_use", `${host || "crypto"}.${property}`, node);
        }
    }
}

function visitMember(node, { facts, env, signal }) {
    // process.env.NAME
    const object = field(node, "object");
    const property = field(node, "property");
    if (!object || !property) return;

    if (text(object) === "process.env") {
        env.add(text(property));
        if (SECRETISH.test(text(property))) {
            signal("secret_access", `process.env.${text(property)}`, node);
        }
    }
}

function visitSubscript(node, { env }) {
    // process.env["NAME"]
    const object = field(node, "object");
    const index = field(node, "index");
    if (object && text(object) === "process.env") {
        const name = stringLiteral(index);
        if (name) env.add(name);
    }
}

function visitAssignment(node, { exportsFound }) {
    const left = field(node, "left");
    const right = field(node, "right");
    if (!left) return;

    const leftText = text(left).replace(/\s+/g, "");

    if (leftText === "module.exports" || leftText === "exports") {
        if (right && right.type === "object") {
            for (const child of right.namedChildren || []) {
                if (child.type === "shorthand_property_identifier") {
                    exportsFound.add(text(child));
                } else if (child.type === "pair") {
                    const key = field(child, "key");
                    if (key) exportsFound.add(text(key).replace(/["'`]/g, ""));
                }
            }
            return;
        }
        if (right && (right.type === "identifier" || right.type === "function_expression" || right.type === "arrow_function")) {
            exportsFound.add(right.type === "identifier" ? text(right) : "default");
        }
        return;
    }

    // module.exports.name = ... / exports.name = ...
    const named = leftText.match(/^(?:module\.)?exports\.([A-Za-z_$][\w$]*)$/);
    if (named) exportsFound.add(named[1]);
}

function visitExport(node, { exportsFound }) {
    // export default <expr>
    if (node.children?.some(child => child.type === "default")) {
        exportsFound.add("default");
    }

    const declaration = field(node, "declaration");
    if (declaration) {
        const name = field(declaration, "name");
        if (name) {
            exportsFound.add(text(name));
            return;
        }
        for (const child of declaration.namedChildren || []) {
            const declaredName = field(child, "name");
            if (declaredName) exportsFound.add(text(declaredName));
        }
        return;
    }

    for (const child of node.namedChildren || []) {
        if (child.type === "export_clause") {
            for (const spec of child.namedChildren || []) {
                const name = field(spec, "name");
                if (name) exportsFound.add(text(name));
            }
        }
    }
}

function visitComparison(node, { facts, signal }) {
    const operator = field(node, "operator");
    const operatorText = operator ? text(operator) : (text(node).match(/[!=]==?/) || [])[0];
    if (!operatorText || !["===", "!==", "==", "!="].includes(operatorText)) return;

    const left = field(node, "left");
    const right = field(node, "right");
    const sides = [text(left), text(right)];

    if (sides.some(side => SECRETISH.test(side))) {
        facts.operations.secretComparison = true;
        signal("secret_comparison", `${sides[0]} ${operatorText} ${sides[1]}`.slice(0, 80), node);
    }
}

// ---------------------------------------------------------------------------
// Derived verdicts
// ---------------------------------------------------------------------------

function dangerousOf(operations) {
    const dangerous = [];
    if (operations.dynamicEval) dangerous.push("eval");
    if (operations.childProcess) dangerous.push("child_process");
    if (operations.processSpawn) dangerous.push("process_spawn");
    if (operations.processExit) dangerous.push("process.exit");
    if (operations.diskDelete) dangerous.push("destructive_fs");
    return dangerous;
}

/**
 * Risk from syntax, not from substrings:
 *   critical  dynamic code execution or process spawning
 *   high      destructive filesystem operations
 *   medium    other filesystem writes, network I/O, crypto / secret handling
 *   low       pure computation or read-only
 */
function riskOf(facts) {
    const operations = facts?.operations || {};

    if (operations.dynamicEval || operations.processSpawn || operations.childProcess) return "critical";
    if (operations.diskDelete) return "high";
    if (operations.diskWrite) return "medium";
    if (operations.outboundHttp || operations.inboundHttp) return "medium";
    if (operations.cryptoUse || operations.secretComparison) return "medium";
    return "low";
}

module.exports = { extract, riskOf, dangerousOf, emptyFacts };
