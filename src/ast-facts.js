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

// Modules whose exports load or call native code: FFI, raw memory, .node addon loaders.
const NATIVE_MODULES = new Set([
    "ffi-napi", "@2060.io/ffi-napi", "ffi", "node-ffi", "koffi", "ref-napi", "ref",
    "bun:ffi", "bindings", "node-gyp-build"
]);

// process.dlopen loads a shared library; process.binding exposes Node internals
// (process.binding("spawn_sync") spawns without child_process).
const NATIVE_PROCESS_METHODS = new Set(["dlopen", "binding", "_linkedBinding"]);

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

// ---------------------------------------------------------------------------
// TypeScript
//
// The TypeScript grammars reuse the JavaScript node types and add type-only
// syntax. None of the node types below exist in the JavaScript grammar, so the
// helpers are no-ops for JavaScript input.
// ---------------------------------------------------------------------------

// `x as T`, `x satisfies T`, `x!`, `<T>x`: the runtime value is the inner expression.
const TS_WRAPPERS = new Set([
    "as_expression", "satisfies_expression", "non_null_expression", "type_assertion"
]);

// Subtrees that only describe types and never run.
const TYPE_ONLY_NODES = new Set([
    "type_annotation", "type_alias_declaration", "interface_declaration",
    "type_arguments", "type_parameters", "implements_clause", "ambient_declaration"
]);

function tsInner(node) {
    const children = node.namedChildren || [];
    return node.type === "type_assertion" ? children[children.length - 1] : children[0];
}

// Strips TypeScript wrappers, and parentheses that only hold one, from an
// expression: `(cp as any)` -> `cp`, `cp!` -> `cp`.
function unwrapTypeOnly(node) {
    let current = node;
    while (current) {
        if (TS_WRAPPERS.has(current.type)) {
            current = tsInner(current);
            continue;
        }
        if (current.type === "parenthesized_expression") {
            const children = current.namedChildren || [];
            if (children.length === 1 && TS_WRAPPERS.has(children[0].type)) {
                current = children[0];
                continue;
            }
        }
        return current;
    }
    return current;
}

function hasTypeWrapper(node) {
    let current = node;
    while (current) {
        if (unwrapTypeOnly(current) !== current) return true;
        if (current.type !== "member_expression" && current.type !== "subscript_expression") {
            return false;
        }
        current = field(current, "object");
    }
    return false;
}

// Source text of an expression without TypeScript wrappers in its object
// chain, so `(fs as any).promises` reads as `fs.promises`. Plain JavaScript is
// returned unchanged.
function exprText(node) {
    if (!hasTypeWrapper(node)) return text(node);
    const inner = unwrapTypeOnly(node);
    if (inner !== node) return exprText(inner);
    if (node.type === "member_expression") {
        return `${exprText(field(node, "object"))}.${text(field(node, "property"))}`;
    }
    const index = field(node, "index");
    return `${exprText(field(node, "object"))}[${text(index)}]`;
}

// `import type { X } from "m"`: erased at compile time, no runtime import.
function isTypeOnlyImport(node) {
    return (node.children || []).some(child => child.type === "type" && !child.isNamed);
}

// `import { type X } from "m"`: this one binding is erased.
function isTypeOnlySpecifier(node) {
    return (node.children || []).some(child => child.type === "type" && !child.isNamed);
}

// `import cp = require("child_process")`: a runtime require in TypeScript.
function importRequireClauseOf(node) {
    return (node.namedChildren || []).find(child => child.type === "import_require_clause") || null;
}

// Like walk(), but skips type-only syntax so `typeof import("fs")` in a type
// position is not read as a runtime import.
function walkRuntime(node, visit) {
    if (!node) return;
    visit(node);
    let children = node.namedChildren || node.children || [];
    if (node.type === "as_expression" || node.type === "satisfies_expression") {
        children = children.slice(0, 1);
    } else if (node.type === "type_assertion") {
        children = children.slice(-1);
    }
    for (const child of children) {
        if (!TYPE_ONLY_NODES.has(child.type)) walkRuntime(child, visit);
    }
}

// A call target split into `object.property`, e.g. fs.writeFileSync or
// crypto.createHmac. `object` is null for a bare identifier call like eval(x).
function callTarget(callNode) {
    const callee = unwrapTypeOnly(field(callNode, "function") || (callNode.namedChildren || [])[0]);
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
            object: object ? exprText(object).split("\n")[0] : null,
            property: property ? text(property) : null,
            raw: exprText(callee).split("\n")[0]
        };
    }

    if (callee.type === "subscript_expression") {
        const object = field(callee, "object");
        const index = field(callee, "index");
        return {
            object: object ? exprText(object).split("\n")[0] : null,
            property: stringLiteral(index),
            raw: exprText(callee).split("\n")[0]
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

    // TypeScript parameter: only its pattern declares a binding, not its type
    // or default value.
    if (node.type === "required_parameter" || node.type === "optional_parameter") {
        return bindingPatternHasName(field(node, "pattern"), name);
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
    const requireClause = importRequireClauseOf(statement);
    if (requireClause) {
        const local = (requireClause.namedChildren || []).find(child => child.type === "identifier");
        return Boolean(local && text(local) === name);
    }

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

            if (child.type === "class_declaration" ||
                child.type === "abstract_class_declaration" ||
                child.type === "enum_declaration") {
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


function isUnshadowedGlobalThis(node) {
    const callee = unwrapTypeOnly(node);
    if (!callee ||
        (callee.type !== "member_expression" &&
         callee.type !== "subscript_expression")) {
        return false;
    }

    const receiver = unwrapTypeOnly(field(callee, "object"));

    return receiver?.type === "identifier" &&
        text(receiver) === "globalThis" &&
        !isNameShadowed(receiver, "globalThis");
}




// Experimental V3: scope-aware alias tracking with control-flow joins.
// This remains a conservative approximation, not a complete JS interpreter.

const EVAL_ALIAS_LOOP_TYPES = new Set([
    "while_statement",
    "do_statement",
    "for_statement",
    "for_in_statement",
    "for_of_statement"
]);


function evalAliasSameNode(a, b) {
    return Boolean(
        a &&
        b &&
        a.type === b.type &&
        a.startIndex === b.startIndex &&
        a.endIndex === b.endIndex
    );
}

function evalAliasNodeIndex(nodes, target) {
    return (nodes || []).findIndex(
        candidate => evalAliasSameNode(candidate, target)
    );
}


function evalAliasIfParts(node) {
    const children = node.namedChildren || [];
    const alternative = field(node, "alternative") ||
        children.find(child => child.type === "else_clause") || null;
    const condition = field(node, "condition") ||
        children.find(child => child.type === "parenthesized_expression") ||
        null;
    const consequence = field(node, "consequence") ||
        children.find(child =>
            !evalAliasSameNode(child, alternative) &&
            !evalAliasSameNode(child, condition)
        ) || null;

    return { condition, consequence, alternative };
}
function evalAliasLoopBody(node) {
    const named = node.namedChildren || [];
    const body = field(node, "body");

    if (body) return body;
    if (node.type === "do_statement") return named[0] || null;

    return named[named.length - 1] || null;
}


function evalAliasLoopCondition(node) {
    const condition = field(node, "condition");
    if (condition) return condition;

    const body = evalAliasLoopBody(node);
    const children = node.namedChildren || [];

    return children.find(
        child => !evalAliasSameNode(child, body)
    ) || null;
}
function evalAliasTryParts(node) {
    const children = node.namedChildren || [];

    return {
        body: children.find(child => child.type === "statement_block") || null,
        catcher: children.find(child => child.type === "catch_clause") || null,
        finalizer: children.find(child => child.type === "finally_clause") || null
    };
}

function evalAliasFunctionPath(node) {
    const path = [];
    let current = node;

    while (current) {
        if (FUNCTION_SCOPE_TYPES.has(current.type)) {
            path.push(spawnScopeKey(current));
        }
        current = current.parent;
    }

    return path.reverse();
}

function evalAliasSameFunctionContext(a, b) {
    const left = evalAliasFunctionPath(a);
    const right = evalAliasFunctionPath(b);

    return left.length === right.length &&
        left.every((entry, index) => entry === right[index]);
}

function evalAliasExecutionPath(node) {
    const path = [];
    let child = node;
    let current = node;

    while (current) {
        if (FUNCTION_SCOPE_TYPES.has(current.type)) {
            path.push(`fn:${spawnScopeKey(current)}`);
        }

        const parent = current.parent;
        if (!parent) break;

        if (parent.type === "if_statement") {
            const parts = evalAliasIfParts(parent);

            if (
                parts.alternative &&
                child.startIndex >= parts.alternative.startIndex &&
                child.endIndex <= parts.alternative.endIndex
            ) {
                path.push(`if:${spawnScopeKey(parent)}:else`);
            } else if (
                parts.consequence &&
                child.startIndex >= parts.consequence.startIndex &&
                child.endIndex <= parts.consequence.endIndex
            ) {
                path.push(`if:${spawnScopeKey(parent)}:then`);
            }
        } else if (
            parent.type === "switch_body" &&
            (child.type === "switch_case" ||
             child.type === "switch_default")
        ) {
            path.push(
                `switch:${spawnScopeKey(parent)}:case:${child.startIndex}`
            );
        } else if (parent.type === "try_statement") {
            const branch =
                child.type === "catch_clause" ? "catch" :
                child.type === "finally_clause" ? "finally" : "try";

            path.push(`try:${spawnScopeKey(parent)}:${branch}`);
        } else if (EVAL_ALIAS_LOOP_TYPES.has(parent.type)) {
            const body = evalAliasLoopBody(parent);

            if (
                body &&
                child.startIndex >= body.startIndex &&
                child.endIndex <= body.endIndex
            ) {
                path.push(`loop:${spawnScopeKey(parent)}`);
            }
        }

        child = parent;
        current = parent;
    }

    return path.reverse();
}

function evalAliasPathIsVisible(eventPath, referencePath) {
    if (eventPath.length > referencePath.length) return false;

    return eventPath.every(
        (entry, index) => entry === referencePath[index]
    );
}

function evalAliasEnclosingSwitchCase(node) {
    let current = node;

    while (current) {
        if (
            current.type === "switch_case" ||
            current.type === "switch_default"
        ) {
            return current;
        }

        if (current.type === "switch_statement") return null;
        current = current.parent;
    }

    return null;
}


function evalAliasTopLevelChild(node, ancestor) {
    let current = node;

    while (
        current &&
        current.parent &&
        !evalAliasSameNode(current.parent, ancestor)
    ) {
        current = current.parent;
    }

    return current && evalAliasSameNode(current.parent, ancestor)
        ? current
        : null;
}
function evalAliasSwitchExitStatement(node) {
    return node && [
        "break_statement",
        "continue_statement",
        "return_statement",
        "throw_statement"
    ].includes(node.type);
}


function evalAliasSwitchFallthroughVisible(eventNode, reference) {
    if (
        !eventNode ||
        !reference ||
        !evalAliasSameFunctionContext(eventNode, reference)
    ) {
        return false;
    }

    const sourceCase = evalAliasEnclosingSwitchCase(eventNode);
    const targetCase = evalAliasEnclosingSwitchCase(reference);

    if (
        !sourceCase ||
        !targetCase ||
        evalAliasSameNode(sourceCase, targetCase)
    ) {
        return false;
    }

    const body = sourceCase.parent;

    if (
        !body ||
        !evalAliasSameNode(body, targetCase.parent) ||
        body.type !== "switch_body"
    ) {
        return false;
    }

    const cases = (body.namedChildren || []).filter(
        child =>
            child.type === "switch_case" ||
            child.type === "switch_default"
    );

    const sourceIndex = evalAliasNodeIndex(cases, sourceCase);
    const targetIndex = evalAliasNodeIndex(cases, targetCase);

    if (sourceIndex < 0 || targetIndex <= sourceIndex) return false;

    const sourceChildren = sourceCase.namedChildren || [];
    const sourceChild = evalAliasTopLevelChild(eventNode, sourceCase);
    const eventIndex = evalAliasNodeIndex(sourceChildren, sourceChild);

    if (eventIndex < 0) return false;

    for (let i = 0; i < eventIndex; i++) {
        if (evalAliasSwitchExitStatement(sourceChildren[i])) return false;
    }

    for (let i = eventIndex + 1; i < sourceChildren.length; i++) {
        if (evalAliasSwitchExitStatement(sourceChildren[i])) return false;
    }

    for (let i = sourceIndex + 1; i < targetIndex; i++) {
        if (
            (cases[i].namedChildren || []).some(
                evalAliasSwitchExitStatement
            )
        ) {
            return false;
        }
    }

    return true;
}
function evalAliasEnclosingTryStatement(node) {
    let current = node;

    while (current) {
        if (current.type === "try_statement") return current;
        current = current.parent;
    }

    return null;
}


function evalAliasTryCatchCanFlow(eventNode, reference) {
    if (
        !eventNode ||
        !reference ||
        !evalAliasSameFunctionContext(eventNode, reference)
    ) {
        return false;
    }

    const sourceTry = evalAliasEnclosingTryStatement(eventNode);
    const targetTry = evalAliasEnclosingTryStatement(reference);

    if (
        !sourceTry ||
        !targetTry ||
        !evalAliasSameNode(sourceTry, targetTry)
    ) {
        return false;
    }

    const parts = evalAliasTryParts(sourceTry);

    if (!parts.body || !parts.catcher) return false;

    if (
        eventNode.startIndex < parts.body.startIndex ||
        eventNode.endIndex > parts.body.endIndex ||
        reference.startIndex < parts.catcher.startIndex ||
        reference.endIndex > parts.catcher.endIndex
    ) {
        return false;
    }

    const statements = parts.body.namedChildren || [];
    const sourceStatement = evalAliasTopLevelChild(
        eventNode,
        parts.body
    );
    const sourceIndex = evalAliasNodeIndex(statements, sourceStatement);

    if (sourceIndex < 0) return false;

    for (let i = 0; i < sourceIndex; i++) {
        if (evalAliasSwitchExitStatement(statements[i])) return false;
    }

    for (let i = sourceIndex + 1; i < statements.length; i++) {
        const statement = statements[i];

        if (statement.type === "throw_statement") return true;

        if (
            statement.type === "return_statement" ||
            statement.type === "break_statement" ||
            statement.type === "continue_statement"
        ) {
            return false;
        }
    }

    return false;
}
function evalAliasEventVisible(event, reference, referencePath) {
    if (evalAliasPathIsVisible(event.contextPath, referencePath)) {
        return true;
    }

    if (!event.node) return false;

    if (evalAliasSwitchFallthroughVisible(event.node, reference)) {
        return true;
    }

    if (!evalAliasTryCatchCanFlow(event.node, reference)) {
        return false;
    }

    const tryNode = evalAliasEnclosingTryStatement(event.node);
    const tryKey = spawnScopeKey(tryNode);

    const eventPath = event.contextPath.filter(
        entry => entry !== `try:${tryKey}:try`
    );

    const catchPath = referencePath.filter(
        entry => entry !== `try:${tryKey}:catch`
    );

    return evalAliasPathIsVisible(eventPath, catchPath);
}


function evalAliasScopeKey(reference, name) {
    const scope = spawnNearestBindingScope(reference, name);
    return scope ? `${spawnScopeKey(scope)}:${name}` : "";
}

function evalAliasStateAtOffset(aliases, key, offset, reference) {
    if (!key || !reference) return false;

    const events = aliases.get(key) || [];
    const referencePath = evalAliasExecutionPath(reference);
    let state = false;

    for (const event of events) {
        if (event.offset >= offset) break;

        if (evalAliasEventVisible(event, reference, referencePath)) {
            state = event.isAlias;
        }
    }

    return state;
}

function evalAliasStateAt(aliases, key, reference) {
    return reference
        ? evalAliasStateAtOffset(
            aliases, key, reference.startIndex, reference
        )
        : false;
}

function evalAliasValue(node, aliases) {
    let current = unwrapTypeOnly(node);

    while (current && current.type === "parenthesized_expression") {
        current = unwrapTypeOnly((current.namedChildren || [])[0]);
    }

    if (!current) return false;

    if (current.type === "identifier") {
        const name = text(current);

        if (name === "eval") {
            return !isNameShadowed(current, "eval");
        }

        const key = evalAliasScopeKey(current, name);
        return evalAliasStateAt(aliases, key, current);
    }

    if (current.type === "member_expression") {
        return text(field(current, "property")) === "eval" &&
            isUnshadowedGlobalThis(current);
    }

    return false;
}

function evalAliasFunctionBinding(node) {
    let nameNode = null;
    let scope = null;

    if (
        node.type === "function_declaration" ||
        node.type === "generator_function_declaration"
    ) {
        nameNode = field(node, "name");

        if (!nameNode || nameNode.type !== "identifier") return null;

        scope = spawnNearestBindingScope(node.parent, text(nameNode));
    } else {
        const parent = node.parent;

        if (
            parent?.type === "variable_declarator" &&
            field(parent, "value")?.startIndex === node.startIndex
        ) {
            nameNode = field(parent, "name");
        } else if (
            parent?.type === "assignment_expression" &&
            field(parent, "right")?.startIndex === node.startIndex
        ) {
            nameNode = unwrapTypeOnly(field(parent, "left"));
        } else {
            return null;
        }

        if (!nameNode || nameNode.type !== "identifier") return null;

        scope = spawnNearestBindingScope(nameNode, text(nameNode));
    }

    if (!scope || !nameNode) return null;

    return {
        bindingKey: `${spawnScopeKey(scope)}:${text(nameNode)}`,
        functionKey: spawnScopeKey(node)
    };
}

function evalAliasEnclosingFunction(node) {
    let current = node;

    while (current) {
        if (FUNCTION_SCOPE_TYPES.has(current.type)) return current;
        current = current.parent;
    }

    return null;
}

function evalAliasScopeIsInsideFunction(scope, fn) {
    if (!scope || !fn) return false;

    return scope.startIndex >= fn.startIndex &&
        scope.endIndex <= fn.endIndex;
}

function isEvalAliasReference(reference, context, callNode) {
    if (!reference || reference.type !== "identifier") return false;

    const name = text(reference);
    const key = evalAliasScopeKey(reference, name);
    const bindingScope = spawnNearestBindingScope(reference, name);
    const enclosingFunction = evalAliasEnclosingFunction(callNode);

    if (
        bindingScope &&
        enclosingFunction &&
        !evalAliasScopeIsInsideFunction(bindingScope, enclosingFunction)
    ) {
        const functionKey = spawnScopeKey(enclosingFunction);
        const sites = context.invocationSites.get(functionKey) || [];

        if (sites.length) {
            return sites.some(
                site => evalAliasStateAt(context.aliases, key, site)
            );
        }

        return (context.aliases.get(key) || []).some(
            event => event.isAlias
        );
    }

    return evalAliasStateAt(context.aliases, key, reference);
}

function evalAliasAppendEvent(aliases, key, event) {
    let events = aliases.get(key);

    if (!events) {
        events = [];
        aliases.set(key, events);
    }

    events.push(event);
}

function evalAliasControlKeys(task, writes) {
    const node = task.node;

    return [...new Set(
        writes
            .filter(write =>
                write.node.startIndex >= node.startIndex &&
                write.node.endIndex <= node.endIndex &&
                evalAliasSameFunctionContext(write.node, node) &&
                (
                    task.kind !== "try-enter" ||
                    write.offset < task.offset
                )
            )
            .map(write => write.key)
    )];
}

function evalAliasControlResult(task, key, aliases) {
    const node = task.node;
    const incoming = evalAliasStateAtOffset(
        aliases, key, node.startIndex, node
    );

    if (task.kind === "if") {
        const parts = evalAliasIfParts(node);

        const conditionState = parts.condition
            ? evalAliasStateAtOffset(
                aliases,
                key,
                parts.condition.endIndex + 1,
                parts.condition
            )
            : incoming;

        const thenState = parts.consequence
            ? evalAliasStateAtOffset(
                aliases, key, parts.consequence.endIndex, parts.consequence
            )
            : conditionState;

        const elseState = parts.alternative
            ? evalAliasStateAtOffset(
                aliases, key, parts.alternative.endIndex, parts.alternative
            )
            : conditionState;

        return thenState || elseState;
    }

    if (task.kind === "loop") {
        const body = evalAliasLoopBody(node);
        const condition = evalAliasLoopCondition(node);

        const conditionState = condition
            ? evalAliasStateAtOffset(
                aliases, key, condition.endIndex + 1, condition
            )
            : incoming;

        const bodyState = body
            ? evalAliasStateAtOffset(aliases, key, body.endIndex, body)
            : incoming;

        if (node.type === "do_statement") return bodyState;

        // A while/for loop may execute zero times.
        return conditionState || bodyState;
    }

    if (task.kind === "switch") {
        const body = (node.namedChildren || []).find(
            child => child.type === "switch_body"
        );

        if (!body) return incoming;

        const children = node.namedChildren || [];
        const discriminant = children.find(child => !evalAliasSameNode(child, body));
        const baseline = discriminant
            ? evalAliasStateAtOffset(
                aliases, key, discriminant.endIndex + 1, discriminant
            )
            : incoming;

        const branches = (body.namedChildren || []).filter(
            child =>
                child.type === "switch_case" ||
                child.type === "switch_default"
        );

        if (!branches.length) return baseline;

        const hasDefault = branches.some(
            child => child.type === "switch_default"
        );

        const possibleStates = branches.map(
            branch => evalAliasStateAtOffset(
                aliases, key, branch.endIndex, branch
            )
        );

        if (!hasDefault) possibleStates.push(baseline);

        return possibleStates.some(Boolean);
    }

    if (
        task.kind === "try-join" ||
        task.kind === "try-enter"
    ) {
        const parts = evalAliasTryParts(node);
        const tryState = parts.body
            ? evalAliasStateAtOffset(
                aliases, key, parts.body.endIndex, parts.body
            )
            : incoming;

        const catchState = parts.catcher
            ? evalAliasStateAtOffset(
                aliases, key, parts.catcher.endIndex, parts.catcher
            )
            : false;

        return parts.catcher ? tryState || catchState : tryState;
    }

    if (task.kind === "try-exit") {
        const parts = evalAliasTryParts(node);

        return parts.finalizer
            ? evalAliasStateAtOffset(
                aliases,
                key,
                parts.finalizer.endIndex,
                parts.finalizer
            )
            : incoming;
    }

    return incoming;
}

function evalAliasBindingsOf(root) {
    const writes = [];
    const controls = [];

    walkRuntime(root, node => {
        let target = null;
        let value = null;
        const offset = node.endIndex;

        if (node.type === "variable_declarator") {
            target = unwrapTypeOnly(field(node, "name"));
            value = field(node, "value");

            if (!value) return;
        } else if (node.type === "assignment_expression") {
            target = unwrapTypeOnly(field(node, "left"));
            const right = field(node, "right");

            if (!right) return;

            const leftEnd = target
                ? target.endIndex - node.startIndex
                : -1;
            const rightStart = right.startIndex - node.startIndex;
            const operator = target
                ? text(node).slice(leftEnd, rightStart).trim()
                : "";

            value = operator === "=" ? right : null;
        } else if (node.type === "update_expression") {
            target = (node.namedChildren || []).find(
                child => child.type === "identifier"
            ) || null;

            value = null;
        } else {
            return;
        }

        if (!target || target.type !== "identifier") return;

        const name = text(target);
        const scope = spawnNearestBindingScope(target, name);
        if (!scope) return;

        writes.push({
            key: `${spawnScopeKey(scope)}:${name}`,
            value,
            offset,
            start: node.startIndex,
            node,
            contextPath: evalAliasExecutionPath(node)
        });
    });

    walkRuntime(root, node => {
        if (node.type === "if_statement") {
            controls.push({
                kind: "if", node, offset: node.endIndex
            });
        } else if (EVAL_ALIAS_LOOP_TYPES.has(node.type)) {
            controls.push({
                kind: "loop", node, offset: node.endIndex
            });
        } else if (node.type === "switch_statement") {
            controls.push({
                kind: "switch", node, offset: node.endIndex
            });
        } else if (node.type === "try_statement") {
            const parts = evalAliasTryParts(node);

            if (parts.finalizer) {
                controls.push({
                    kind: "try-enter",
                    node,
                    offset: parts.finalizer.startIndex
                });
                controls.push({
                    kind: "try-exit",
                    node,
                    offset: node.endIndex
                });
            } else {
                controls.push({
                    kind: "try-join",
                    node,
                    offset: node.endIndex
                });
            }
        }
    });

    const tasks = [
        ...writes.map(write => ({
            kind: "write",
            node: write.node,
            offset: write.offset,
            start: write.start,
            write
        })),
        ...controls
    ];

    tasks.sort((a, b) =>
        a.offset - b.offset ||
        (a.kind === "write" ? -1 : b.kind === "write" ? 1 : 0) ||
        ((a.node.endIndex - a.node.startIndex) -
         (b.node.endIndex - b.node.startIndex))
    );

    const aliases = new Map();

    for (const task of tasks) {
        if (task.kind === "write") {
            const write = task.write;
            const isAlias = write.value
                ? evalAliasValue(write.value, aliases)
                : false;

            evalAliasAppendEvent(aliases, write.key, {
                offset: write.offset,
                isAlias,
                contextPath: write.contextPath,
                node: write.node
            });

            continue;
        }

        const contextPath = evalAliasExecutionPath(task.node);

        for (const key of evalAliasControlKeys(task, writes)) {
            const isAlias = evalAliasControlResult(task, key, aliases);

            evalAliasAppendEvent(aliases, key, {
                offset: task.offset,
                isAlias,
                contextPath,
                node: task.node
            });
        }
    }

    const functionsByBinding = new Map();

    walkRuntime(root, node => {
        if (!FUNCTION_SCOPE_TYPES.has(node.type)) return;

        const info = evalAliasFunctionBinding(node);
        if (!info) return;

        const entries = functionsByBinding.get(info.bindingKey) || [];

        if (!entries.includes(info.functionKey)) {
            entries.push(info.functionKey);
        }

        functionsByBinding.set(info.bindingKey, entries);
    });

    const invocationSites = new Map();

    walkRuntime(root, node => {
        if (node.type !== "call_expression") return;

        const callee = unwrapTypeOnly(
            field(node, "function") || (node.namedChildren || [])[0]
        );

        if (callee?.type !== "identifier") return;

        const bindingKey = evalAliasScopeKey(callee, text(callee));
        const functionKeys = functionsByBinding.get(bindingKey) || [];

        for (const functionKey of functionKeys) {
            const sites = invocationSites.get(functionKey) || [];
            sites.push(node);
            invocationSites.set(functionKey, sites);
        }
    });

    return { aliases, invocationSites };
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
            secretComparison: false,
            unsafeDeserialization: false,
            nativeCode: false
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

function extract(content, language = "javascript") {
    const facts = emptyFacts();
    const ast = TreeParser.parse(String(content || ""), language);

    // A partial parse would report proven absences that are really parser gaps,
    // so anything with an ERROR node is handed back to the text fallback.
    if (!ast.ok || !ast.root || hasParseError(ast)) {
        facts.error = ast.error || "source did not parse cleanly";
        return facts;
    }

    facts.ast = true;

    const spawnBindings = spawnBindingsOf(ast.root);
    const nativeBindings = nativeBindingsOf(ast.root);
    const evalAliases = evalAliasBindingsOf(ast.root);
    const routes = new Set();
    const exportsFound = new Set();
    const imports = new Set();
    const env = new Set();
    const calls = { network: new Set(), filesystem: new Set(), process: new Set(), crypto: new Set(), dynamic: new Set() };
    const signals = [];

    const signal = (name, evidence, node) => {
        signals.push({ signal: name, evidence, line: line(node) });
    };

    walkRuntime(ast.root, node => {
        switch (node.type) {
            case "call_expression":
                visitCall(node, { facts, routes, imports, calls, signal, spawnBindings, evalAliases, nativeBindings });
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
                visitSubscript(node, { env, signal });
                break;
            case "assignment_expression":
                visitAssignment(node, { exportsFound });
                break;
            case "export_statement":
                visitExport(node, { exportsFound });
                break;
            case "import_statement": {
                if (isTypeOnlyImport(node)) break;
                const requireClause = importRequireClauseOf(node);
                const source = stringLiteral(field(requireClause || node, "source"));
                if (source) {
                    imports.add(source);
                    if (CHILD_PROCESS_MODULES.has(source)) {
                        const evidence = requireClause ? "require(child_process)" : "import(child_process)";
                        facts.operations.childProcess = true;
                        calls.process.add(evidence);
                        signal("child_process_import", evidence, node);
                    }
                    if (isNativeAddonPath(source)) {
                        markNative(facts, calls, signal, `${requireClause ? "require" : "import"}(*.node)`, node);
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
function spawnRootIdentifierNode(node) {
    let current = unwrapTypeOnly(node);
    while (current &&
        (current.type === "member_expression" ||
         current.type === "subscript_expression")) {
        current = unwrapTypeOnly(field(current, "object"));
    }
    return current?.type === "identifier" ? current : null;
}

function spawnScopeKey(scope) {
    if (!scope) return "";
    return `${scope.type}:${scope.startIndex}:${scope.endIndex}`;
}

function spawnScopeDeclaresBinding(scope, name) {
    if (FUNCTION_SCOPE_TYPES.has(scope.type)) {
        return functionScopeHasBinding(scope, name);
    }

    if (scope.type === "program") {
        return lexicalScopeHasBinding(scope, name) ||
            varScopeHasBinding(scope, name);
    }

    if (LEXICAL_SCOPE_TYPES.has(scope.type)) {
        return lexicalScopeHasBinding(scope, name);
    }

    return false;
}

function spawnNearestBindingScope(reference, name) {
    let current = reference;

    while (current) {
        if (
            (FUNCTION_SCOPE_TYPES.has(current.type) ||
             LEXICAL_SCOPE_TYPES.has(current.type) ||
             current.type === "program") &&
            spawnScopeDeclaresBinding(current, name)
        ) {
            return current;
        }

        current = current.parent;
    }

    return null;
}

function spawnResolvesBinding(reference, name, kind, bindings) {
    const scope = spawnNearestBindingScope(reference, name);
    if (!scope) return false;

    const scoped = kind === "modules"
        ? bindings.moduleScopes
        : bindings.functionScopes;

    return Boolean(scoped.get(spawnScopeKey(scope))?.has(name));
}

function spawnBindingsOf(root) {
    const modules = new Set();
    const functions = new Set();
    const moduleScopes = new Map();
    const functionScopes = new Map();

    const addScoped = (map, scope, name) => {
        if (!scope || !name) return false;

        let names = map.get(spawnScopeKey(scope));
        if (!names) {
            names = new Set();
            map.set(spawnScopeKey(scope), names);
        }

        const existed = names.has(name);
        names.add(name);
        return !existed;
    };

    function declarationScopeOf(declarator) {
        const isVar = declarator.parent?.type === "variable_declaration";
        let current = declarator.parent?.parent;

        while (current) {
            if (current.type === "program") return current;

            if (isVar
                ? FUNCTION_SCOPE_TYPES.has(current.type)
                : LEXICAL_SCOPE_TYPES.has(current.type)) {
                return current;
            }

            current = current.parent;
        }

        return root;
    }

    function importScopeOf(node) {
        let current = node.parent;

        while (current) {
            if (current.type === "program") return current;
            if (LEXICAL_SCOPE_TYPES.has(current.type)) return current;
            current = current.parent;
        }

        return root;
    }

    const bindNames = (target, source, scope) => {
        if (!target || !SPAWN_MODULES.has(source)) return;

        if (target.type === "identifier") {
            const name = text(target);
            modules.add(name);
            addScoped(moduleScopes, scope, name);
            return;
        }

        walk(target, node => {
            if (node.type === "shorthand_property_identifier_pattern") {
                const name = text(node);
                functions.add(name);
                addScoped(functionScopes, scope, name);
            }

            if (node.type === "pair_pattern") {
                const children = node.namedChildren || [];
                const value = children[children.length - 1];

                if (value?.type === "identifier") {
                    const name = text(value);
                    functions.add(name);
                    addScoped(functionScopes, scope, name);
                }
            }
        });
    };

    // First pass: preserve existing require/import/destructuring support.
    walk(root, node => {
        if (node.type === "variable_declarator") {
            let value = unwrapTypeOnly(field(node, "value"));

            if (value?.type === "await_expression") {
                value = unwrapTypeOnly(field(value, "argument") ||
                    (value.namedChildren || [])[0]);
            }

            if (value?.type === "call_expression") {
                const { object, property } = callTarget(value);

                if (!object &&
                    (property === "require" || property === "import")) {
                    bindNames(
                        field(node, "name"),
                        stringLiteral(args(value)[0]),
                        declarationScopeOf(node)
                    );
                }
            }

            return;
        }

        if (node.type === "import_statement") {
            if (isTypeOnlyImport(node)) return;

            const requireClause = importRequireClauseOf(node);
            const source = stringLiteral(field(requireClause || node, "source"));
            if (!source || !SPAWN_MODULES.has(source)) return;

            const scope = importScopeOf(node);

            if (requireClause) {
                const local = (requireClause.namedChildren || []).find(child => child.type === "identifier");
                if (local) {
                    modules.add(text(local));
                    addScoped(moduleScopes, scope, text(local));
                }
                return;
            }

            walk(node, child => {
                if (child.type === "import_specifier") {
                    if (isTypeOnlySpecifier(child)) return;
                    const local = field(child, "alias") ||
                        field(child, "name");

                    if (local) {
                        const name = text(local);
                        functions.add(name);
                        addScoped(functionScopes, scope, name);
                    }
                } else if (
                    child.type === "namespace_import" ||
                    child.type === "import_clause"
                ) {
                    const local = field(child, "name") ||
                        (child.namedChildren || [])[0];

                    if (local?.type === "identifier") {
                        const name = text(local);
                        modules.add(name);
                        addScoped(moduleScopes, scope, name);
                    }
                }
            });
        }
    });

    const declarators = [];
    walk(root, node => {
        if (node.type === "variable_declarator") {
            declarators.push(node);
        }
    });

    // Repeated passes support simple chains such as run2 = run.
    let changed = true;
    let pass = 0;

    while (changed && pass <= declarators.length) {
        changed = false;
        pass++;

        for (const node of declarators) {
            const target = field(node, "name");
            if (target?.type !== "identifier") continue;

            let value = unwrapTypeOnly(field(node, "value"));

            if (value?.type === "await_expression") {
                value = unwrapTypeOnly(field(value, "argument") ||
                    (value.namedChildren || [])[0]);
            }

            if (!value) continue;

            const name = text(target);
            const scope = declarationScopeOf(node);

            if (
                value.type === "member_expression" ||
                value.type === "subscript_expression"
            ) {
                const receiver = spawnRootIdentifierNode(
                    field(value, "object")
                );

                const propertyNode = value.type === "member_expression"
                    ? field(value, "property")
                    : field(value, "index");

                const property = propertyNode?.type === "string"
                    ? stringLiteral(propertyNode)
                    : propertyNode?.type === "template_string"
                        ? stringLiteral(propertyNode)
                        : propertyNode ? text(propertyNode) : null;

                if (
                    receiver &&
                    SPAWN_FUNCTIONS.has(property) &&
                    spawnResolvesBinding(
                        receiver, text(receiver), "modules",
                        { moduleScopes, functionScopes }
                    )
                ) {
                    functions.add(name);

                    if (addScoped(functionScopes, scope, name)) {
                        changed = true;
                    }
                }
            } else if (value.type === "identifier") {
                const sourceName = text(value);
                const bindings = { moduleScopes, functionScopes };

                if (spawnResolvesBinding(
                    value, sourceName, "modules", bindings
                )) {
                    modules.add(name);

                    if (addScoped(moduleScopes, scope, name)) {
                        changed = true;
                    }
                } else if (spawnResolvesBinding(
                    value, sourceName, "functions", bindings
                )) {
                    functions.add(name);

                    if (addScoped(functionScopes, scope, name)) {
                        changed = true;
                    }
                }
            }
        }
    }

    return { modules, functions, moduleScopes, functionScopes };
}

function isSpawnCall({ object, property, raw, callee }, host, spawnBindings) {
    if (!property) return false;

    const receiver = object ? field(callee, "object") : null;
    const root = spawnRootIdentifierNode(receiver);
    const rootName = root ? text(root) : null;

    // A recognized module alias remains a spawning capability.
    if (object && root && spawnResolvesBinding(
        root, rootName, "modules", spawnBindings
    )) {
        return true;
    }

    // A known function alias must resolve to the trusted binding in scope.
    if (!object && spawnResolvesBinding(
        callee, property, "functions", spawnBindings
    )) {
        return true;
    }

    if (!SPAWN_FUNCTIONS.has(property)) return false;

    if (object) {
        // Preserve the existing inline require("child_process") case.
        if (/child_process/.test(raw)) return true;

        // A locally declared receiver shadows the conventional module name.
        if (root && spawnNearestBindingScope(root, rootName)) return false;

        return !SPAWN_ONLY_WHEN_BOUND.has(property) &&
            /^(child_?process|cp)$/i.test(host);
    }

    return !SPAWN_ONLY_WHEN_BOUND.has(property);
}
function visitCall(node, { facts, routes, imports, calls, signal, spawnBindings, evalAliases, nativeBindings }) {
    const callee = unwrapTypeOnly(field(node, "function") || (node.namedChildren || [])[0]);
    const { object, property, raw } = callTarget(node);
    const sequence = callee?.type === "parenthesized_expression"
        ? (callee.namedChildren || []).find(child => child.type === "sequence_expression")
        : null;
    const expressions = sequence?.namedChildren || [];
    const indirectEvalName = expressions[expressions.length - 1];
    const indirectGlobalEval =
        indirectEvalName?.type === "identifier" &&
        text(indirectEvalName) === "eval" &&
        !isNameShadowed(indirectEvalName, "eval");
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
            if (isNativeAddonPath(source)) {
                markNative(facts, calls, signal, `${property}(*.node)`, node);
            }
        }
        return;
    }

    // Native code: process.dlopen(...), Deno.dlopen(...), koffi.load(...),
    // ffi.Library(...), dlopen from "bun:ffi", require("bindings")("addon")
    const nativeEvidence = nativeCallEvidence({ object, property, callee, host }, nativeBindings);
    if (nativeEvidence) {
        markNative(facts, calls, signal, nativeEvidence, node);
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
    if (isSpawnCall({ object, property, raw, callee }, host, spawnBindings)) {
        facts.operations.processSpawn = true;
        calls.process.add(object ? `${object}.${property}` : String(property));
        signal("process_spawn", object ? `${object}.${property}` : String(property), node);
        return;
    }

    // Dynamic code execution. Do not flag arbitrary object methods named eval.
    if (
        indirectGlobalEval ||
        isEvalAliasReference(callee, evalAliases, node) ||
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

function visitSubscript(node, { env, signal }) {
    // process.env["NAME"]
    const object = field(node, "object");
    const index = field(node, "index");
    if (object && text(object) === "process.env") {
        const name = stringLiteral(index);
        if (name) {
            env.add(name);
            if (SECRETISH.test(name)) {
                signal("secret_access", `process.env.${name}`, node);
            }
        }
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

    // TypeScript `export = name`, the counterpart of `module.exports = name`.
    if (node.children?.some(child => child.type === "=" && !child.isNamed)) {
        const value = (node.namedChildren || [])[0];
        exportsFound.add(value?.type === "identifier" ? text(value) : "default");
        return;
    }

    let declaration = field(node, "declaration");
    // `export declare const x: T`
    if (declaration?.type === "ambient_declaration") {
        declaration = (declaration.namedChildren || [])[0] || null;
    }
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
// Native code
// ---------------------------------------------------------------------------

function isNativeAddonPath(source) {
    return typeof source === "string" && /\.node$/.test(source);
}

function markNative(facts, calls, signal, evidence, node) {
    facts.operations.nativeCode = true;
    calls.dynamic.add(evidence);
    signal("native_code", evidence, node);
}

// Local names bound to a NATIVE_MODULES import, mapped to "module" or
// "module.export". Not scope-aware: a later shadowing binding is still counted.
function nativeBindingsOf(root) {
    const names = new Map();
    const bind = (target, source) => {
        if (!target || !NATIVE_MODULES.has(source)) return;
        if (target.type === "identifier") {
            names.set(text(target), source);
            return;
        }
        walk(target, node => {
            if (node.type === "shorthand_property_identifier_pattern") {
                names.set(text(node), `${source}.${text(node)}`);
            } else if (node.type === "pair_pattern") {
                const key = field(node, "key");
                const value = field(node, "value");
                if (value?.type === "identifier") names.set(text(value), `${source}.${text(key)}`);
            }
        });
    };
    walk(root, node => {
        if (node.type === "variable_declarator") {
            let value = unwrapTypeOnly(field(node, "value"));
            if (value?.type === "await_expression") {
                value = unwrapTypeOnly(field(value, "argument") || (value.namedChildren || [])[0]);
            }
            if (value?.type === "call_expression") {
                const { object, property } = callTarget(value);
                if (!object && (property === "require" || property === "import")) {
                    bind(field(node, "name"), stringLiteral(args(value)[0]));
                }
            }
        } else if (node.type === "import_statement" && !isTypeOnlyImport(node)) {
            const requireClause = importRequireClauseOf(node);
            const source = stringLiteral(field(requireClause || node, "source"));
            if (!NATIVE_MODULES.has(source)) return;
            if (requireClause) {
                bind((requireClause.namedChildren || []).find(child => child.type === "identifier"), source);
                return;
            }
            walk(node, child => {
                if (child.type === "import_specifier") {
                    const name = field(child, "name");
                    const alias = field(child, "alias") || name;
                    if (name && alias) names.set(text(alias), `${source}.${text(name)}`);
                } else if (child.type === "namespace_import") {
                    const id = (child.namedChildren || []).find(c => c.type === "identifier");
                    if (id) names.set(text(id), source);
                } else if (child.type === "import_clause") {
                    const id = (child.namedChildren || []).find(c => c.type === "identifier");
                    if (id) names.set(text(id), source);
                }
            });
        }
    });
    return names;
}

function nativeCallEvidence({ object, property, callee, host }, nativeBindings) {
    if (object === "process" && NATIVE_PROCESS_METHODS.has(property)) return `process.${property}`;
    if (object === "Deno" && property === "dlopen") return "Deno.dlopen";
    if (object && host && nativeBindings.has(host)) return `${nativeBindings.get(host)}.${property}`;
    if (!object && property && nativeBindings.has(property)) return nativeBindings.get(property);
    // require("bindings")("addon") / require("koffi").load(...)
    let inner = callee;
    while (inner?.type === "member_expression") inner = field(inner, "object");
    if (inner?.type === "call_expression") {
        const target = callTarget(inner);
        const source = stringLiteral(args(inner)[0]);
        if (!target.object && (target.property === "require" || target.property === "import") &&
            NATIVE_MODULES.has(source)) {
            return property && callee?.type === "member_expression" ? `${source}.${property}` : source;
        }
    }
    return null;
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
    if (operations.unsafeDeserialization) dangerous.push("unsafe_deserialization");
    if (operations.nativeCode) dangerous.push("native_code");
    return dangerous;
}

/**
 * Risk from syntax, not from substrings:
 *   critical  dynamic code execution, process spawning, unsafe deserialization
 *             or native code (FFI, native addons, raw memory)
 *   high      destructive filesystem operations
 *   medium    other filesystem writes, network I/O, crypto / secret handling
 *   low       pure computation or read-only
 */
function riskOf(facts) {
    const operations = facts?.operations || {};

    if (operations.dynamicEval || operations.processSpawn || operations.childProcess ||
        operations.unsafeDeserialization || operations.nativeCode) return "critical";
    if (operations.diskDelete) return "high";
    if (operations.diskWrite) return "medium";
    if (operations.outboundHttp || operations.inboundHttp) return "medium";
    if (operations.cryptoUse || operations.secretComparison) return "medium";
    return "low";
}

module.exports = { extract, riskOf, dangerousOf, emptyFacts };
