/**
 * sentinel-ir
 *
 * Convert JavaScript source into a compact, structural intermediate
 * representation (IR) meant to be read by an LLM instead of the raw file.
 *
 * JavaScript
 *      ↓
 * TreeParser (tree-sitter)
 *      ↓
 * AstFacts   (routes / exports / imports / env / calls / risk)
 *      ↓
 * analyze()  -> full IR
 *      ↓
 * compress() -> { mission, world, constraints, forbidden, summary, facts }
 *
 * Facts vs. guesses:
 * The structural part of the IR (routes, exports, imports, env reads, real
 * network/filesystem/process calls, risk) comes from the tree-sitter AST via
 * ./ast-facts.js. The substring heuristics below are only the FALLBACK for
 * source that fails to parse — they read an Express server as network-free and
 * a function called `evaluate` as `eval`, which is why they never decide
 * anything when the AST is available.
 *
 * World signals (pressure, confidence, budget, consecutiveFailures) are
 * caller-supplied options. The library keeps no state between calls.
 */

const AstFacts = require("./ast-facts");
const TreeParser = require("./tree-parser");
const PythonFacts = require("./python-facts");
const RustFacts = require("./rust-facts");

const LANGUAGES = Object.freeze(["javascript", "typescript", "tsx", "python", "rust"]);

const LANGUAGE_ALIASES = Object.freeze({
    javascript: "javascript",
    js: "javascript",
    typescript: "typescript",
    ts: "typescript",
    tsx: "tsx",
    python: "python",
    py: "python",
    rust: "rust",
    rs: "rust"
});

// File extensions that select a grammar when no `language` option is given.
// Anything else (including no target) is analyzed as JavaScript, as before.
const EXTENSION_LANGUAGES = Object.freeze({
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
    ".py": "python",
    ".pyi": "python",
    ".rs": "rust"
});

// Explicit `language` wins; otherwise the target's extension decides. An
// unknown explicit language is kept as given so the IR can say what it could
// not analyze instead of parsing it with the wrong grammar.
function resolveLanguage(language, target) {
    if (typeof language === "string" && language.trim() !== "") {
        const id = language.trim().toLowerCase();
        return { language: LANGUAGE_ALIASES[id] || id, supported: Object.hasOwn(LANGUAGE_ALIASES, id) };
    }

    const match = /\.[^./\\]+$/.exec(String(target || "").toLowerCase());
    const inferred = match && EXTENSION_LANGUAGES[match[0]];
    return { language: inferred || "javascript", supported: true };
}

const DEFAULTS = Object.freeze({
    pressure: 0.5,
    confidence: 0.75,
    budget: 0.015,
    consecutiveFailures: 0
});

// Only a finite number inside the range is a value; anything else ("abc", {},
// NaN, ±Infinity, out of range) falls back to the default instead of being
// clamped.
function numberOr(value, fallback, min, max) {
    return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max
        ? value
        : fallback;
}

function readOptions(options = {}) {
    const opts = options && typeof options === "object" ? options : {};
    const target = typeof opts.target === "string" ? opts.target : null;
    return {
        target,
        ...resolveLanguage(opts.language, target),
        pressure: numberOr(opts.pressure, DEFAULTS.pressure, 0, 1),
        confidence: numberOr(opts.confidence, DEFAULTS.confidence, 0, 1),
        budget: numberOr(opts.budget, DEFAULTS.budget, 0, Infinity),
        consecutiveFailures: numberOr(opts.consecutiveFailures, DEFAULTS.consecutiveFailures, 0, Infinity)
    };
}

function inferObjective(content, consecutiveFailures, facts = null) {
    if (facts?.ast) {
        const operations = facts.operations || {};
        if (operations.cryptoUse || operations.secretComparison) return "security_refactor";
        if (operations.diskWrite || operations.diskDelete || operations.diskRead) return "filesystem_simplification";
        if (operations.outboundHttp || operations.inboundHttp) return "network_stability";
        if (consecutiveFailures > 0) return "stability_repair";
        return "general_optimization";
    }

    const lower = String(content || "").toLowerCase();

    if (lower.includes("crypto") || lower.includes("hash") || lower.includes("cipher")) {
        return "security_refactor";
    }

    if (lower.includes("fs.") || lower.includes("writefile") || lower.includes("unlink")) {
        return "filesystem_simplification";
    }

    if (lower.includes("fetch") || lower.includes("axios") || lower.includes("http")) {
        return "network_stability";
    }

    if (consecutiveFailures > 0) {
        return "stability_repair";
    }

    return "general_optimization";
}

function inferConstraints(filePath, consecutiveFailures) {
    const constraints = ["preserve_api", "avoid_breaking_changes"];

    if (String(filePath || "").includes("crypto")) {
        constraints.push("preserve_security");
    }

    if (consecutiveFailures > 2) {
        constraints.push("minimize_scope");
    }

    return [...new Set(constraints)];
}

function inferRisk(filePath, content = "", facts = null) {
    const lower = String(content || "").toLowerCase();
    const path = String(filePath || "").toLowerCase();

    if (facts?.ast) {
        const risk = RustFacts.compileTimeRisk(facts, AstFacts.riskOf(facts));
        // A file that lives on the security path is never below medium, even
        // when its syntax looks harmless.
        if (risk === "low" && path.includes("crypto")) return "medium";
        return risk;
    }

    if (
        lower.includes("eval") ||
        lower.includes("process.exit") ||
        lower.includes("exec(") ||
        lower.includes("spawn(") ||
        NATIVE_TEXT.test(lower)
    ) {
        return "critical";
    }

    if (path.includes("crypto") || lower.includes("pbkdf2") || lower.includes("cipher")) {
        return "medium";
    }

    if (FS_WRITE_TEXT.test(lower)) {
        return "high";
    }

    if (NET_TEXT.test(lower)) {
        return "medium";
    }

    return "low";
}

// Text fallback for filesystem writes and deletes (lower-cased source).
const FS_WRITE_TEXT = /writefile|unlink|appendfile|createwritestream|copyfile|outputfile|outputjson|writejson|emptydir|\b(rmsync|rmdir|rmdirsync|truncatesync|renamesync|symlinksync|removesync)\b|\bfs\w*(\s*\.\s*promises)?\s*\.\s*(rm|rename|truncate|remove|move|copy)\s*\(/;

// Text fallback for outbound HTTP (lower-cased source): fetch/axios anywhere, or
// an HTTP module being loaded.
const NET_TEXT = /fetch|axios|(\brequire\s*\(\s*|\bfrom\s+|\bimport\s*\(\s*)["'`](node:)?(https?|http2|got|superagent|request|undici|ky|needle)["'`]/;

// Text-fallback counterpart of the native_code fact (lower-cased source).
// Unparseable code: any trace of a native loader or FFI module counts, since an
// incomplete parse is no proof that the import is unused.
const NATIVE_TEXT = new RegExp([
    /\b_?ctypes\.(cdll|windll|oledll|pydll|pythonapi|memmove|memset|string_at|wstring_at|cfunctype|winfunctype|dlopen)\b/,
    /\bfrom\s+_?ctypes\s+import\b[^\n]*\b(cdll|windll|oledll|pydll|pythonapi|memmove|memset|string_at|wstring_at|cfunctype|winfunctype|\*)/,
    /\bdlopen\s*\(/,
    /\.set_source\s*\(/,
    /\bprocess\s*\.\s*(dlopen|binding|_linkedbinding)\b/,
    /\b(require|import)\s*\(\s*["'`][^"'`\n]*\.node["'`]/,
    /\bfrom\s+["'][^"'\n]*\.node["']/,
    /(\brequire\s*\(\s*|\bfrom\s+|\bimport\s+)["'`](@[^/"'`]+\/)?(koffi|ffi-napi|ffi|node-ffi|ffi-rs|ref-napi|bun:ffi|bindings|node-gyp-build)["'`]/
].map(r => r.source).join("|"));

function inferForbidden(content = "", facts = null) {
    if (facts?.ast) {
        return [...new Set(facts.dangerous || [])];
    }

    const lower = String(content || "").toLowerCase();
    const forbidden = [];

    if (lower.includes("eval(")) forbidden.push("eval");
    if (lower.includes("process.exit")) forbidden.push("process.exit");
    if (lower.includes("fs.rm")) forbidden.push("fs.rm");
    if (lower.includes("child_process")) forbidden.push("child_process");
    if (NATIVE_TEXT.test(lower)) forbidden.push("native_code");

    return [...new Set(forbidden)];
}

function summarize(content = "", facts = null) {
    const text = String(content || "");
    const lines = text.split("\n").length;
    const size = text.length;

    if (facts?.ast) {
        const operations = facts.operations || {};
        return {
            size,
            lines,
            hasCrypto: Boolean(operations.cryptoUse || operations.secretComparison
                || (facts.imports || []).includes("crypto")),
            hasFilesystem: Boolean(operations.diskRead || operations.diskWrite || operations.diskDelete),
            hasNetwork: Boolean(operations.inboundHttp || operations.outboundHttp)
        };
    }

    return {
        size,
        lines,
        hasCrypto: text.toLowerCase().includes("crypto"),
        hasFilesystem: text.toLowerCase().includes("fs."),
        hasNetwork: NET_TEXT.test(text.toLowerCase())
    };
}

// The compact, token-conscious projection of the AST facts: enabled operations
// only, empty categories omitted, and every risk signal keeps the syntax that
// produced it. `ast: true` means the facts are complete for the parsed file, so
// a missing key is a proven absence rather than a gap in the IR.
function compressFacts(facts) {
    if (!facts?.ast) {
        const reason = facts?.error || "source did not parse; IR fell back to text heuristics";
        return facts?.parseError ? { ast: false, reason, parseError: facts.parseError } : { ast: false, reason };
    }

    const compressed = { ast: true };
    const put = (key, value) => {
        if (Array.isArray(value) && value.length > 0) compressed[key] = value;
    };

    put("routes", facts.routes);
    put("exports", facts.exports);
    put("imports", facts.imports);
    put("env", facts.env);
    put("operations", Object.entries(facts.operations || {})
        .filter(([, enabled]) => enabled)
        .map(([name]) => name));

    const calls = {};
    for (const [bucket, entries] of Object.entries(facts.calls || {})) {
        if (Array.isArray(entries) && entries.length > 0) calls[bucket] = entries;
    }
    if (Object.keys(calls).length > 0) compressed.calls = calls;

    put("dangerous", facts.dangerous);
    put("riskSignals", (facts.riskSignals || []).map(s => `${s.signal}:${s.evidence}@${s.line}`));

    return compressed;
}

function analyze(content, options = {}) {
    const opts = readOptions(options);
    const facts = opts.supported
        ? (opts.language === "python" ? PythonFacts.extract(content)
            : opts.language === "rust" ? RustFacts.extract(content, { target: opts.target })
                : AstFacts.extract(content, opts.language))
        : {
            ...AstFacts.emptyFacts(),
            error: `unsupported language: ${opts.language} (supported: ${LANGUAGES.join(", ")})`
        };

    return {
        target: opts.target,
        language: opts.language,
        objective: inferObjective(content, opts.consecutiveFailures, facts),
        constraints: inferConstraints(opts.target, opts.consecutiveFailures),
        risk: inferRisk(opts.target, content, facts),
        pressure: opts.pressure,
        confidence: opts.confidence,
        budget: opts.budget,
        forbidden: inferForbidden(content, facts),
        summary: summarize(content, facts),
        analysisStatus: facts.ast === true ? 'complete' : 'incomplete',
        facts
    };
}

function compress(ir) {
    return {
        analysisStatus: ir.facts?.ast === true ? 'complete' : 'incomplete',
        language: ir.language || "javascript",
        mission: {
            target: ir.target,
            objective: ir.objective
        },
        world: {
            pressure: ir.pressure,
            confidence: ir.confidence,
            budget: ir.budget,
            risk: ir.risk
        },
        constraints: ir.constraints,
        forbidden: ir.forbidden,
        summary: ir.summary,
        facts: compressFacts(ir.facts)
    };
}

function expandDecision(decision, sourceIr) {
    return {
        action: decision.action,
        patch: decision.patch,
        target: sourceIr.target,
        objective: sourceIr.objective,
        confidence: sourceIr.confidence,
        pressure: sourceIr.pressure
    };
}

// Loads the bundled WebAssembly grammars. Without arguments only JavaScript is
// loaded; pass e.g. { languages: ["typescript", "tsx"] } before calling the
// synchronous analyze() on TypeScript.
async function initializeWasm(options = {}) {
    const requested = Array.isArray(options?.languages) ? options.languages : ["javascript"];
    for (const language of requested) {
        const resolved = resolveLanguage(language, null);
        if (!resolved.supported) {
            throw new Error(`Unsupported language: ${language} (supported: ${LANGUAGES.join(", ")})`);
        }
        await TreeParser.initWasm(resolved.language);
    }
}

async function analyzeAsync(content, options = {}) {
    const opts = readOptions(options);
    if (opts.supported) await TreeParser.initWasm(opts.language);
    return analyze(content, options);
}

module.exports = {
    analyze,
    analyzeAsync,
    compress,
    compressFacts,
    expandDecision,
    DEFAULTS,
    LANGUAGES,
    initializeWasm
};
