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
const { boundFacts } = require("./ir-text");
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
// Without a target the code is analyzed as JavaScript; a target with no or any
// other extension (Makefile, configure, x.rb) is reported as unsupported
// instead of being parsed with the wrong grammar.
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
// Only a plain extension is echoed into facts.error; the target is caller text.
const SAFE_EXTENSION = /^\.[a-z0-9_+-]{1,16}$/;
const SAFE_LANGUAGE = /^[a-z0-9_+#.-]{1,32}$/;

function resolveLanguage(language, target) {
    if (typeof language === "string" && language.trim() !== "") {
        const id = language.trim().toLowerCase();
        return Object.hasOwn(LANGUAGE_ALIASES, id)
            ? { language: LANGUAGE_ALIASES[id], supported: true }
            : { language: "unknown", supported: false, requested: SAFE_LANGUAGE.test(id) ? id : "(unnamed)" };
    }

    if (typeof target !== "string" || target === "") return { language: "javascript", supported: true };
    const match = /\.[^./\\]+$/.exec(target.toLowerCase());
    if (!match) return { language: "unknown", supported: false, extension: "(none)" };
    const inferred = EXTENSION_LANGUAGES[match[0]];
    return inferred
        ? { language: inferred, supported: true }
        : { language: "unknown", supported: false, extension: SAFE_EXTENSION.test(match[0]) ? match[0] : "(unnamed)" };
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

// Text fallback for Python and Rust (lower-cased source). The generic checks
// below are JavaScript-shaped; a syntax error must not turn os.system or
// Command::new into a confident "low".
const LANGUAGE_TEXT = {
    python: {
        critical: /\bos\s*\.\s*(system|popen\d?|exec\w*|spawn\w*|fork\w*|posix_spawn\w*|startfile)\b|\bimport\s+_?ctypes\b|\b(subprocess|popen2|cffi|llvmlite|c?pickle|_pickle|dill|marshal|shelve|jsonpickle)\b|\bcommands\s*\.\s*getstatus|\bpty\s*\.\s*spawn\b|\bcreate_subprocess_(exec|shell)\b|\byaml\s*\.\s*(unsafe_)?load\b|\bjoblib\s*\.\s*load\b|\bread_pickle\b|\bloadlibrary\b|\b__import__\b|\b(import_module|exec_module|load_module|load_source|spec_from_file_location|runpy)\b|\bcompile\s*\(|\bexec\b/,
        high: /\bshutil\s*\.\s*(rmtree|move|copy\w*|chown)\b|\brmtree\b|\bos\s*\.\s*(remove|unlink|rmdir|removedirs|renames?|replace|makedirs|mkdir|chmod|chown|truncate|symlink|link)\b|\.\s*(write_text|write_bytes|unlink|rmdir|touch|mkdir|symlink_to|hardlink_to)\s*\(|\bopen\s*\([^)\n]{0,200}["'][rbt]*[wxa+]/,
        network: /\b(requests|urllib\d?|httpx|aiohttp|socket|socketserver|http\s*\.\s*(client|server)|wsgiref|ftplib|smtplib|telnetlib|paramiko|websockets?|flask|fastapi|django|quart|sanic)\b/,
        crypto: /\b(hashlib|hmac|secrets|crypt|cryptography|cryptodome|nacl|bcrypt|jwt|passlib)\b/
    },
    rust: {
        critical: /\bunsafe\b|\bextern\s*("|\{)|\b(no_mangle|export_name|link_section)\b|\b(std|tokio|async_std|smol)\s*::\s*process\b(?!\s*::\s*(exit|abort|id|exitcode|stdio)\b|\s*;|\s*::\s*\{(?![^}]*\bcommand\b))|\bcommand\s*::\s*new\b|\b(async_process|duct|xshell|cmd_lib|libloading|dlopen2?|cc|cmake|pkg_config|vcpkg|rhai|mlua|rlua|boa_engine|deno_core|v8)\s*::|\b(global_|naked_|llvm_)?asm\s*!|\btransmute\b|\b(dlopen|dlsym|loadlibrary\w*|getprocaddress)\b|\b(libc|nix)\s*::\s*(\w+\s*::\s*)?(system|popen|v?fork|exec\w*|posix_spawnp?)\b|\bsubprocess\s*::\s*(exec|popen)\b|\bpython\s*::\s*(run|eval)\b|\bpy\s*\.\s*(run|eval)\s*\(|cargo::?rustc-link-/,
        high: /\bfs(_err)?\s*::\s*(write|remove_\w+|rename|copy|create_dir\w*|hard_link|soft_link|set_permissions)\b|\bfile\s*::\s*(create\w*|options)\b|\bopenoptions\b|\bsymlink\w*|\btempfile\s*::/,
        network: /\b(tcpstream|tcplistener|udpsocket|unixlistener|reqwest|hyper|hyper_util|ureq|surf|isahc|attohttpc|curl|tungstenite|tokio_tungstenite|awc|axum|actix_web|rocket|warp|tiny_http|tide|poem|salvo|ntex)\b|\b(tokio|async_std)\s*::\s*net\b/,
        crypto: /\b(sha1|sha2|sha3|md5|md_5|hmac|ring|openssl|aes|aes_gcm|chacha20poly1305|rsa|ed25519_dalek|x25519_dalek|argon2|bcrypt|scrypt|pbkdf2|jsonwebtoken|blake2|blake3|orion|sodiumoxide|k256|p256|p384|hkdf|crypto_box|aws_lc_rs|rustls)\b/
    }
};

const RISK_ORDER = ["low", "medium", "high", "critical"];

function languageTextRisk(language, lower) {
    const checks = LANGUAGE_TEXT[language];
    if (!checks) return "low";
    if (checks.critical.test(lower)) return "critical";
    if (checks.high.test(lower)) return "high";
    if (checks.network.test(lower) || checks.crypto.test(lower)) return "medium";
    return "low";
}

// Code the parser could not read to the end, or could not read at all
// (unsupported language), is never low: what it hides is unknown.
function inferRisk(filePath, content = "", facts = null, language = "javascript", supported = true) {
    const fallback = textRisk(filePath, content, facts);
    if (facts?.ast) return fallback;
    const own = languageTextRisk(language, String(content || "").toLowerCase());
    const risk = RISK_ORDER.indexOf(own) > RISK_ORDER.indexOf(fallback) ? own : fallback;
    return risk === "low" ? "medium" : risk;
}

// Names the IR quotes from the source (imports, exports, env names, routes)
// that read as instructions to an AI agent, or hide text in whitespace,
// control or bidirectional characters. They stay in the IR as data and are
// also named in riskSignals as suspicious_text.
const INSTRUCTION_TEXT = new RegExp([
    /\b(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+|above\s+|earlier\s+|these\s+|those\s+|safety\s+|security\s+)*(instructions?|risks|prompts?|guardrails|findings)\b/,
    /\b(ignore|disregard|forget|override|bypass)\s+(all|any|the|your|previous|prior|above|earlier|these|those|safety|security)\s+(rules|warnings|polic(y|ies)|checks)\b/,
    /\bsystem\s+override\b/,
    /\byou\s+are\s+now\b/,
    /\bnew\s+instructions\b/,
    /\b(mark|treat|report|label|consider)\s+(this|it|the\s+\w+)(\s+\w+)?\s+(as\s+)?(safe|trusted|harmless|low\s+risk)\b/,
    /\brm\s+-?rf\b/,
    /\bcurl\b.*\|\s*(ba|z)?sh\b/
].map(r => r.source).join("|"));
const HIDDEN_CHARS = /[\s\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff]/;

const HIDDEN_CHARS_ALL = new RegExp(HIDDEN_CHARS.source, "g");

function suspiciousName(kind, value) {
    const name = String(value);
    // A route is "GET /path": only the path counts.
    const checked = kind === "routes" ? name.slice(name.indexOf(" ") + 1) : name;
    if (HIDDEN_CHARS.test(checked)) return true;
    const words = checked.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_./:\\-]+/g, " ").toLowerCase();
    return INSTRUCTION_TEXT.test(words) || INSTRUCTION_TEXT.test(checked.toLowerCase());
}

// The line of the name itself; a route is searched by its path.
function lineOf(content, kind, value) {
    const name = String(value);
    const at = String(content || "").indexOf(kind === "routes" ? name.slice(name.indexOf(" ") + 1) : name);
    return at < 0 ? 1 : String(content).slice(0, at).split("\n").length;
}

function markSuspiciousText(facts, content) {
    if (!facts?.ast) return facts;
    const found = [];
    for (const kind of ["imports", "exports", "env", "routes"]) {
        for (const value of facts[kind] || []) {
            if (suspiciousName(kind, value)) {
                const shown = String(value).replace(HIDDEN_CHARS_ALL, c => c === " " ? " " : `\\u{${c.codePointAt(0).toString(16)}}`);
                found.push({ signal: "suspicious_text", evidence: `${kind}: ${shown}`, line: lineOf(content, kind, value) });
            }
        }
    }
    if (found.length === 0) return facts;
    return {
        ...facts,
        operations: { ...facts.operations, suspiciousText: true },
        riskSignals: [...(facts.riskSignals || []), ...found]
    };
}

function textRisk(filePath, content = "", facts = null) {
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
    /\bfrom\s+_?ctypes\s+import\b[^\n]*\b(cdll|windll|oledll|pydll|pythonapi|memmove|memset|string_at|wstring_at|cfunctype|winfunctype)\b|\bfrom\s+_?ctypes\s+import\s*\*/,
    /\bdlopen\s*\(/,
    /\.set_source\s*\(/,
    /\bprocess\s*\.\s*(dlopen|binding|_linkedbinding)\b/,
    /\b(require|import)\s*\(\s*["'`][^"'`\n]*\.node["'`]/,
    /\bfrom\s+["'][^"'\n]*\.node["']/,
    /(\brequire\s*\(\s*|\bfrom\s+|\bimport\s+)["'`](@[^/"'`]+\/)?(koffi|ffi-napi|ffi|node-ffi|ffi-rs|ref-napi|bun:ffi|bindings|node-gyp-build)["'`]/
].map(r => r.source).join("|"));

// Text-fallback counterparts of the Python and Rust `dangerous` facts, so a
// file rated critical by LANGUAGE_TEXT also says which capability it saw.
const LANGUAGE_FORBIDDEN_TEXT = {
    python: [
        ["eval", /\b(eval|exec|compile)\s*\(|\bexec\b|\b__import__\b|\b(import_module|exec_module|load_module|load_source|spec_from_file_location|runpy)\b/],
        ["child_process", /\b(subprocess|popen2)\b|\bcreate_subprocess_(exec|shell)\b|\bpty\s*\.\s*spawn\b|\bcommands\s*\.\s*getstatus/],
        ["process_spawn", /\bos\s*\.\s*(system|popen\d?|exec\w*|spawn\w*|fork\w*|posix_spawn\w*|startfile)\b|\bsubprocess\s*\.\s*\w+\s*\(|\bcreate_subprocess_(exec|shell)\b|\bpty\s*\.\s*spawn\b/],
        ["destructive_fs", /\brmtree\b|\bshutil\s*\.\s*move\b|\bos\s*\.\s*(remove|unlink|rmdir|removedirs|truncate)\b|\.\s*(unlink|rmdir)\s*\(/],
        ["unsafe_deserialization", /\b(c?pickle|_pickle|dill|marshal|shelve|jsonpickle)\b|\bjoblib\s*\.\s*load\b|\byaml\s*\.\s*(unsafe_)?load\b|\bread_pickle\b/],
        ["native_code", /\bimport\s+_?ctypes\b|\b(cffi|llvmlite)\b|\bloadlibrary\b/]
    ],
    rust: [
        ["eval", /\b(rhai|mlua|rlua|boa_engine|deno_core|v8)\s*::|\bpython\s*::\s*(run|eval)\b|\bpy\s*\.\s*(run|eval)\s*\(/],
        ["child_process", /\b(std|tokio|async_std|smol)\s*::\s*process\s*::\s*(\{[^}]*)?\bcommand\b|\b(std|tokio|async_std|smol)\s*::\s*process\s*(;|::\s*\{[^}]*\bself\b)[\s\S]*\bprocess\s*::\s*command\b|\b(async_process|duct|xshell|cmd_lib)\s*::/],
        ["process_spawn", /\bcommand\s*::\s*new\b|\b(libc|nix)\s*::\s*(\w+\s*::\s*)?(system|popen|v?fork|exec\w*|posix_spawnp?)\b|\bsubprocess\s*::\s*(exec|popen)\b/],
        ["destructive_fs", /\bfs(_err)?\s*::\s*(remove_\w+|rename)\b/],
        ["native_code", /\bunsafe\b|\bextern\s*("|\{)|\b(no_mangle|export_name|link_section)\b|\b(global_|naked_|llvm_)?asm\s*!|\btransmute\b|\b(libloading|dlopen2?|cc|cmake|pkg_config|vcpkg)\s*::|\b(dlopen|dlsym|loadlibrary\w*|getprocaddress)\b|cargo::?rustc-link-/]
    ]
};

function inferForbidden(content = "", facts = null, language = "javascript") {
    if (facts?.ast) {
        return [...new Set(facts.dangerous || [])];
    }

    const lower = String(content || "").toLowerCase();
    const forbidden = [];
    for (const [name, pattern] of LANGUAGE_FORBIDDEN_TEXT[language] || []) {
        if (pattern.test(lower)) forbidden.push(name);
    }

    if (lower.includes("eval(")) forbidden.push("eval");
    if (lower.includes("process.exit")) forbidden.push("process.exit");
    if (lower.includes("fs.rm")) forbidden.push("fs.rm");
    if (lower.includes("child_process")) forbidden.push("child_process");
    if (NATIVE_TEXT.test(lower)) forbidden.push("native_code");

    return [...new Set(forbidden)];
}

function summarize(content = "", facts = null, language = "javascript") {
    const text = String(content || "");
    const lines = text === "" ? 0 : text.split("\n").length;
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
        hasCrypto: text.toLowerCase().includes("crypto")
            || Boolean(LANGUAGE_TEXT[language]?.crypto.test(text.toLowerCase())),
        hasFilesystem: text.toLowerCase().includes("fs.")
            || Boolean(LANGUAGE_TEXT[language]?.high.test(text.toLowerCase())),
        hasNetwork: NET_TEXT.test(text.toLowerCase())
            || Boolean(LANGUAGE_TEXT[language]?.network.test(text.toLowerCase()))
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

// Code nested thousands of levels deep overflows the stack of the recursive
// extractors; it gets the same text-heuristic IR as a file that did not parse.
function extractFacts(content, opts) {
    if (!opts.supported) {
        return {
            ...AstFacts.emptyFacts(),
            error: opts.extension
                ? `unsupported file type: ${opts.extension} (supported: ${Object.keys(EXTENSION_LANGUAGES).join(" ")})`
                : `unsupported language: ${opts.requested} (supported: ${LANGUAGES.join(", ")})`
        };
    }
    try {
        return opts.language === "python" ? PythonFacts.extract(content)
            : opts.language === "rust" ? RustFacts.extract(content, { target: opts.target })
                : AstFacts.extract(content, opts.language);
    } catch (error) {
        if (!(error instanceof RangeError)) throw error;
        return { ...AstFacts.emptyFacts(), error: "source is nested too deeply to analyze" };
    }
}

function analyze(content, options = {}) {
    const opts = readOptions(options);
    const facts = boundFacts(markSuspiciousText(extractFacts(content, opts), content));

    return {
        target: opts.target,
        language: opts.language,
        objective: inferObjective(content, opts.consecutiveFailures, facts),
        constraints: inferConstraints(opts.target, opts.consecutiveFailures),
        risk: inferRisk(opts.target, content, facts, opts.language, opts.supported),
        pressure: opts.pressure,
        confidence: opts.confidence,
        budget: opts.budget,
        forbidden: inferForbidden(content, facts, opts.language),
        summary: summarize(content, facts, opts.language),
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
// synchronous analyze() on TypeScript. analyze() has no other parser.
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
