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
    return {
        target: typeof opts.target === "string" ? opts.target : null,
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
        const risk = AstFacts.riskOf(facts);
        // A file that lives on the security path is never below medium, even
        // when its syntax looks harmless.
        if (risk === "low" && path.includes("crypto")) return "medium";
        return risk;
    }

    if (
        lower.includes("eval") ||
        lower.includes("process.exit") ||
        lower.includes("exec(") ||
        lower.includes("spawn(")
    ) {
        return "critical";
    }

    if (path.includes("crypto") || lower.includes("pbkdf2") || lower.includes("cipher")) {
        return "medium";
    }

    if (lower.includes("writefile") || lower.includes("unlink")) {
        return "high";
    }

    if (lower.includes("fetch") || lower.includes("axios")) {
        return "medium";
    }

    return "low";
}

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
        hasNetwork: text.toLowerCase().includes("fetch") || text.toLowerCase().includes("axios")
    };
}

// The compact, token-conscious projection of the AST facts: enabled operations
// only, empty categories omitted, and every risk signal keeps the syntax that
// produced it. `ast: true` means the facts are complete for the parsed file, so
// a missing key is a proven absence rather than a gap in the IR.
function compressFacts(facts) {
    if (!facts?.ast) {
        return { ast: false, reason: facts?.error || "source did not parse; IR fell back to text heuristics" };
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
    const facts = AstFacts.extract(content);

    return {
        target: opts.target,
        objective: inferObjective(content, opts.consecutiveFailures, facts),
        constraints: inferConstraints(opts.target, opts.consecutiveFailures),
        risk: inferRisk(opts.target, content, facts),
        pressure: opts.pressure,
        confidence: opts.confidence,
        budget: opts.budget,
        forbidden: inferForbidden(content, facts),
        summary: summarize(content, facts),
        facts
    };
}

function compress(ir) {
    return {
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

module.exports = { analyze, compress, compressFacts, expandDecision, DEFAULTS };
