"use strict";

/**
 * Bounds the code text that reaches the IR. Every string in the IR is read by
 * a model, and the code it came from is untrusted, so:
 *   - codeText() renders an expression without its comments and with every
 *     string literal replaced by "…", for evidence built from source text;
 *   - withoutComments() keeps the strings, for text the analyzer matches on;
 *   - boundFacts() collapses whitespace and caps each fact string at
 *     MAX_TEXT characters.
 */

const MAX_TEXT = 128;
const ELLIPSIS = "…";
const STRING_TYPES = new Set([
    "string", "template_string", "regex",
    "string_literal", "raw_string_literal", "char_literal",
    "concatenated_string"
]);

const COMMENT_TYPES = new Set(["comment", "line_comment", "block_comment"]);

function isComment(node) {
    return COMMENT_TYPES.has(node.type);
}

// Named children without comments: a comment between two tokens must not
// change what the extractors see.
function named(node) {
    const children = node?.namedChildren;
    if (!children) return [];
    return children.some(isComment) ? children.filter(child => !isComment(child)) : children;
}

// Source text of `node` with comments dropped and, when `redact` is set, every
// string literal replaced by "…". Stops once the output passes `limit`, so a
// huge expression costs no more than the part that is kept.
function render(node, limit, redact) {
    let out = "";
    const visit = current => {
        if (isComment(current)) return;
        if (redact && STRING_TYPES.has(current.type)) {
            out += `"${ELLIPSIS}"`;
            return;
        }
        const children = current.children || [];
        if (children.length === 0) {
            out += current.text;
            return;
        }
        const source = current.text;
        const start = current.startIndex;
        let position = start;
        for (const child of children) {
            out += source.slice(position - start, child.startIndex - start);
            if (out.length > limit) return;
            visit(child);
            if (out.length > limit) return;
            position = child.endIndex;
        }
        out += source.slice(position - start);
    };
    visit(node);
    return out;
}

// Evidence built from an expression: no comments, no string contents, one
// line of at most `limit` characters.
function codeText(node, limit = MAX_TEXT) {
    if (!node) return "";
    return boundText(render(node, limit, true), limit);
}

// The same text the analyzer matches on, only without comments.
function withoutComments(node) {
    if (!node) return "";
    const source = node.text;
    if (!/[/#]/.test(source)) return source;
    return render(node, Infinity, false);
}

function boundText(value, limit = MAX_TEXT) {
    const text = String(value).replace(/\s+/g, " ");
    if (text.length <= limit) return text;
    let end = limit - ELLIPSIS.length;
    const last = text.charCodeAt(end - 1);
    if (last >= 0xD800 && last <= 0xDBFF) end--;
    return text.slice(0, end) + ELLIPSIS;
}

function boundList(values) {
    if (!Array.isArray(values)) return values;
    return values.map(value => boundText(value));
}

function boundFacts(facts) {
    if (!facts || typeof facts !== "object") return facts;
    const bounded = { ...facts };
    for (const key of ["routes", "exports", "imports", "env", "dangerous"]) {
        if (Array.isArray(facts[key])) bounded[key] = boundList(facts[key]);
    }
    if (facts.calls && typeof facts.calls === "object") {
        bounded.calls = {};
        for (const [bucket, entries] of Object.entries(facts.calls)) bounded.calls[bucket] = boundList(entries);
    }
    if (Array.isArray(facts.riskSignals)) {
        bounded.riskSignals = facts.riskSignals.map(signal => ({ ...signal, evidence: boundText(signal.evidence ?? "") }));
    }
    return bounded;
}

module.exports = { MAX_TEXT, isComment, named, codeText, withoutComments, boundText, boundFacts };
