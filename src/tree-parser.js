"use strict";

const path = require("path");

const DIRECT_INPUT_LIMIT = 32 * 1024;
const CHUNK_SIZE = 8 * 1024;

// Bundled WebAssembly grammars, one per supported language id.
const WASM_GRAMMARS = Object.freeze({
    javascript: "tree-sitter-javascript.wasm",
    typescript: "tree-sitter-typescript.wasm",
    tsx: "tree-sitter-tsx.wasm",
    python: "tree-sitter-python.wasm"
});

const nodeFlag = (node, key) => typeof node[key] === "function"
    ? Boolean(node[key]())
    : Boolean(node[key]);

const errorAt = (position, kind, expected) => ({
    line: position.row + 1,
    column: position.column + 1,
    kind,
    ...(expected ? { expected } : {})
});

const OPENING = Object.freeze({ "(": ")", "[": "]", "{": "}" });
const CLOSING = new Set([")", "]", "}"]);
const COMPOUND_KEYWORDS = new Set([
    "if", "elif", "else", "while", "for", "try", "except", "finally", "with", "def", "class", "async"
]);

function leafTokens(node) {
    const out = [];
    const stack = [node];
    while (stack.length) {
        const current = stack.pop();
        const children = current.children || [];
        if (!children.length) out.push(current);
        for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    }
    return out;
}

function firstInnerError(node) {
    const stack = [...(node.children || [])].reverse();
    while (stack.length) {
        const current = stack.pop();
        if (current.type === "ERROR") return current;
        if (!nodeFlag(current, "hasError")) continue;
        const children = current.children || [];
        for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);
    }
    return null;
}

// tree-sitter-python often wraps a whole statement, or the whole file, in one
// ERROR node starting at its first token, so its start says little. Inside it,
// look for what CPython would report: an unmatched closing bracket, a block
// header without ':', or a bracket that is never closed.
function pythonErrorIn(error, lines) {
    for (let region = error; region;) {
        const tokens = leafTokens(region);

        const open = [];
        let closer = null;
        for (const token of tokens) {
            if (nodeFlag(token, "isMissing")) {
                if (!open.length) return errorAt(token.startPosition, "missing", token.type);
                break;
            }
            if (OPENING[token.type]) open.push(token);
            else if (CLOSING.has(token.type)) {
                if (open.length && OPENING[open[open.length - 1].type] === token.type) open.pop();
                else {
                    closer = token;
                    break;
                }
            }
        }

        let headerEnd = null;
        let depth = 0;
        let header = false;
        let colon = false;
        for (let i = 0; i < tokens.length && !headerEnd; i++) {
            const token = tokens[i];
            const prev = tokens[i - 1];
            const lineStart = !prev || (depth === 0 && token.startPosition.row > prev.endPosition.row &&
                !(lines[prev.endPosition.row] || "").trimEnd().endsWith("\\"));
            if (lineStart) {
                if (header && !colon) {
                    headerEnd = prev;
                    break;
                }
                header = COMPOUND_KEYWORDS.has(token.type);
                colon = false;
            }
            if (OPENING[token.type]) depth++;
            else if (CLOSING.has(token.type)) depth = Math.max(0, depth - 1);
            else if (token.type === ":" && depth === 0) colon = true;
            else if (token.type === "lambda") header = false;
        }

        if (headerEnd && (!closer || isBefore(headerEnd.endPosition, closer.startPosition))) {
            return errorAt(headerEnd.endPosition, "missing", ":");
        }
        if (closer) return errorAt(closer.startPosition, "unexpected");
        if (open.length) {
            const bracket = open[open.length - 1];
            return errorAt(bracket.startPosition, "unclosed", OPENING[bracket.type]);
        }

        const inner = firstInnerError(region);
        if (inner) {
            region = inner;
            continue;
        }
        const row = region.startPosition.row;
        const last = tokens.filter(t => t.startPosition.row === row && t.endPosition.row === row).pop();
        return errorAt(last ? last.endPosition : region.startPosition, "unexpected");
    }
    return null;
}

function isBefore(a, b) {
    return a.row < b.row || (a.row === b.row && a.column < b.column);
}

const TreeParser = {
    parser: null,
    backend: null,

    // Výchozí cesta pro platformy, kde fungují nativní moduly.
    init() {
        if (this.parser && this.backend === "native") return;

        const Parser = require("tree-sitter");
        const JavaScript = require("tree-sitter-javascript");

        this.parser = new Parser();
        this.parser.setLanguage(JavaScript);
        this.backend = "native";
    },

    // Android/WASM: sdílí jednu rozpracovanou inicializaci.
    wasmInitPromise: null,
    wasmRuntimePromise: null,

    // Grammars other than JavaScript exist only as bundled WebAssembly and are
    // loaded on first use, so a JavaScript-only caller never loads them.
    languageParsers: {},
    languagePromises: {},

    loadWasmRuntime() {
        if (this.wasmRuntimePromise) return this.wasmRuntimePromise;

        this.wasmRuntimePromise = (async () => {
            const mod = require("web-tree-sitter");
            const Parser = mod.Parser || mod.default || mod;
            const Language = mod.Language || Parser.Language;

            if (!Parser || typeof Parser.init !== "function" ||
                !Language || typeof Language.load !== "function") {
                throw new Error("Unsupported web-tree-sitter API.");
            }

            await Parser.init();
            return { Parser, Language };
        })().catch(error => {
            this.wasmRuntimePromise = null;
            throw error;
        });

        return this.wasmRuntimePromise;
    },

    async loadWasmParser(language) {
        const { Parser, Language } = await this.loadWasmRuntime();
        const wasmPath = path.join(__dirname, "..", "wasm", WASM_GRAMMARS[language]);
        const grammar = await Language.load(wasmPath);
        const parser = new Parser();
        parser.setLanguage(grammar);
        return parser;
    },

    async initWasm(language = "javascript") {
        if (!Object.hasOwn(WASM_GRAMMARS, language)) {
            throw new Error(`Unsupported language: ${language}`);
        }

        if (language !== "javascript") {
            if (this.languageParsers[language]) return;
            if (this.languagePromises[language]) return this.languagePromises[language];

            this.languagePromises[language] = this.loadWasmParser(language)
                .then(parser => {
                    this.languageParsers[language] = parser;
                })
                .catch(error => {
                    delete this.languagePromises[language];
                    throw error;
                });

            return this.languagePromises[language];
        }

        if (this.parser && this.backend === "wasm") return;
        if (this.wasmInitPromise) return this.wasmInitPromise;

        this.wasmInitPromise = this.loadWasmParser("javascript")
            .then(parser => {
                this.parser = parser;
                this.backend = "wasm";
            })
            .catch(error => {
                this.wasmInitPromise = null;
                throw error;
            });

        return this.wasmInitPromise;
    },

    parseInput(content, parser = this.parser) {
        if (content.length <= DIRECT_INPUT_LIMIT) {
            return parser.parse(content);
        }

        return parser.parse(index =>
            index < content.length
                ? content.slice(index, index + CHUNK_SIZE)
                : null
        );
    },

    parserFor(language) {
        if (language === "javascript") {
            if (!this.parser) {
                this.init();
            }
            return this.parser;
        }

        const parser = this.languageParsers[language];
        if (!parser) {
            throw new Error(
                `The ${language} parser is not initialized. ` +
                "Use analyzeAsync() or initializeWasm({ languages }) first."
            );
        }
        return parser;
    },

    // WebAssembly trees live outside the JS heap and are not garbage collected;
    // without this a long-running process runs out of parser memory.
    release(ast) {
        if (typeof ast?.tree?.delete === "function") ast.tree.delete();
    },

    parse(content, language = "javascript") {
        try {
            if (typeof content !== "string") {
                throw new Error(
                    "TreeParser.parse expects source code as string."
                );
            }

            if (!Object.hasOwn(WASM_GRAMMARS, language)) {
                throw new Error(`Unsupported language: ${language}`);
            }

            const parser = this.parserFor(language);
            const tree = this.parseInput(content, parser);
            const root = tree.rootNode;
            const hasError = typeof root.hasError === "function"
                ? root.hasError()
                : Boolean(root.hasError);

            return {
                ok: true,
                language,
                tree,
                root,
                nodes: this.extractNodes(root),
                metrics: {
                    ...this.getMetrics(root),
                    hasError
                },
                ...(hasError ? { parseError: this.firstError(root, language, content) } : {})
            };
        } catch (error) {
            return {
                ok: false,
                language,
                root: null,
                nodes: [],
                metrics: {
                    nodeCount: 0,
                    depth: 0,
                    hasError: true
                },
                error: error.message
            };
        }
    },

    // Position of the first ERROR or MISSING node. No source text is copied:
    // it is untrusted and goes straight into the IR.
    firstError(root, language = "javascript", content = "") {
        let current = root;
        while (current) {
            if (nodeFlag(current, "isMissing")) return errorAt(current.startPosition, "missing", current.type);
            if (current.type === "ERROR") {
                return language === "python"
                    ? pythonErrorIn(current, content.split("\n"))
                    : errorAt(current.startPosition, "unexpected");
            }

            let next = null;
            for (const child of current.children || []) {
                if (nodeFlag(child, "isMissing") || child.type === "ERROR" || nodeFlag(child, "hasError")) {
                    next = child;
                    break;
                }
            }
            if (!next) return errorAt(current.startPosition, "unexpected");
            current = next;
        }
        return null;
    },

    extractNodes(node, result = []) {
        if (!node) return result;

        result.push({
            type: node.type,
            text: node.text ? node.text.slice(0, 100) : null,
            named: Boolean(node.isNamed ?? node.named),
            childCount: node.namedChildCount || 0
        });

        for (const child of node.children || []) {
            this.extractNodes(child, result);
        }

        return result;
    },

    getMetrics(node) {
        const walk = (current, depth = 0) => {
            if (!current) return { count: 0, maxDepth: depth };

            let count = 1;
            let maxDepth = depth;

            for (const child of current.children || []) {
                const result = walk(child, depth + 1);
                count += result.count;
                maxDepth = Math.max(maxDepth, result.maxDepth);
            }

            return { count, maxDepth };
        };

        const result = walk(node);

        return {
            nodeCount: result.count,
            depth: result.maxDepth,
            hasError: false
        };
    }
};

TreeParser.WASM_GRAMMARS = WASM_GRAMMARS;

module.exports = TreeParser;
