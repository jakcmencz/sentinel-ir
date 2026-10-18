"use strict";

const path = require("path");

const DIRECT_INPUT_LIMIT = 32 * 1024;
const CHUNK_SIZE = 8 * 1024;

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

    async initWasm() {
        if (this.parser && this.backend === "wasm") return;
        if (this.wasmInitPromise) return this.wasmInitPromise;

        this.wasmInitPromise = (async () => {
            const mod = require("web-tree-sitter");
            const Parser = mod.Parser || mod.default || mod;
            const Language = mod.Language || Parser.Language;

            if (!Parser || typeof Parser.init !== "function" ||
                !Language || typeof Language.load !== "function") {
                throw new Error("Unsupported web-tree-sitter API.");
            }

            await Parser.init();

            const wasmPath = path.join(
                __dirname, "..", "wasm", "tree-sitter-javascript.wasm"
            );

            const language = await Language.load(wasmPath);
            const parser = new Parser();
            parser.setLanguage(language);

            this.parser = parser;
            this.backend = "wasm";
        })().catch(error => {
            this.wasmInitPromise = null;
            throw error;
        });

        return this.wasmInitPromise;
    },

    parseInput(content) {
        if (content.length <= DIRECT_INPUT_LIMIT) {
            return this.parser.parse(content);
        }

        return this.parser.parse(index =>
            index < content.length
                ? content.slice(index, index + CHUNK_SIZE)
                : null
        );
    },

    parse(content) {
        try {
            if (typeof content !== "string") {
                throw new Error(
                    "TreeParser.parse expects source code as string."
                );
            }

            if (!this.parser) {
                this.init();
            }

            const tree = this.parseInput(content);
            const root = tree.rootNode;
            const hasError = typeof root.hasError === "function"
                ? root.hasError()
                : Boolean(root.hasError);

            return {
                ok: true,
                language: "javascript",
                root,
                nodes: this.extractNodes(root),
                metrics: {
                    ...this.getMetrics(root),
                    hasError
                }
            };
        } catch (error) {
            return {
                ok: false,
                language: "javascript",
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

module.exports = TreeParser;
