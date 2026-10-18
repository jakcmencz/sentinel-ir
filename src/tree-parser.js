/**
 * SENTINEL AUTONOMOUS AGENT SYSTEM
 * MODULE: libs/core/tree-parser.js
 *
 * Purpose:
 * Convert JavaScript source into AST structure.
 *
 * JavaScript
 *      ↓
 * Tree Parser
 *      ↓
 * Semantic Analyzer
 *      ↓
 * Sentinel-IR
 */

const Parser = require("tree-sitter");
const JavaScript = require("tree-sitter-javascript");

// tree-sitter's node bindings reject direct string input above 32 KiB, so
// larger files are fed through a chunked reader instead.
const DIRECT_INPUT_LIMIT = 32 * 1024;
const CHUNK_SIZE = 8 * 1024;

const TreeParser = {
    parser: null,

    init() {
        this.parser = new Parser();
        this.parser.setLanguage(JavaScript);
    },

    parseInput(content) {
        if (content.length <= DIRECT_INPUT_LIMIT) {
            return this.parser.parse(content);
        }

        return this.parser.parse(index => (
            index < content.length
                ? content.slice(index, index + CHUNK_SIZE)
                : null
        ));
    },

    parse(content) {
        try {
            if (!this.parser) {
                this.init();
            }

            if (typeof content !== "string") {
                throw new Error("TreeParser.parse expects source code as string.");
            }

            const tree = this.parseInput(content);

            return {
                ok: true,
                language: "javascript",
                root: tree.rootNode,
                nodes: this.extractNodes(tree.rootNode),
                metrics: this.getMetrics(tree.rootNode)
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
            named: !!node.named,
            childCount: node.namedChildCount || 0
        });

        for (const child of node.children || []) {
            this.extractNodes(child, result);
        }

        return result;
    },

    getMetrics(node) {
        const walk = (n, depth = 0) => {
            if (!n) {
                return { count: 0, maxDepth: depth };
            }

            let count = 1;
            let maxDepth = depth;

            for (const child of n.children || []) {
                const childMetrics = walk(child, depth + 1);
                count += childMetrics.count;
                maxDepth = Math.max(maxDepth, childMetrics.maxDepth);
            }

            return { count, maxDepth };
        };

        const metrics = walk(node, 0);

        return {
            nodeCount: metrics.count,
            depth: metrics.maxDepth,
            hasError: false
        };
    }
};

module.exports = TreeParser;