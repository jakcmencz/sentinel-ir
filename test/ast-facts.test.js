const test = require('node:test');
const assert = require('node:assert/strict');

const AstFacts = require('../src/ast-facts');
const SentinelIR = require('../src/sentinel-ir');

const analyzeAt = (target, content) => SentinelIR.analyze(content, { target });

// Initialize the WASM parser before synchronous AST extraction tests run.
test.before(async () => {
    await SentinelIR.initializeWasm();
});


test('routes come from call syntax, with method and path', () => {
    const facts = AstFacts.extract(`
        const express = require("express");
        const app = express();
        app.get("/health", (req, res) => res.json({ ok: true }));
        app.post("/webhook", handler);
        router.delete("/orders/:id", handler);
        app.listen(3000);
    `);

    assert.equal(facts.ast, true);
    assert.deepEqual(facts.routes, ['GET /health', 'POST /webhook', 'DELETE /orders/:id']);
    assert.equal(facts.operations.inboundHttp, true);
});

test('a getter called on something that is not a route host is not a route', () => {
    const facts = AstFacts.extract('cache.get("user:1"); map.delete("k");');

    assert.deepEqual(facts.routes, []);
    assert.equal(facts.operations.inboundHttp, false);
});

test('exports and imports are read from module syntax', () => {
    const facts = AstFacts.extract(`
        const fs = require("fs");
        const { join } = require("path");
        function save() {}
        module.exports = { save, VERSION: "1" };
    `);

    assert.deepEqual(facts.imports, ['fs', 'path']);
    assert.deepEqual(facts.exports, ['VERSION', 'save']);
});

test('named and default ESM exports are collected too', () => {
    const facts = AstFacts.extract(`
        import axios from "axios";
        export function fetchStatus() {}
        export const TIMEOUT = 10;
        export default fetchStatus;
    `);

    assert.deepEqual(facts.imports, ['axios']);
    assert.deepEqual(facts.exports, ['TIMEOUT', 'default', 'fetchStatus']);
});

test('environment reads are collected from member and subscript access', () => {
    const facts = AstFacts.extract(`
        const port = process.env.PORT;
        const key = process.env["SIGNING_KEY"];
        const other = config.env.NOT_AN_ENV_VAR;
    `);

    assert.deepEqual(facts.env, ['PORT', 'SIGNING_KEY']);
});

test('filesystem operations distinguish read, write and delete', () => {
    const facts = AstFacts.extract(`
        const fs = require("fs");
        fs.readFileSync(p);
        fs.writeFileSync(p, data);
        fs.unlinkSync(p);
    `);

    assert.equal(facts.operations.diskRead, true);
    assert.equal(facts.operations.diskWrite, true);
    assert.equal(facts.operations.diskDelete, true);
    assert.deepEqual(facts.calls.filesystem, ['fs.readFileSync', 'fs.unlinkSync', 'fs.writeFileSync']);
    assert.deepEqual(facts.dangerous, ['destructive_fs']);
});

test('a function named evaluate is not eval', () => {
    const facts = AstFacts.extract(`
        function evaluate(poly, x) { return poly.reduce((a, c) => a * x + c, 0); }
        module.exports = { evaluate };
    `);

    assert.equal(facts.operations.dynamicEval, false);
    assert.deepEqual(facts.dangerous, []);
    assert.equal(AstFacts.riskOf(facts), 'low');
});

test('real dynamic code and process control are critical', () => {
    const facts = AstFacts.extract(`
        const { execSync } = require("child_process");
        execSync("git status");
        eval(userInput);
        new Function("return 1")();
        process.exit(1);
    `);

    assert.equal(facts.operations.dynamicEval, true);
    assert.equal(facts.operations.processSpawn, true);
    assert.equal(facts.operations.processExit, true);
    assert.deepEqual(facts.dangerous, ['eval', 'child_process', 'process_spawn', 'process.exit']);
    assert.equal(AstFacts.riskOf(facts), 'critical');
});

test('a call named exec is only process spawning when it comes from a spawning module', () => {
    const regex = AstFacts.extract(`
        const match = schemaAndHostRegExp.exec(location);
        cm.execCommand("newlineAndIndent");
        module.exports = { match };
    `);

    assert.equal(regex.operations.processSpawn, false, 'regex.exec is not a process');
    assert.equal(AstFacts.riskOf(regex), 'low');

    const local = AstFacts.extract('function exec(script) { return script; }\nexec("x");');
    assert.equal(local.operations.processSpawn, false, 'a locally defined exec is not a process');

    const cluster = AstFacts.extract('const cluster = require("cluster");\ncluster.fork();');
    assert.equal(cluster.operations.processSpawn, false, 'cluster.fork is not child_process');
});

test('process spawning is found through every binding of a spawning module', () => {
    const bindings = {
        'module alias': 'const cp = require("child_process");\ncp.exec("ls");',
        'destructured': 'const { exec } = require("child_process");\nexec("ls");',
        'renamed': 'const { exec: sh } = require("node:child_process");\nsh("ls");',
        'esm named': 'import { spawn } from "node:child_process";\nspawn("ls");',
        'inline require': 'require("child_process").execSync("ls");',
        'bare unambiguous name': 'const out = spawnSync("ls");',
        'wrapper library': 'const { execa } = require("execa");\nexeca("ls");',
        'shell runner': 'const shell = require("shelljs");\nshell.exec("ls");'
    };

    for (const [name, source] of Object.entries(bindings)) {
        const facts = AstFacts.extract(source);
        assert.equal(facts.operations.processSpawn, true, `${name} should spawn`);
        assert.equal(AstFacts.riskOf(facts), 'critical', `${name} should be critical`);
    }
});

test('a dynamically imported child_process is still child_process', () => {
    const awaited = AstFacts.extract('async function run() { const cp = await import("node:child_process"); cp.exec("ls"); }');

    assert.deepEqual(awaited.imports, ['node:child_process']);
    assert.equal(awaited.operations.childProcess, true);
    assert.equal(awaited.operations.processSpawn, true);
    assert.equal(AstFacts.riskOf(awaited), 'critical');

    const thenned = AstFacts.extract('import("child_process").then(cp => cp.exec("ls"));');
    assert.equal(thenned.operations.childProcess, true);
    assert.equal(AstFacts.riskOf(thenned), 'critical');

    const harmless = AstFacts.extract('async function run() { const fs = await import("fs"); return fs.readFileSync(p); }');
    assert.deepEqual(harmless.imports, ['fs']);
    assert.equal(harmless.operations.childProcess, false);
    assert.equal(AstFacts.riskOf(harmless), 'low');
});

test('secret comparisons are recognised as an auth check', () => {
    const facts = AstFacts.extract('if (req.headers["x-token"] !== process.env.OPERATOR_TOKEN) return;');

    assert.equal(facts.operations.secretComparison, true);
    assert.ok(facts.riskSignals.some(signal => signal.signal === 'secret_comparison'));
});

test('every risk signal names the syntax and the line that produced it', () => {
    const facts = AstFacts.extract('\n\nfs.writeFileSync(p, data);\n');
    const signal = facts.riskSignals.find(entry => entry.signal === 'disk_write');

    assert.ok(signal, 'no disk_write signal');
    assert.equal(signal.evidence, 'fs.writeFileSync');
    assert.equal(signal.line, 3);
});

test('unparseable source degrades to the text fallback instead of claiming facts', () => {
    const facts = AstFacts.extract('function ( { unbalanced');

    assert.notEqual(facts.ast, true);
    assert.deepEqual(facts.routes, []);
});

test('SentinelIR derives risk and forbidden list from the AST, not from substrings', () => {
    const server = analyzeAt('samples/server.js', `
        const express = require("express");
        const app = express();
        app.get("/health", (req, res) => res.json({ ok: true }));
        app.listen(process.env.PORT);
    `);

    assert.equal(server.summary.hasNetwork, true, 'an Express server does use the network');
    assert.deepEqual(server.forbidden, []);

    const poly = analyzeAt('samples/polynomial.js', 'function evaluate(x) { return x; }');
    assert.equal(poly.risk, 'low');
});

test('the compressed IR carries the facts and omits empty categories', () => {
    const ir = analyzeAt('samples/server.js', `
        const express = require("express");
        const app = express();
        app.post("/webhook", handler);
        app.listen(process.env.PORT);
    `);
    const compressed = SentinelIR.compress(ir);

    assert.equal(compressed.facts.ast, true);
    assert.deepEqual(compressed.facts.routes, ['POST /webhook']);
    assert.deepEqual(compressed.facts.env, ['PORT']);
    assert.equal('filesystem' in (compressed.facts.calls || {}), false);
    assert.equal('dangerous' in compressed.facts, false);
});

test('sources above the tree-sitter direct input limit are still parsed', () => {
    const filler = Array.from(
        { length: 900 },
        (_, index) => `function helper${index}(value) { return value + ${index}; }`
    ).join('\n');

    const content = [
        'const express = require("express");',
        'const app = express();',
        filler,
        'app.get("/late/route", (req, res) => res.json({ ok: true }));',
        'app.listen(process.env.LATE_PORT);'
    ].join('\n');

    assert.ok(content.length > 32 * 1024, 'fixture must exceed the 32 KiB direct input limit');

    const facts = AstFacts.extract(content);
    assert.equal(facts.ast, true, 'a large but valid file must not fall back to no facts');
    assert.deepEqual(facts.routes, ['GET /late/route']);
    assert.deepEqual(facts.env, ['LATE_PORT']);
});
