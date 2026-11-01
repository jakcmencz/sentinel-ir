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

const staticChildProcessImportCases = [
    ['namespace import', 'import * as cp from "node:child_process";'],
    ['named import', 'import { execSync } from "node:child_process";'],
    ['renamed import', 'import { execSync as run } from "node:child_process";'],
    ['side-effect import', 'import "node:child_process";'],
    ['unprefixed import', 'import { execSync } from "child_process";']
];

for (const [name, source] of staticChildProcessImportCases) {
    test(`static ES ${name} records child_process capability`, () => {
        const facts = AstFacts.extract(source);

        assert.equal(facts.ast, true, 'source must parse successfully');
        assert.equal(
            facts.operations.childProcess,
            true,
            'static import should register child_process capability'
        );
        assert.equal(
            facts.operations.processSpawn,
            false,
            'import alone does not prove a process was spawned'
        );
        assert.ok(
            facts.dangerous.includes('child_process'),
            'dangerous capabilities should include child_process'
        );
        assert.equal(
            AstFacts.riskOf(facts),
            'critical',
            'risk should follow the documented child_process policy'
        );
        assert.ok(
            facts.riskSignals.some(s => s.signal === 'child_process_import'),
            'the capability import should have a risk signal'
        );
    });
}

const dynamicExecutionRegressionCases = [
    ['globalThis.eval()', 'globalThis.eval(input);'],
    ['computed globalThis eval', 'globalThis["eval"](input);'],
    ['Function() without new', 'Function("return 1");'],
    ['globalThis.Function constructor', 'new globalThis.Function("return 1");'],
    ['computed globalThis Function constructor', 'new globalThis["Function"]("return 1");']
];

for (const [name, source] of dynamicExecutionRegressionCases) {
    test(`dynamic code detection covers ${name}`, () => {
        const facts = AstFacts.extract(source);

        assert.equal(facts.ast, true, 'source must parse successfully');
        assert.equal(
            facts.operations.dynamicEval,
            true,
            'dynamic code execution must be identified'
        );
        assert.equal(AstFacts.riskOf(facts), 'critical');
        assert.ok(
            facts.riskSignals.some(signal => signal.signal === 'dynamic_code'),
            'dynamic code must have a risk signal'
        );
    });
}

test('computed child_process method detects actual process spawning', () => {
    const facts = AstFacts.extract(
        'const cp = require("child_process"); cp["execSync"]("example");'
    );

    assert.equal(facts.ast, true);
    assert.equal(facts.operations.childProcess, true);
    assert.equal(
        facts.operations.processSpawn,
        true,
        'computed execSync call must be identified as process spawning'
    );
    assert.ok(facts.dangerous.includes('process_spawn'));
    assert.equal(AstFacts.riskOf(facts), 'critical');
    assert.ok(
        facts.riskSignals.some(signal => signal.signal === 'process_spawn')
    );
});

test('an ordinary object method named eval is not dynamic code by itself', () => {
    const facts = AstFacts.extract(
        'const parser = { eval(input) { return input; } }; parser.eval(input);'
    );

    assert.equal(facts.ast, true);
    assert.equal(
        facts.operations.dynamicEval,
        false,
        'a method merely named eval must not be misclassified'
    );
});

const shadowingRegressionCases = [
    ['global Function call', 'Function("return 1");', true],
    ['global Function constructor', 'new Function("return 1");', true],
    ['explicit global Function with local shadow',
        'const Function = value => value; new globalThis.Function("return 1");', true],
    ['local Function variable',
        'const Function = value => value; Function("ordinary text");', false],
    ['Function parameter',
        'function run(Function) { return Function("ordinary text"); }', false],
    ['local Function constructor name',
        'function run(Function) { return new Function("ordinary text"); }', false],
    ['local eval variable',
        'const eval = value => value; eval("ordinary text");', false],
    ['eval parameter',
        'function run(eval) { return eval(input); }', false],
    ['explicit global eval despite local shadow',
        'const eval = value => value; globalThis.eval(input);', true]
];

for (const [name, source, expected] of shadowingRegressionCases) {
    test(`shadowing: ${name}`, () => {
        const facts = AstFacts.extract(source);

        assert.equal(facts.ast, true, 'source must parse successfully');
        assert.equal(
            facts.operations.dynamicEval,
            expected,
            'dynamic execution should match the resolved kind of reference'
        );
        assert.equal(
            AstFacts.riskOf(facts),
            expected ? 'critical' : 'low'
        );
    });
}

const evalAliasControlFlowRegressionCases = [
    [
        'switch fallthrough carries an eval alias into the next case',
        `
            let execute = function (x) { return x; };
            switch (mode) {
                case 0:
                    execute = eval;
                case 1:
                    execute("x");
                    break;
                default:
                    execute = function (x) { return x; };
            }
        `,
        true
    ],
    [
        'switch break prevents an eval alias reaching the next case',
        `
            let execute = function (x) { return x; };
            switch (mode) {
                case 0:
                    execute = eval;
                    break;
                case 1:
                    execute("x");
                    break;
            }
        `,
        false
    ],
    [
        'a later switch case overwrites the alias before the call',
        `
            let execute = function (x) { return x; };
            switch (mode) {
                case 0:
                    execute = eval;
                case 1:
                    execute = function (x) { return x; };
                    break;
                case 2:
                    execute("x");
                    break;
            }
        `,
        false
    ],
    [
        'eval alias assigned before throw is visible in catch',
        `
            let execute = function (x) { return x; };
            try {
                execute = eval;
                throw new Error("test");
            } catch (error) {
                execute("x");
            }
        `,
        true
    ],
    [
        'throw before eval alias assignment does not taint catch',
        `
            let execute = function (x) { return x; };
            try {
                throw new Error("test");
                execute = eval;
            } catch (error) {
                execute("x");
            }
        `,
        false
    ],
    [
        'assignment in try without a later explicit throw does not taint catch',
        `
            let execute = function (x) { return x; };
            try {
                execute = eval;
            } catch (error) {
                execute("x");
            }
        `,
        false
    ]
];

for (const [name, source, expected] of evalAliasControlFlowRegressionCases) {
    test(`eval alias control-flow regression: ${name}`, () => {
        const facts = AstFacts.extract(source);

        assert.equal(facts.ast, true, 'source must parse successfully');
        assert.equal(
            Boolean(facts.operations.dynamicEval),
            expected,
            'dynamic eval detection must match the expected control flow'
        );
        assert.equal(
            AstFacts.riskOf(facts),
            expected ? 'critical' : 'low'
        );

        assert.equal(
            facts.riskSignals.some(signal => signal.signal === 'dynamic_code'),
            expected,
            'dynamic code risk signal must agree with the expected result'
        );
    });
}
