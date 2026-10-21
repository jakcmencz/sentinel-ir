const test = require('node:test');
const assert = require('node:assert/strict');

const { analyze, analyzeAsync, compress, compressFacts, expandDecision, DEFAULTS } = require('../src/sentinel-ir');

// Initialize the WASM parser before synchronous analysis tests run.
test.before(async () => {
    await require('../src/sentinel-ir').initializeWasm();
});


test('analyzeAsync initializes WASM and analyzes different source types', async () => {
    const cases = [
        {
            source: 'function add(a, b) { return a + b; }',
            expectedRisk: 'low'
        },
        {
            source: 'const cp = require("child_process"); cp.exec("id");',
            expectedRisk: 'critical'
        },
        {
            source: 'function evaluate(value) { return value; }',
            expectedRisk: 'low'
        }
    ];

    for (const item of cases) {
        const ir = await analyzeAsync(item.source);
        assert.equal(ir.facts.ast, true);
    assert.equal(ir.analysisStatus, 'complete');
        assert.equal(ir.risk, item.expectedRisk);
    }
});

const SERVER = `
    const express = require("express");
    const fs = require("fs");
    const app = express();
    app.post("/upload", (req, res) => { fs.writeFileSync("/tmp/x", req.body); res.end(); });
    app.listen(process.env.PORT);
`;

test('analyze without options uses the documented defaults', () => {
    const ir = analyze('module.exports = { add: (a, b) => a + b };');

    assert.equal(ir.target, null);
    assert.equal(ir.pressure, DEFAULTS.pressure);
    assert.equal(ir.confidence, DEFAULTS.confidence);
    assert.equal(ir.budget, DEFAULTS.budget);
    assert.equal(ir.objective, 'general_optimization');
    assert.deepEqual(ir.constraints, ['preserve_api', 'avoid_breaking_changes']);
    assert.equal(ir.risk, 'low');
    assert.deepEqual(ir.forbidden, []);
    assert.equal(ir.facts.ast, true);
    assert.deepEqual(ir.facts.exports, ['add']);
});

test('analyze passes caller-supplied world signals through unchanged', () => {
    const ir = analyze(SERVER, { target: 'src/server.js', pressure: 0.2, confidence: 0.9, budget: 0.5 });

    assert.equal(ir.target, 'src/server.js');
    assert.equal(ir.pressure, 0.2);
    assert.equal(ir.confidence, 0.9);
    assert.equal(ir.budget, 0.5);
});

test('zero is a valid world signal, not a missing one', () => {
    const ir = analyze('const a = 1;', { pressure: 0, confidence: 0, budget: 0 });
    assert.deepEqual([ir.pressure, ir.confidence, ir.budget], [0, 0, 0]);
});

test('invalid world signals fall back to the defaults instead of being clamped', () => {
    for (const bad of ['0.4', NaN, Infinity, -Infinity, -0.1, {}, [], true, null]) {
        const ir = analyze('const a = 1;', { pressure: bad, confidence: bad, budget: bad, consecutiveFailures: bad });
        assert.equal(ir.pressure, DEFAULTS.pressure, `pressure ${String(bad)}`);
        assert.equal(ir.confidence, DEFAULTS.confidence, `confidence ${String(bad)}`);
        assert.equal(ir.budget, DEFAULTS.budget, `budget ${String(bad)}`);
        assert.equal(ir.objective, 'general_optimization', `consecutiveFailures ${String(bad)}`);
    }

    const above = analyze('const a = 1;', { pressure: 1.5, confidence: 2 });
    assert.equal(above.pressure, DEFAULTS.pressure);
    assert.equal(above.confidence, DEFAULTS.confidence);
});

test('a non-object options argument is treated as no options', () => {
    for (const opts of [undefined, null, 'x', 42]) {
        const ir = analyze('const a = 1;', opts);
        assert.equal(ir.pressure, DEFAULTS.pressure);
        assert.equal(ir.target, null);
    }
});

test('consecutiveFailures drives the stability objective and the scope constraint', () => {
    const code = 'module.exports = function id(x) { return x; };';

    assert.equal(analyze(code, { consecutiveFailures: 1 }).objective, 'stability_repair');
    assert.equal(analyze(code, { consecutiveFailures: 1 }).constraints.includes('minimize_scope'), false);
    assert.equal(analyze(code, { consecutiveFailures: 3 }).constraints.includes('minimize_scope'), true);
    // A structural objective wins over the failure count.
    assert.equal(analyze(SERVER, { consecutiveFailures: 5 }).objective, 'filesystem_simplification');
});

test('a target on the crypto path is never below medium risk and keeps security', () => {
    const ir = analyze('const a = 1;', { target: 'lib/crypto/keys.js' });
    assert.equal(ir.risk, 'medium');
    assert.equal(ir.constraints.includes('preserve_security'), true);
});

test('analyze reads structure from the AST', () => {
    const ir = analyze(SERVER, { target: 'src/server.js' });

    assert.equal(ir.objective, 'filesystem_simplification');
    assert.equal(ir.summary.hasNetwork, true);
    assert.equal(ir.summary.hasFilesystem, true);
    assert.equal(ir.summary.hasCrypto, false);
    assert.equal(ir.summary.lines, SERVER.split('\n').length);
    assert.equal(ir.summary.size, SERVER.length);
    assert.deepEqual(ir.facts.routes, ['POST /upload']);
    assert.deepEqual(ir.facts.env, ['PORT']);
});

test('dangerous syntax becomes critical risk and a forbidden list', () => {
    const ir = analyze('const { exec } = require("child_process");\nexec("ls");\neval(input);');

    assert.equal(ir.risk, 'critical');
    assert.deepEqual([...ir.forbidden].sort(), ['child_process', 'eval', 'process_spawn']);
});

test('analyze is stateless: the same input gives the same IR', () => {
    const first = JSON.stringify(analyze(SERVER, { target: 'a.js', pressure: 0.3 }));
    analyze('eval(x)', { pressure: 0.9, consecutiveFailures: 9 });
    const second = JSON.stringify(analyze(SERVER, { target: 'a.js', pressure: 0.3 }));
    assert.equal(first, second);
});

test('compress produces the documented top-level shape', () => {
    const ir = analyze(SERVER, { target: 'src/server.js', pressure: 0.2, confidence: 0.9, budget: 0.1 });
    const compressed = compress(ir);

    assert.deepEqual(Object.keys(compressed), ['analysisStatus', 'language', 'mission', 'world', 'constraints', 'forbidden', 'summary', 'facts']);
    assert.deepEqual(compressed.mission, { target: 'src/server.js', objective: 'filesystem_simplification' });
    assert.deepEqual(compressed.world, { pressure: 0.2, confidence: 0.9, budget: 0.1, risk: ir.risk });
    assert.deepEqual(compressed.constraints, ir.constraints);
    assert.deepEqual(compressed.forbidden, ir.forbidden);
    assert.deepEqual(compressed.summary, ir.summary);
    assert.deepEqual(compressed.facts, compressFacts(ir.facts));
});

test('the compressed IR is smaller than the source it describes', () => {
    const filler = Array.from({ length: 50 }, (_, i) => `function helper${i}(v) { return v * ${i} + 1; }`).join('\n');
    const content = `${SERVER}\n${filler}\nmodule.exports = { app };`;
    const compressed = JSON.stringify(compress(analyze(content, { target: 'src/server.js' })));
    assert.ok(compressed.length < content.length, `${compressed.length} >= ${content.length}`);
});

test('compressFacts keeps only enabled operations and non-empty categories', () => {
    const facts = compressFacts(analyze(SERVER).facts);

    assert.equal(facts.ast, true);
    assert.deepEqual(facts.routes, ['POST /upload']);
    assert.deepEqual(facts.imports, ['express', 'fs']);
    assert.deepEqual(facts.env, ['PORT']);
    assert.deepEqual([...facts.operations].sort(), ['diskWrite', 'inboundHttp']);
    assert.equal('exports' in facts, false);
    assert.equal('dangerous' in facts, false);
    assert.equal('crypto' in facts.calls, false);
    for (const entries of Object.values(facts.calls)) assert.ok(entries.length > 0);
});

test('compressFacts renders risk signals as signal:evidence@line', () => {
    const facts = compressFacts(analyze('const a = 1;\neval(a);').facts);
    assert.deepEqual(facts.riskSignals, ['dynamic_code:eval@2']);
    assert.deepEqual(facts.dangerous, ['eval']);
});

test('compressFacts marks missing or unparsed facts as ast:false with a reason', () => {
    assert.deepEqual(compressFacts(null), {
        ast: false, reason: 'source did not parse; IR fell back to text heuristics'
    });
    assert.deepEqual(compressFacts({ ast: false, error: 'boom' }), { ast: false, reason: 'boom' });
});

test('unparseable source falls back to text heuristics and says so', () => {
    const ir = analyze('function broken( {{{ eval(', { target: 'x.js' });
    const compressed = compress(ir);
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.equal(compressed.analysisStatus, 'incomplete');
assert.equal(compressed.facts.ast, false);
    assert.equal(typeof compressed.facts.reason, 'string');
    assert.equal(compressed.world.risk, 'critical');
    assert.deepEqual(compressed.forbidden, ['eval']);
});

test('expandDecision joins an LLM decision with the IR it was made on', () => {
    const ir = analyze(SERVER, { target: 'src/server.js', pressure: 0.4, confidence: 0.8 });
    const decision = { action: 'PATCH', patch: '--- a\n+++ b\n', reasoning: 'not carried over' };

    assert.deepEqual(expandDecision(decision, ir), {
        action: 'PATCH',
        patch: '--- a\n+++ b\n',
        target: 'src/server.js',
        objective: 'filesystem_simplification',
        confidence: 0.8,
        pressure: 0.4
    });
});

test('expandDecision only copies known fields from the decision', () => {
    const expanded = expandDecision({ action: 'SKIP' }, analyze('const a = 1;'));
    assert.deepEqual(Object.keys(expanded), ['action', 'patch', 'target', 'objective', 'confidence', 'pressure']);
    assert.equal(expanded.patch, undefined);
});
