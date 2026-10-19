const test = require('node:test');
const assert = require('node:assert/strict');

const AstFacts = require('../src/ast-facts');
const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm();
});

const cases = [
  [
    'default import shadows global Function',
    'import Function from "safe-module"; Function("text");',
    false
  ],
  [
    'renamed import shadows global Function',
    'import { run as Function } from "safe-module"; Function("text");',
    false
  ],
  [
    'local globalThis.Function is not the global constructor',
    'const globalThis = { Function: x => x }; globalThis.Function("text");',
    false
  ],
  [
    'local globalThis.eval is not global eval',
    'const globalThis = { eval: x => x }; globalThis.eval("text");',
    false
  ],
  [
    'local globalThis does not make its constructor global',
    'const globalThis = { Function: x => x }; new globalThis.Function("text");',
    false
  ],
  [
    'computed local globalThis.eval is not global eval',
    'const globalThis = { eval: x => x }; globalThis["eval"]("text");',
    false
  ],
  [
    'object method named Function does not shadow the global',
    'const obj = { Function() { Function("return 1"); } };',
    true
  ],
  [
    'class method named Function does not shadow the global',
    'class Example { Function() { Function("return 1"); } }',
    true
  ],
  [
    'object method named eval does not shadow the global',
    'const obj = { eval() { eval("code"); } };',
    true
  ],
  [
    'real global Function remains critical',
    'Function("return 1");',
    true
  ],
  [
    'real globalThis.Function remains critical',
    'globalThis.Function("return 1");',
    true
  ],
  [
    'real globalThis.eval remains critical',
    'globalThis.eval("code");',
    true
  ]
];

for (const [name, source, expected] of cases) {
  test(`scope regression: ${name}`, () => {
    const facts = AstFacts.extract(source);

    assert.equal(facts.ast, true, 'source must parse successfully');
    assert.equal(
      facts.operations.dynamicEval,
      expected,
      'dynamic execution must match the resolved reference'
    );
    assert.equal(
      AstFacts.riskOf(facts),
      expected ? 'critical' : 'low'
    );
  });
}
