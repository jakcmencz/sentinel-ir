const test = require('node:test');
const assert = require('node:assert/strict');

const AstFacts = require('../src/ast-facts');
const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm();
});

test('indirect global eval through comma operator is detected', () => {
  const facts = AstFacts.extract('(0, eval)(input);');

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.dynamicEval, true);
  assert.ok(facts.riskSignals.some(item => item.signal === 'dynamic_code'));
  assert.equal(AstFacts.riskOf(facts), 'critical');
});

test('direct alias of child_process method is detected', () => {
  const facts = AstFacts.extract(`
    const cp = require("child_process");
    const run = cp.execSync;
    run("example");
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.processSpawn, true);
  assert.ok(facts.riskSignals.some(item => item.signal === 'process_spawn'));
});

test('parameter shadowing a spawn alias is not a process spawn', () => {
  const facts = AstFacts.extract(`
    const { execSync: run } = require("child_process");

    function helper(run) {
      run("ordinary");
    }
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.processSpawn, false);
});

test('bracket access to a secret environment key emits a warning', () => {
  const facts = AstFacts.extract(`
    const key = process.env["API_KEY"];
  `);

  assert.equal(facts.ast, true);
  assert.ok(facts.env.includes('API_KEY'));
  assert.ok(
    facts.riskSignals.some(
      item =>
        item.signal === 'secret_access' &&
        item.evidence === 'process.env.API_KEY'
    )
  );
});

test('static template literal property is recognized', () => {
  const facts = AstFacts.extract('globalThis[`eval`](input);');

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.dynamicEval, true);
});

test('interpolated template literal is not assumed to be a fixed eval key', () => {
  const facts = AstFacts.extract(
    'globalThis[`eval${suffix}`](input);'
  );

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.dynamicEval, false);
});

test('indirect eval does not flag a shadowed eval binding', () => {
  const facts = AstFacts.extract(`
    function helper(eval) {
      (0, eval)(input);
    }
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.dynamicEval, false);
});

test('local lexical binding shadows a spawn alias', () => {
  const facts = AstFacts.extract(`
    const cp = require("child_process");
    const run = cp.execSync;

    function helper() {
      const run = value => value;
      run("ordinary");
    }
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.processSpawn, false);
});

test('local cp parameter shadows a module binding', () => {
  const facts = AstFacts.extract(`
    const cp = require("child_process");

    function helper(cp) {
      cp.execSync("ordinary");
    }
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.processSpawn, false);
});

test('process spawn detection follows a chain of local aliases', () => {
  const facts = AstFacts.extract(`
    const cp = require("child_process");
    const run = cp.execSync;
    const runAgain = run;
    runAgain("example");
  `);

  assert.equal(facts.ast, true);
  assert.equal(facts.operations.processSpawn, true);
  assert.ok(facts.riskSignals.some(
    item => item.signal === 'process_spawn'
  ));
});
