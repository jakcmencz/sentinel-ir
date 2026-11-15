const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm({ languages: ['javascript', 'typescript', 'tsx', 'python', 'rust'] });
});

test('unknown target extension is unsupported, not JavaScript', async () => {
  for (const target of ['x.rb', 'main.go', 'README.md', 'dir/App.vue']) {
    const ir = await SentinelIR.analyzeAsync('system("ls")\neval(x)\n', { target });
    assert.equal(ir.analysisStatus, 'incomplete', target);
    assert.equal(ir.language, 'unknown');
    assert.match(ir.facts.error, /^unsupported file type: \.\w+ \(supported: \.js /);
    assert.equal(SentinelIR.compress(ir).facts.ast, false);
  }
});

test('no extension and known extensions still pick a grammar', async () => {
  assert.equal((await SentinelIR.analyzeAsync('eval(1)', { target: 'Makefile' })).language, 'javascript');
  assert.equal((await SentinelIR.analyzeAsync('eval(1)')).analysisStatus, 'complete');
  assert.equal((await SentinelIR.analyzeAsync('export declare const x: number;', { target: 'a.d.ts' })).language, 'typescript');
  assert.equal((await SentinelIR.analyzeAsync('x = 1', { target: 'x.rb', language: 'python' })).analysisStatus, 'complete');
});

const positions = [
  ['rust', 'fn main() {\n    let x = std::process::Command::new("sh";\n', { line: 2, column: 39, kind: 'unclosed', expected: ')' }],
  ['tsx', 'export default () => <div>{x</div>;\n', { line: 1, column: 27, kind: 'unclosed', expected: '}' }],
  ['javascript', 'const cp = require("child_process");\nfunction f( {\n  cp.exec("x");\n', { line: 2, column: 13, kind: 'unclosed', expected: '}' }]
];

for (const [language, code, expected] of positions) {
  test(`${language}: an error region wrapping the file points at the bracket`, () => {
    const ir = SentinelIR.analyze(code, { language });
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.deepEqual(ir.facts.parseError, expected);
  });
}

test('broken Python and Rust list what the text fallback saw in forbidden', () => {
  const py = SentinelIR.analyze('import os, subprocess, pickle\nos.system("x")\nsubprocess.run("y")\npickle.loads(b)\nshutil.rmtree(d)\ndef f(:\n', { language: 'python' });
  assert.equal(py.analysisStatus, 'incomplete');
  assert.equal(py.risk, 'critical');
  assert.deepEqual(py.forbidden.sort(), ['child_process', 'destructive_fs', 'process_spawn', 'unsafe_deserialization']);

  const rs = SentinelIR.analyze('use std::process::Command;\nfn main() { unsafe {}; Command::new("sh"); std::fs::remove_file("x");\n', { language: 'rust' });
  assert.equal(rs.analysisStatus, 'incomplete');
  assert.equal(rs.risk, 'critical');
  assert.deepEqual(rs.forbidden.sort(), ['child_process', 'destructive_fs', 'native_code', 'process_spawn']);

  const clean = SentinelIR.analyze('def f(:\n    return 1\n', { language: 'python' });
  assert.deepEqual(clean.forbidden, []);
});

test('TypeScript declarations ship with the package', () => {
  const pkg = require('../package.json');
  assert.equal(pkg.types, 'src/sentinel-ir.d.ts');
  assert.ok(pkg.files.includes(pkg.types));
  const dts = fs.readFileSync(path.join(__dirname, '..', pkg.types), 'utf8');
  for (const name of Object.keys(SentinelIR)) {
    assert.match(dts, new RegExp(`export (function|const) ${name}\\b`), name);
  }
});
