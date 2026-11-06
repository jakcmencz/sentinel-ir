const test = require('node:test');
const assert = require('node:assert/strict');

const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm({ languages: ['javascript', 'typescript', 'tsx'] });
});

const analyze = (code, target = 'a.mjs') => SentinelIR.analyze(code, { target });
const signals = ir => ir.facts.riskSignals.map(s => `${s.signal}:${s.evidence}@${s.line}`);

const positive = [
  ['inline require', 'require("fs").writeFileSync(p, 1);', 'medium', 'disk_write:require("fs").writeFileSync@1'],
  ['inline node:fs delete', 'require("node:fs").unlinkSync(p);', 'high', 'destructive_fs:require("node:fs").unlinkSync@1'],
  ['inline subscript', 'require("fs")["writeFileSync"](p, 1);', 'medium', 'disk_write:require("fs").writeFileSync@1'],
  ['inline await import', '(await import("fs")).writeFileSync(p, 1);', 'medium', 'disk_write:(await import("fs")).writeFileSync@1'],
  ['renamed module', 'const files = require("fs");\nfiles.writeFileSync(p, 1);', 'medium', 'disk_write:files.writeFileSync@2'],
  ['destructured', 'const { writeFileSync } = require("fs");\nwriteFileSync(p, 1);', 'medium', 'disk_write:writeFileSync@2'],
  ['destructured alias', 'const { unlinkSync: del } = require("fs");\ndel(p);', 'high', 'destructive_fs:del@2'],
  ['string key', 'const { "writeFile": wf } = require("fs");\nwf(p);', 'medium', 'disk_write:wf@2'],
  ['named import fs/promises', 'import { writeFile } from "fs/promises";\nawait writeFile(p, 1);', 'medium', 'disk_write:writeFile@2'],
  ['namespace import', 'import * as nodefs from "node:fs";\nnodefs.rmSync(p);', 'high', 'destructive_fs:nodefs.rmSync@2'],
  ['default import', 'import disk from "fs";\ndisk.appendFileSync(p, 1);', 'medium', 'disk_write:disk.appendFileSync@2'],
  ['require().promises', 'const w = require("fs").promises;\nw.unlink(p);', 'high', 'destructive_fs:w.unlink@2'],
  ['destructured promises', 'const { promises: p2 } = require("fs");\np2.rm(p);', 'high', 'destructive_fs:p2.rm@2'],
  ['nested destructured promises', 'const { promises: { rm } } = require("fs");\nawait rm(p);', 'high', 'destructive_fs:rm@2'],
  ['inline member alias', 'const w = require("fs").writeFileSync;\nw(p, 1);', 'medium', 'disk_write:w@2'],
  ['module member alias', 'const f = require("fs");\nconst del = f.unlinkSync;\ndel(p);', 'high', 'destructive_fs:del@3'],
  ['function alias chain', 'const { rmSync } = require("fs");\nconst r2 = rmSync;\nr2(p);', 'high', 'destructive_fs:r2@3'],
  ['used in nested function', 'const { rmSync } = require("fs");\nfunction g() { rmSync(p); }', 'high', 'destructive_fs:rmSync@2']
];

for (const [name, code, risk, signal] of positive) {
  test(`fs module binding: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.analysisStatus, 'complete');
    assert.equal(ir.risk, risk);
    assert.deepEqual(signals(ir), [signal]);
  });
}

const negative = [
  ['parameter shadows imported function', 'const { writeFileSync } = require("fs");\nfunction f(writeFileSync) { writeFileSync(p); }'],
  ['module bound in another block', '{ const files = require("fs"); }\nfiles.writeFileSync(p);'],
  ['inner let shadows module', 'const files = require("fs");\nfunction g() { let files = db; files.rmSync(p); }'],
  ['local function shadows import', 'import { writeFile } from "fs/promises";\nfunction h() { function writeFile() {} writeFile(p); }'],
  ['unrelated module with fs-like methods', 'const db = require("./db");\ndb.writeFileSync(p);\ndb.rmSync(p);'],
  ['unrelated package', 'const store = require("fs-like-store");\nstore.writeFileSync(p);'],
  ['own function named writeFileSync', 'function writeFileSync() {}\nwriteFileSync(p);'],
  ['read only', 'const { readFileSync } = require("fs");\nreadFileSync(p);']
];

for (const [name, code] of negative) {
  test(`fs module binding stays low: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.analysisStatus, 'complete');
    assert.equal(ir.risk, 'low');
    assert.deepEqual(ir.facts.riskSignals, []);
  });
}

test('read through a renamed fs module counts as a filesystem read', () => {
  const ir = analyze('const files = require("fs");\nfiles.readFileSync(p);');
  assert.equal(ir.facts.operations.diskRead, true);
  assert.deepEqual(ir.facts.calls.filesystem, ['files.readFileSync']);
});

test('TypeScript and TSX fs bindings', () => {
  assert.equal(analyze('import files = require("fs");\nfiles.unlinkSync(p as string);', 'a.ts').risk, 'high');
  assert.equal(analyze('(require("fs") as typeof import("fs")).writeFileSync(p!, "x");', 'a.ts').risk, 'medium');
  assert.equal(analyze('import { rmSync } from "node:fs";\nexport const C = () => <button onClick={() => rmSync(p)} />;', 'a.tsx').risk, 'high');
  assert.equal(analyze('import type { writeFileSync } from "fs";\ndeclare const writeFileSync: any;\nwriteFileSync(p);', 'a.ts').risk, 'low');
  assert.equal(analyze('import { type rmSync } from "fs";\nrmSync(p);', 'a.ts').risk, 'low');
});

test('text fallback flags fs deletes and writes in unparseable code', () => {
  for (const code of [
    'const files = require("fs");\nfiles.rmSync(p);\nif (',
    'const { rmdirSync } = require("fs");\nrmdirSync(p);\nif (',
    'fs.promises.rm(p);\nif (',
    'fs.createWriteStream(p);\nif ('
  ]) {
    const ir = analyze(code, 'a.js');
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.equal(ir.risk, 'high', code);
  }
  assert.equal(analyze('const x = items.rm;\nif (', 'a.js').risk, 'low');
});

test('child_process bindings are unchanged by the shared binding walker', () => {
  assert.equal(analyze('const { exec: run } = require("child_process");\nrun(cmd);').risk, 'critical');
  assert.equal(analyze('const { writeFileSync: run } = require("fs");\nrun(cmd);').risk, 'medium');
  assert.equal(analyze('const { exec } = require("fs");\nexec(cmd);').risk, 'low');
});
