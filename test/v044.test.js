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

const netPositive = [
  ['inline require axios', 'require("axios").get(u);', 'outbound_http:require("axios").get@1'],
  ['renamed https', 'const net = require("https");\nnet.get(u);', 'outbound_http:net.get@2'],
  ['namespace node:https', 'import * as h from "node:https";\nh.request(u);', 'outbound_http:h.request@2'],
  ['undici named', 'import { request } from "undici";\nawait request(u);', 'outbound_http:request@2'],
  ['undici fetch alias', 'import { fetch as f } from "undici";\nawait f(u);', 'outbound_http:f@2'],
  ['got default call', 'import got from "got";\nawait got(u);', 'outbound_http:got@2'],
  ['inline got call', 'require("got")(u);', 'outbound_http:require("got")@1'],
  ['node-fetch renamed', 'const nf = require("node-fetch");\nnf(u);', 'outbound_http:nf@2'],
  ['axios.create instance', 'const axios = require("axios");\nconst api = axios.create({});\napi.post(u);', 'outbound_http:api.post@3'],
  ['axios default export', 'const ax = require("axios").default;\nax.get(u);', 'outbound_http:ax.get@2'],
  ['http2.connect', 'const h2 = require("http2");\nh2.connect(u);', 'outbound_http:h2.connect@2'],
  ['destructured alias', 'const { get: g } = require("https");\ng(u);', 'outbound_http:g@2'],
  ['then callback', 'import("https").then(h => h.get(u));', 'outbound_http:h.get@1']
];

for (const [name, code, signal] of netPositive) {
  test(`network module binding: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.analysisStatus, 'complete');
    assert.equal(ir.risk, 'medium');
    assert.equal(ir.facts.operations.outboundHttp, true);
    assert.deepEqual(signals(ir), [signal]);
  });
}

const netNegative = [
  ['parameter shadows module', 'const net = require("https");\nfunction f(net) { net.get(u); }'],
  ['unrelated module get', 'const cache = require("./cache");\ncache.get(k);'],
  ['http constants', 'const h = require("http");\nh.METHODS.includes(m);\nconst x = h.STATUS_CODES[200];'],
  ['Map.get', 'const m = new Map();\nm.get(k);'],
  ['axios interceptors', 'const ax = require("axios");\nax.interceptors.request.use(f);'],
  ['non-http package named like a method', 'const { get } = require("lodash");\nget(o, "a");']
];

for (const [name, code] of netNegative) {
  test(`network module binding stays low: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.analysisStatus, 'complete');
    assert.equal(ir.risk, 'low');
    assert.deepEqual(ir.facts.riskSignals, []);
  });
}

test('TypeScript network bindings', () => {
  assert.equal(analyze('import net = require("https");\nnet.get(u as string);', 'a.ts').risk, 'medium');
  assert.equal(analyze('import type { AxiosInstance } from "axios";\ndeclare const api: AxiosInstance;\napi.get(u);', 'a.ts').risk, 'low');
});

const fsExtra = [
  ['remove', 'const fse = require("fs-extra");\nawait fse.remove(p);', 'high', 'destructive_fs:fse.remove@2'],
  ['emptyDirSync via fs name', 'const fs = require("fs-extra");\nfs.emptyDirSync(p);', 'high', 'destructive_fs:fs.emptyDirSync@2'],
  ['named outputFile', 'import { outputFile } from "fs-extra";\nawait outputFile(p, d);', 'medium', 'disk_write:outputFile@2'],
  ['writeJson', 'const fse = require("fs-extra");\nfse.writeJsonSync(p, o);', 'medium', 'disk_write:fse.writeJsonSync@2'],
  ['move', 'import fse from "fs-extra";\nawait fse.move(a, b);', 'medium', 'disk_write:fse.move@2']
];

for (const [name, code, risk, signal] of fsExtra) {
  test(`fs-extra: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.risk, risk);
    assert.deepEqual(signals(ir), [signal]);
  });
}

test('fs-extra reads stay low', () => {
  const ir = analyze('const fse = require("fs-extra");\nfse.readJsonSync(p);\nfse.pathExistsSync(p);');
  assert.equal(ir.risk, 'low');
  assert.equal(ir.facts.operations.diskRead, true);
});

const thenPositive = [
  ['arrow param', 'import("fs").then(m => m.writeFileSync(p));', 'medium', 'disk_write:m.writeFileSync@1'],
  ['destructured param', 'import("node:fs").then(({ rmSync }) => rmSync(p));', 'high', 'destructive_fs:rmSync@1'],
  ['function expression', 'import("fs").then(function (m) {\n  m.unlinkSync(p);\n});', 'high', 'destructive_fs:m.unlinkSync@2'],
  ['promises submodule', 'import("fs").then(({ promises }) => promises.rm(p));', 'high', 'destructive_fs:promises.rm@1']
];

for (const [name, code, risk, signal] of thenPositive) {
  test(`import().then callback: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.risk, risk);
    assert.deepEqual(signals(ir), [signal]);
    assert.ok(!ir.facts.calls.filesystem.some(c => c.endsWith('.then')));
  });
}

test('import().then callback: TypeScript and child_process', () => {
  assert.equal(analyze('import("fs").then((m: any) => m.writeFileSync(p));', 'a.ts').risk, 'medium');
  assert.deepEqual(signals(analyze('import("child_process").then(cp => cp.exec(c));')),
    ['child_process_import:import(child_process)@1', 'process_spawn:cp.exec@1']);
});

test('import().then callback stays low when the module or binding does not match', () => {
  for (const code of [
    'import("./db").then(m => m.writeFileSync(p));',
    'import("fs").then(m => { function g(m) { m.rmSync(p); } });',
    'import("fs").then(handler);',
    'load("fs").then(m => m.rmSync(p));'
  ]) {
    const ir = analyze(code);
    assert.equal(ir.risk, 'low', code);
    assert.deepEqual(ir.facts.riskSignals, [], code);
  }
});

test('text fallback flags fs-extra deletes and HTTP module loads in unparseable code', () => {
  for (const [code, risk] of [
    ['const fse = require("fs-extra");\nfse.removeSync(p);\nif (', 'high'],
    ['fse.emptyDir(p);\nif (', 'high'],
    ['fs.remove(p);\nif (', 'high'],
    ['const net = require("https");\nnet.get(u);\nif (', 'medium'],
    ['import got from "got";\nif (', 'medium'],
    ['const x = list.remove(i);\nif (', 'low'],
    ['const x = require("httpx-lite");\nif (', 'low']
  ]) {
    const ir = analyze(code, 'a.js');
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.equal(ir.risk, risk, code);
  }
});

const netClientMethods = [
  ['got.paginate', 'import got from "got";\nfor await (const x of got.paginate(u)) {}', 'outbound_http:got.paginate@2'],
  ['got.paginate.all', 'import got from "got";\nawait got.paginate.all(u);', 'outbound_http:got.paginate.all@2'],
  ['got.stream', 'const g = require("got");\ng.stream(u);', 'outbound_http:g.stream@2'],
  ['superagent.del', 'const sa = require("superagent");\nsa.del(u);', 'outbound_http:sa.del@2'],
  ['superagent agent instance', 'const sa = require("superagent");\nconst agent = sa.agent();\nagent.get(u);', 'outbound_http:agent.get@3'],
  ['axios.postForm', 'import axios from "axios";\nawait axios.postForm(u, d);', 'outbound_http:axios.postForm@2'],
  ['axios.options', 'const ax = require("axios");\nax.options(u);', 'outbound_http:ax.options@2'],
  ['needle.request', 'const n = require("needle");\nn.request("get", u, null, cb);', 'outbound_http:n.request@2'],
  ['undici.upgrade', 'import { upgrade } from "undici";\nawait upgrade(u);', 'outbound_http:upgrade@2']
];

for (const [name, code, signal] of netClientMethods) {
  test(`HTTP client method: ${name}`, () => {
    const ir = analyze(code);
    assert.equal(ir.risk, 'medium');
    assert.deepEqual(signals(ir), [signal]);
  });
}

test('HTTP client helpers are not requests', () => {
  for (const code of [
    'const ax = require("axios");\nax.isAxiosError(e);\nax.isCancel(e);\nax.CancelToken.source();\nax.mergeConfig(a, b);',
    'import got from "got";\ngot.mergeOptions(a, b);',
    'import { setGlobalDispatcher, getGlobalDispatcher } from "undici";\nsetGlobalDispatcher(d);\ngetGlobalDispatcher();',
    'const n = require("needle");\nn.defaults({ timeout: 1 });',
    'const g = require("got");\nconst list = [];\nlist.paginate.all(u);',
    'const { isAxiosError, isCancel: cancelled } = require("axios");\nisAxiosError(e);\ncancelled(e);',
    'import { Agent, MockAgent as M } from "undici";\nAgent(o);\nM();'
  ]) {
    const ir = analyze(code);
    assert.equal(ir.risk, 'low', code);
    assert.deepEqual(ir.facts.riskSignals, [], code);
  }
});
