// Every native API written in every supported way: a generated matrix instead
// of hand-picked cases, so a new access form is checked against all APIs.
const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeAsync } = require('../src/sentinel-ir');

async function wrong(cases) {
    const out = [];
    for (const [language, source, expected] of cases) {
        const ir = await analyzeAsync(source, { language });
        const native = ir.facts.operations.nativeCode === true;
        if (ir.analysisStatus !== 'complete' || native !== expected || (expected && ir.risk !== 'critical')) {
            out.push(`${expected ? 'missed' : 'false positive'} [${language}] ${source.replace(/\n/g, ' ; ')}`);
        }
    }
    return out;
}

// [first name, rest of the expression]
const PY_APIS = [
    ['CDLL', '("libc.so.6").system(b"id")'],
    ['WinDLL', '("kernel32").VirtualAlloc(0, 1, 0x3000, 0x40)'],
    ['cdll', '.LoadLibrary("./x.so")'],
    ['windll', '.kernel32.WriteProcessMemory(h, a, b, n, None)'],
    ['pythonapi', '.Py_IncRef(o)'],
    ['memmove', '(dst, src, 8)'],
    ['string_at', '(0x1000, 8)'],
    ['cast', '(0x1000, P)'],
    ['CFUNCTYPE', '(None)(0x41414141)']
];
const PY_FORMS = [
    (h, r) => `import ctypes\nctypes.${h}${r}`,
    (h, r) => `import ctypes as c\nc.${h}${r}`,
    (h, r) => `from ctypes import ${h}\n${h}${r}`,
    (h, r) => `from ctypes import ${h} as zz\nzz${r}`,
    (h, r) => `from ctypes import *\n${h}${r}`,
    (h, r) => `import ctypes\ngetattr(ctypes, "${h}")${r}`,
    (h, r) => `import ctypes\nn = "${h}"\ngetattr(ctypes, n)${r}`,
    (h, r) => `c = __import__("ctypes")\nc.${h}${r}`,
    (h, r) => `import importlib\nc = importlib.import_module("ctypes")\nc.${h}${r}`,
    (h, r) => `import sys\nsys.modules["ctypes"].${h}${r}`,
    (h, r) => `import ctypes\nvars(ctypes)["${h}"]${r}`,
    (h, r) => `import ctypes\nctypes.__dict__["${h}"]${r}`,
    (h, r) => `import ctypes\nf = ctypes.${h}\nf${r}`,
    (h, r) => `def g():\n    import ctypes\n    return ctypes.${h}${r}`,
    (h, r) => `import ctypes\nclass K:\n    def m(self):\n        return ctypes.${h}${r}`,
    (h, r) => `x = ctypes.${h}${r}`
];

const PROCESS_APIS = [['dlopen', '(module, "x.node")'], ['binding', '("spawn_sync")'], ['_linkedBinding', '("x")']];
const PROCESS_FORMS = [
    (m, r) => `process.${m}${r}`,
    (m, r) => `process["${m}"]${r}`,
    (m, r) => `process?.${m}${r}`,
    (m, r) => `const p = process; p.${m}${r}`,
    (m, r) => `const { ${m} } = process; ${m}${r}`,
    (m, r) => `const { ${m}: zz } = process; zz${r}`,
    (m, r) => `globalThis.process.${m}${r}`,
    (m, r) => `globalThis["process"].${m}${r}`,
    (m, r) => `require("process").${m}${r}`,
    (m, r) => `const { ${m} } = require("node:process"); ${m}${r}`,
    (m, r) => `import p from "node:process"; p.${m}${r}`,
    (m, r) => `import * as p from "process"; p.${m}${r}`,
    (m, r) => `import { ${m} as zz } from "node:process"; zz${r}`,
    (m, r) => `process.${m}.call(process, ...[1])`,
    (m, r) => `process.${m}.apply(process, [1])`,
    (m, r) => `Reflect.apply(process.${m}, process, [1])`,
    (m, r) => `(0, process.${m})${r}`,
    (m, r) => `const f = process.${m}; f${r}`,
    (m, r) => `const n = "${m}"; process[n]${r}`,
    (m, r) => `function g() { return process.${m}${r}; }`,
    (m, r) => `const g = () => process.${m}${r};`,
    (m, r) => `class K { m() { return process.${m}${r}; } }`
];

// [module, export, rest]
const FFI_APIS = [['koffi', 'load', '("libc.so.6")'], ['ffi-napi', 'Library', '("libc", {})'], ['bun:ffi', 'dlopen', '("x", {})'], ['@napi-ffi/ffi-napi', 'Library', '("x", {})']];
const FFI_FORMS = [
    (s, e, r) => `const k = require("${s}"); k.${e}${r}`,
    (s, e, r) => `const { ${e} } = require("${s}"); ${e}${r}`,
    (s, e, r) => `const { ${e}: zz } = require("${s}"); zz${r}`,
    (s, e, r) => `require("${s}").${e}${r}`,
    (s, e, r) => `import k from "${s}"; k.${e}${r}`,
    (s, e, r) => `import * as k from "${s}"; k.${e}${r}`,
    (s, e, r) => `import { ${e} } from "${s}"; ${e}${r}`,
    (s, e, r) => `import { ${e} as zz } from "${s}"; zz${r}`,
    (s, e, r) => `const k = await import("${s}"); k.${e}${r}`,
    (s, e, r) => `const k = require("${s}"); k["${e}"]${r}`,
    (s, e, r) => `const k = require("${s}"); new k.${e}${r}`,
    (s, e, r) => `const k = require("${s}"); function g() { return k.${e}${r}; }`
];

const LANGUAGES = ['javascript', 'typescript', 'tsx'];

test('matrix: every ctypes API in every access form is critical', async () => {
    const cases = PY_APIS.flatMap(([h, r]) => PY_FORMS.map(form => ['python', form(h, r), true]));
    assert.deepEqual(await wrong(cases), [], `${cases.length} cases`);
});

test('matrix: every process native method in every access form is critical (JS, TS, TSX)', async () => {
    const cases = PROCESS_APIS.flatMap(([m, r]) => PROCESS_FORMS.flatMap(form =>
        LANGUAGES.map(language => [language, form(m, r), true])));
    assert.deepEqual(await wrong(cases), [], `${cases.length} cases`);
});

test('matrix: every FFI module export in every import form is critical (JS, TS, TSX)', async () => {
    const cases = FFI_APIS.flatMap(([s, e, r]) => FFI_FORMS.flatMap(form =>
        LANGUAGES.map(language => [language, form(s, e, r), true])));
    assert.deepEqual(await wrong(cases), [], `${cases.length} cases`);
});

test('matrix: the same forms with a harmless member are not native code', async () => {
    const cases = [
        ...PY_FORMS.map(form => ['python', form('sizeof', '(ctypes.c_int)'), false]),
        ...PY_FORMS.map(form => ['python', form('c_uint32', '(7)'), false]),
        ...PROCESS_FORMS.filter((_, i) => ![13, 14, 15, 16, 18].includes(i)).flatMap(form =>
            LANGUAGES.map(language => [language, form('cwd', '()'), false])),
        ...FFI_FORMS.flatMap(form => LANGUAGES.map(language => [language, form('./lib.js', 'load', '("x")'), false])),
        ['python', 'import ctypes\nt = getattr(ctypes, "c_" + kind)', false],
        ['python', 'import ctypes\nt = getattr(ctypes, f"c_{kind}")(0)', false],
        ['javascript', 'function f(process) { process.dlopen(1); process[n](); }', false],
        ['javascript', 'const k = require("koffi"); function g(k) { return k.load("x"); }', false]
    ];
    assert.deepEqual(await wrong(cases), [], `${cases.length} cases`);
});

test('unparseable source still reports native loaders and FFI modules', async () => {
    for (const [language, source, expected] of [
        ['python', 'from ctypes import CDLL\nCDLL("x")\nclass (', true],
        ['python', 'import cffi\nffi = cffi.FFI()\nffi.dlopen(None)\n)))', true],
        ['javascript', 'const k = require("koffi"); k.load("x");\nlet = = ;', true],
        ['javascript', 'require("./build/Release/addon.node");\n}}}', true],
        ['typescript', 'import koffi from "koffi";\nkoffi.load("x");\nlet a: = 1;', true],
        ['python', 'from ctypes import c_int, sizeof\nsizeof(c_int)\nclass (', false],
        ['javascript', 'const fs = require("fs");\n}}}', false]
    ]) {
        const ir = await analyzeAsync(source, { language });
        assert.equal(ir.analysisStatus, 'incomplete', source);
        assert.equal(ir.forbidden.includes('native_code'), expected, source);
    }
});
