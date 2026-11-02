const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeAsync, compress } = require('../src/sentinel-ir');

const native = ir => ir.facts.riskSignals.filter(s => s.signal === 'native_code').map(s => s.evidence);

test('Python: loading or calling native code through ctypes / cffi is critical', async () => {
    const cases = {
        'import ctypes\nlibc = ctypes.CDLL("libc.so.6")\nlibc.system(b"rm -rf /tmp/x")': ['ctypes.CDLL', 'ctypes.CDLL().system'],
        'from ctypes import CDLL as load\nload(None).puts(b"x")': ['ctypes.CDLL().puts', 'ctypes.CDLL'],
        'import ctypes\nctypes.cdll.LoadLibrary("./evil.so")': ['ctypes.cdll.LoadLibrary'],
        'import ctypes\nctypes.cdll.LoadLibrary("libobjc.dylib").objc_getClass(b"NSApp")': ['ctypes.cdll.LoadLibrary', 'ctypes.cdll.LoadLibrary().objc_getClass'],
        'import ctypes\nv = ctypes.CDLL(None).gnu_get_libc_version().decode()': ['ctypes.CDLL', 'ctypes.CDLL().gnu_get_libc_version'],
        'from ctypes import windll\nk = windll.kernel32\nk.VirtualAlloc(0, 4096, 0x3000, 0x40)': ['ctypes.windll.kernel32.VirtualAlloc'],
        'import ctypes\nctypes.WinDLL("user32")': ['ctypes.WinDLL'],
        'import ctypes\nctypes.pythonapi.PyFrame_LocalsToFast(f, 0)': ['ctypes.pythonapi.PyFrame_LocalsToFast'],
        'import ctypes\nctypes.memmove(dst, src, 5)': ['ctypes.memmove'],
        'import ctypes\nctypes.string_at(0x1000, 64)': ['ctypes.string_at'],
        'import ctypes\np = ctypes.cast(addr, ctypes.POINTER(ctypes.c_char))': ['ctypes.cast'],
        'import ctypes\nctypes.c_char.from_address(0x1000)': ['ctypes.c_char.from_address'],
        'import ctypes\nctypes.CFUNCTYPE(None)(0x1000)()': ['ctypes.CFUNCTYPE'],
        'import _ctypes\n_ctypes.dlopen("x.so")': ['_ctypes.dlopen'],
        'from cffi import FFI\nffi = FFI()\nlib = ffi.dlopen("c")\nlib.printf(b"x")': ['cffi.FFI().dlopen', 'cffi.FFI().dlopen().printf'],
        'ctypes.CDLL("x")': ['ctypes.CDLL'],
        '__import__("ctypes").CDLL("x")': ['ctypes.CDLL'],
        'import ctypes\ngetattr(ctypes, "CDLL")("x")': ['ctypes.CDLL']
    };
    for (const [source, evidence] of Object.entries(cases)) {
        const ir = await analyzeAsync(source, { language: 'python' });
        assert.equal(ir.analysisStatus, 'complete', source);
        assert.equal(ir.risk, 'critical', source);
        assert.deepEqual(ir.forbidden, ['native_code'], source);
        assert.deepEqual(native(ir).sort(), [...evidence].sort(), source);
        assert.deepEqual(compress(ir).facts.operations, ['nativeCode'], source);
    }
});

test('Python: importing ctypes, types, sizes and buffers alone is not native code', async () => {
    for (const source of [
        'import ctypes',
        'import ctypes.util\nprint(ctypes.util.find_library("c"))',
        'import ctypes\nx = ctypes.c_int(5)\nprint(ctypes.sizeof(x))',
        'import ctypes\nbuf = ctypes.create_string_buffer(16)',
        'from ctypes import Structure, c_int\nclass P(Structure):\n    _fields_ = [("x", c_int)]',
        'def f(ctypes):\n    ctypes.CDLL("x")',
        'class Loader:\n    def CDLL(self, n): pass\nLoader().CDLL("x")',
        '# ctypes.CDLL("libc.so.6")\ns = "ctypes.memmove(a, b, 1)"'
    ]) {
        const ir = await analyzeAsync(source, { language: 'python' });
        assert.equal(ir.analysisStatus, 'complete', source);
        assert.equal(ir.facts.operations.nativeCode, false, source);
        assert.equal(ir.risk, 'low', source);
        assert.deepEqual(native(ir), [], source);
    }
});

test('JavaScript / TypeScript: native addons, FFI and process.binding are critical', async () => {
    const cases = [
        ['js', 'process.dlopen(module, "/tmp/x.node")', ['process.dlopen']],
        ['js', 'const b = process.binding("spawn_sync"); b.spawn({ file: "sh" })', ['process.binding']],
        ['js', 'process._linkedBinding("x")', ['process._linkedBinding']],
        ['js', 'Deno.dlopen("libc.so.6", {})', ['Deno.dlopen']],
        ['js', 'const koffi = require("koffi"); const lib = koffi.load("libc.so.6");', ['koffi.load']],
        ['js', 'const { load: open } = require("koffi"); open("x")', ['koffi.load']],
        ['js', 'require("koffi").load("x")', ['koffi.load']],
        ['js', 'const ffi = require("ffi-napi"); ffi.Library("libc", {})', ['ffi-napi.Library']],
        ['js', 'import { dlopen } from "bun:ffi"; dlopen("x", {})', ['bun:ffi.dlopen']],
        ['js', 'const addon = require("./build/Release/addon.node")', ['require(*.node)']],
        ['js', 'import addon from "./addon.node"', ['import(*.node)']],
        ['js', 'const addon = require("bindings")("addon")', ['bindings']],
        ['js', 'const load = require("node-gyp-build"); load(__dirname)', ['node-gyp-build']],
        ['ts', 'import koffi from "koffi"; koffi.load("x")', ['koffi.load']],
        ['ts', 'import * as koffi from "koffi"; koffi.load("x")', ['koffi.load']],
        ['ts', 'import koffi = require("koffi"); (koffi as any).load("x")', ['koffi.load']]
    ];
    for (const [language, source, evidence] of cases) {
        const ir = await analyzeAsync(source, { language: language === 'ts' ? 'typescript' : 'javascript' });
        assert.equal(ir.analysisStatus, 'complete', source);
        assert.equal(ir.risk, 'critical', source);
        assert.deepEqual(ir.forbidden, ['native_code'], source);
        assert.deepEqual(native(ir), evidence, source);
    }
});

test('JavaScript: an FFI import alone, look-alike methods and type imports are not native code', async () => {
    for (const [language, source] of [
        ['javascript', 'const koffi = require("koffi")'],
        ['javascript', 'obj.binding("x"); myproc.dlopen(1); lib.load("x")'],
        ['javascript', 'const data = require("./data.json"); require("./node")'],
        ['javascript', '// process.dlopen(module, "x.node")\nconst s = "require(\'koffi\').load()"'],
        ['typescript', 'import type { IKoffiLib } from "koffi"; let x: IKoffiLib;']
    ]) {
        const ir = await analyzeAsync(source, { language });
        assert.equal(ir.analysisStatus, 'complete', source);
        assert.equal(ir.facts.operations.nativeCode, false, source);
        assert.deepEqual(native(ir), [], source);
    }
});

test('nativeCode is part of the operations shape for every language', async () => {
    for (const language of ['javascript', 'typescript', 'python']) {
        const ir = await analyzeAsync('x = 1', { language });
        assert.equal(ir.facts.operations.nativeCode, false, language);
    }
});
