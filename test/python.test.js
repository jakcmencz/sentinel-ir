const test = require('node:test');
const assert = require('node:assert/strict');

const { analyze, analyzeAsync, compress, initializeWasm } = require('../src/sentinel-ir');

const py = source => analyzeAsync(source, { target: 'm.py' });
const ops = ir => Object.entries(ir.facts.operations).filter(([, on]) => on).map(([name]) => name).sort();
const signals = ir => ir.facts.riskSignals.map(s => `${s.signal}:${s.evidence}`);

test('sync analyze() on Python before initialization is incomplete, not guessed', () => {
    const ir = analyze('x = 1', { target: 'a.py' });
    assert.equal(ir.language, 'python');
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.match(ir.facts.error, /python parser is not initialized/);
});

test('.py and .pyi select Python; py and python are aliases', async () => {
    for (const target of ['a.py', 'B.PY', 'stubs/a.pyi']) assert.equal((await analyzeAsync('x = 1', { target })).language, 'python', target);
    assert.equal((await analyzeAsync('x = 1', { language: 'py' })).analysisStatus, 'complete');
    assert.equal((await analyzeAsync('x = 1', { target: 'a.js', language: 'Python' })).language, 'python');
    assert.equal(compress(await py('x = 1')).language, 'python');
});

test('a Flask service yields the same kind of facts as JavaScript', async () => {
    const ir = await py(`
import os
import requests
from flask import Flask

app = Flask(__name__)

@app.route("/items", methods=["GET", "POST"])
def items():
    return requests.get(os.environ["UPSTREAM_URL"]).json()

@app.get("/health")
def health():
    return "ok"

def _private():
    pass
`);
    assert.equal(ir.analysisStatus, 'complete');
    assert.equal(ir.risk, 'medium');
    assert.deepEqual(ir.facts.routes, ['GET /items', 'POST /items', 'GET /health']);
    assert.deepEqual(ir.facts.exports, ['health', 'items']);
    assert.deepEqual(ir.facts.imports, ['flask', 'os', 'requests']);
    assert.deepEqual(ir.facts.env, ['UPSTREAM_URL']);
    assert.deepEqual(ops(ir), ['inboundHttp', 'outboundHttp']);
    assert.deepEqual(ir.facts.calls.network, ['app.get', 'app.route', 'requests.get']);
});

test('FastAPI routers and HTTP client sessions are recognized', async () => {
    const ir = await py(`
from fastapi import APIRouter
import httpx
r = APIRouter()
@r.post("/jobs")
async def create():
    async with httpx.AsyncClient() as client:
        await client.post("https://example.com")
`);
    assert.deepEqual(ir.facts.routes, ['POST /jobs']);
    assert.deepEqual(ir.facts.calls.network, ['httpx.AsyncClient().post', 'r.post']);
});

test('process spawning is critical, through any import alias', async () => {
    const cases = {
        'import subprocess\nsubprocess.run(["ls"])': 'subprocess.run',
        'import subprocess as sp\nsp.Popen("ls", shell=True)': 'subprocess.Popen',
        'from subprocess import check_output as co\nco(["ls"])': 'subprocess.check_output',
        'import os\nos.system("ls")': 'os.system',
        'from os import system as sh\nsh("ls")': 'os.system',
        'import os\nrun = os.popen\nrun("ls")': 'os.popen',
        'import asyncio\nasyncio.create_subprocess_shell("ls")': 'asyncio.create_subprocess_shell'
    };
    for (const [source, evidence] of Object.entries(cases)) {
        const ir = await py(source);
        assert.equal(ir.risk, 'critical', source);
        assert.ok(ir.facts.calls.process.includes(evidence), source);
        assert.ok(ir.forbidden.includes('process_spawn'), source);
    }
});

test('importing subprocess alone is a child-process capability, like child_process in JS', async () => {
    const ir = await py('import subprocess');
    assert.equal(ir.risk, 'critical');
    assert.deepEqual(ir.forbidden, ['child_process']);
    assert.deepEqual(signals(ir), ['child_process_import:import(subprocess)']);
});

test('eval, exec and compile are dynamic code unless the name is rebound', async () => {
    for (const source of ['eval("1")', 'exec("x = 1")', 'compile("1", "f", "eval")', 'run = eval\nrun("1")', 'import builtins\nbuiltins.exec("1")']) {
        const ir = await py(source);
        assert.equal(ir.risk, 'critical', source);
        assert.deepEqual(ir.forbidden, ['eval'], source);
    }
    const shadowed = {
        'def eval(x):\n    return x\neval("1")': 'module-level def',
        'def f(eval):\n    eval("1")': 'parameter',
        'def f():\n    exec = print\n    exec("1")': 'local assignment',
        'from mylib import eval\neval("1")': 'import from another module',
        'class C:\n    def compile(self):\n        pass\nC().compile()': 'method'
    };
    for (const [source, why] of Object.entries(shadowed)) {
        assert.equal((await py(source)).risk, 'low', why);
    }
});

test('a class-body binding does not shadow a builtin inside its methods', async () => {
    const ir = await py('class C:\n    eval = None\n    def m(self):\n        eval("1")');
    assert.equal(ir.risk, 'critical');
});

test('unsafe deserialization is critical', async () => {
    const cases = {
        'import pickle\npickle.loads(data)': 'pickle.loads',
        'from pickle import load\nload(f)': 'pickle.load',
        'import marshal\nmarshal.loads(b"")': 'marshal.loads',
        'import yaml\nyaml.load(s)': 'yaml.load',
        'import yaml\nyaml.load(s, Loader=yaml.Loader)': 'yaml.load',
        'import yaml\nyaml.unsafe_load(s)': 'yaml.unsafe_load',
        'import numpy as np\nnp.load("a.npy", allow_pickle=True)': 'numpy.load',
        'import pandas as pd\npd.read_pickle("a.pkl")': 'pandas.read_pickle',
        'import shelve\nshelve.open("db")': 'shelve.open'
    };
    for (const [source, evidence] of Object.entries(cases)) {
        const ir = await py(source);
        assert.equal(ir.risk, 'critical', source);
        assert.deepEqual(ir.forbidden, ['unsafe_deserialization'], source);
        assert.deepEqual(signals(ir), [`unsafe_deserialization:${evidence}`], source);
        assert.deepEqual(compress(ir).facts.operations, ['unsafeDeserialization'], source);
    }
    for (const source of [
        'import yaml\nyaml.load(s, Loader=yaml.SafeLoader)',
        'import yaml\nyaml.safe_load(s)',
        'import json\njson.loads(s)',
        'import numpy as np\nnp.load("a.npy")'
    ]) {
        assert.equal((await py(source)).risk, 'low', source);
    }
});

test('filesystem: delete is high, write is medium, read is low', async () => {
    const cases = [
        ['import shutil\nshutil.rmtree("build")', 'high', 'shutil.rmtree'],
        ['import os\nos.remove("a")', 'high', 'os.remove'],
        ['from pathlib import Path\np = Path("a") / "b"\np.unlink()', 'high', 'pathlib.Path().unlink'],
        ['from pathlib import Path\nPath.home().joinpath("x").rmdir()', 'high', 'pathlib.Path().rmdir'],
        ['open("a.txt", "w").write("x")', 'medium', 'open'],
        ['open("a.txt", mode="a")', 'medium', 'open'],
        ['open("a.txt", m)', 'medium', 'open'],
        ['import pathlib\npathlib.Path("a").write_text("x")', 'medium', 'pathlib.Path().write_text'],
        ['import shutil\nshutil.copy("a", "b")', 'medium', 'shutil.copy'],
        ['with open("a.txt") as f:\n    f.read()', 'low', 'open'],
        ['open("a.txt", "rb")', 'low', 'open'],
        ['import os\nos.listdir(".")', 'low', 'os.listdir']
    ];
    for (const [source, risk, evidence] of cases) {
        const ir = await py(source);
        assert.equal(ir.risk, risk, source);
        assert.ok(ir.facts.calls.filesystem.includes(evidence), source);
    }
});

test('a local open() is not the builtin', async () => {
    assert.deepEqual(ops(await py('def open(p, m):\n    pass\nopen("a", "w")')), []);
});

test('crypto, constant-time compare and secret comparison', async () => {
    const ir = await py(`
import hashlib, hmac, os
def check(token, sig):
    digest = hashlib.sha256(token.encode()).hexdigest()
    if hmac.compare_digest(digest, sig):
        return True
    return token == os.environ["API_TOKEN"]
`);
    assert.equal(ir.risk, 'medium');
    assert.equal(ir.objective, 'security_refactor');
    assert.deepEqual(ir.facts.calls.crypto, ['hashlib.sha256', 'hmac.compare_digest']);
    assert.deepEqual(ops(ir), ['cryptoUse', 'secretComparison']);
    assert.deepEqual(signals(ir).sort(), [
        'crypto_use:hashlib.sha256',
        'secret_access:os.environ.API_TOKEN',
        'secret_comparison:hmac.compare_digest',
        'secret_comparison:token == os.environ["API_TOKEN"]'
    ]);
});

test('environment reads through os.environ and os.getenv', async () => {
    const ir = await py('import os\nfrom os import environ as e\nos.getenv("A")\nos.environ.get("B")\ne["C"]\nos.environ[name]');
    assert.deepEqual(ir.facts.env, ['A', 'B', 'C']);
});

test('sys.exit is a process exit, not a risk by itself', async () => {
    const ir = await py('import sys\nsys.exit(1)');
    assert.equal(ir.risk, 'low');
    assert.deepEqual(ir.forbidden, ['process.exit']);
});

test('__all__ decides exports when it is a literal list', async () => {
    const ir = await py('__all__ = ["b"]\ndef a(): pass\ndef b(): pass');
    assert.deepEqual(ir.facts.exports, ['b']);
});

test('strings, comments and docstrings are not code', async () => {
    const ir = await py('"""eval(x) and subprocess.run"""\n# os.system("rm -rf /")\nx = "pickle.loads(data)"');
    assert.equal(ir.risk, 'low');
    assert.deepEqual(ops(ir), []);
    assert.deepEqual(ir.facts.calls, { network: [], filesystem: [], process: [], crypto: [], dynamic: [] });
});

test('broken Python is incomplete, not a confident low risk', async () => {
    const ir = await py('def f(:\n    subprocess.run(x)');
    assert.equal(ir.analysisStatus, 'incomplete');
    assert.equal(compress(ir).facts.ast, false);
});

test('the grammar accepts Python 2 statements; exec "..." is still dynamic code', async () => {
    assert.equal((await py('print "hello"')).analysisStatus, 'complete');
    assert.equal((await py('exec "x = 1"')).risk, 'critical');
});

test('sync analyze() works on Python after initializeWasm({ languages })', async () => {
    await initializeWasm({ languages: ['python'] });
    const ir = analyze('import os\nos.system("ls")', { target: 'a.py' });
    assert.equal(ir.risk, 'critical');
});

test('JavaScript facts keep their shape: one new operation flag, off', async () => {
    const ir = await analyzeAsync('const a = 1;', { target: 'a.js' });
    assert.equal(ir.facts.operations.unsafeDeserialization, false);
    assert.deepEqual(compress(ir).facts, { ast: true });
});
