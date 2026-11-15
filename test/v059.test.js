const test = require('node:test');
const assert = require('node:assert/strict');
const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm({ languages: ['python', 'rust'] });
});

const PYTHON = [
  'os.system(x)', 'os.popen(x)', 'os.fork()', 'subprocess', 'popen2', 'import ctypes', 'import _ctypes',
  'cffi', 'llvmlite', 'pickle', 'cpickle', 'dill', 'marshal', 'shelve', 'jsonpickle',
  'commands.getstatusoutput(x)', 'pty.spawn(x)', 'asyncio.create_subprocess_exec(x)', 'yaml.load(x)',
  'joblib.load(x)', 'pd.read_pickle(x)', 'LoadLibrary(x)', '__import__', 'importlib.import_module(x)',
  'compile(x)', 'exec', 'os.startfile(x)'
];
const RUST = [
  'unsafe', 'extern "C" {}', '#[no_mangle]', 'std::process::Command::new(x)', 'use std::process;',
  'use std::process::{self, Stdio};', 'tokio::process::Command', 'Command::new(x)', 'duct::cmd',
  'libloading::Library', 'cc::Build', 'rhai::Engine', 'asm!(x)', 'transmute(x)', 'dlsym(x)',
  'libc::system(x)', 'nix::unistd::fork()', 'subprocess::Exec::cmd', 'py.run(x)', 'cargo:rustc-link-lib=x'
];

test('broken Python/Rust rated critical always names a forbidden capability', () => {
  for (const [language, list, tail] of [['python', PYTHON, '\ndef (:\n'], ['rust', RUST, '\nfn main() {\n']]) {
    for (const code of list) {
      const ir = SentinelIR.analyze(code + tail, { language });
      assert.equal(ir.analysisStatus, 'incomplete', code);
      assert.equal(ir.risk, 'critical', code);
      assert.notDeepEqual(ir.forbidden, [], code);
    }
  }
});

test('broken files with harmless process/importlib/ctypes names are not critical', () => {
  for (const [language, code] of [
    ['python', 'import importlib\nimportlib.reload(m)\ndef (:\n'],
    ['python', 'from ctypes import c_int, sizeof\nsizeof(c_int)\nclass (\n'],
    ['rust', 'fn main() { std::process::exit(1);\n'],
    ['rust', 'fn main() { let id = std::process::id(); std::process::abort();\n'],
    ['rust', 'use std::process::Stdio;\nfn main() {\n']
  ]) {
    const ir = SentinelIR.analyze(code, { language });
    assert.equal(ir.analysisStatus, 'incomplete', code);
    assert.notEqual(ir.risk, 'critical', code);
    assert.deepEqual(ir.forbidden, [], code);
  }
});
