const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeAsync } = require('../src/sentinel-ir');

const rs = source => analyzeAsync(source, { target: 'src/lib.rs' });
const ops = ir => Object.entries(ir.facts.operations).filter(([, on]) => on).map(([name]) => name).sort();

const syntax = [
    ['wasm-bindgen extern types (web-sys, js-sys)', 'extern "C" { pub type AbortController; #[wasm_bindgen(method)] pub fn abort(this: &AbortController); }'],
    ['unsafe extern with safe items', 'unsafe extern "C" { pub safe fn f() -> u64; safe static X: i32; pub unsafe fn g(); }'],
    ['safe and auto as identifiers', 'fn g(safe: bool, auto: u8) -> u8 { let auto = auto + 1; let safe = !safe; auto.max(safe as u8) }'],
    ['safe and auto as type names', 'type safe = u8; struct W(safe, auto); fn g(x: Vec<safe>, d: &dyn auto) -> impl safe { x } impl safe for auto {}'],
    ['const impl and [const] / ~const bounds', 'const impl<T: [const] Clone> Foo<T> { fn h(f: impl [const] FnOnce(T) -> bool + ~const Destruct) {} }'],
    ['const and auto traits', 'pub const trait Tr { fn f(); } pub unsafe auto trait Send2 {}'],
    ['trait aliases', 'trait Al = Clone + Send; pub trait Bl<T> = Iterator<Item = T> where T: Copy;'],
    ['macro 2.0', 'pub macro m($x:expr) { $x } macro n { ($y:ident) => { $y } }'],
    ['negative const generics', 'type Y = Ranged<-5, 5>; fn f() -> Ranged<{ -1 }, 1> { todo!() }'],
    ['f16 and f128', 'fn f(a: f16, b: f128) { let _ = 1f16; let _ = 2.0f128; }'],
    ['super let and const closures', 'fn k() { super let z = 1; let c = const |x: u8| x; }'],
    ['attributes on expressions', 'fn k() { let w = #[cold] || 1; let t = (#[allow(unused)] 1, 2); }'],
    ['turbofish in type position', 'fn k(p: *const Gray::<u8>) { let q = p as *const Gray::<u16>; }'],
    ['try! from edition 2015 next to try blocks', 'fn f() -> Result<u8, E> { let x = try!(a()); let y: Result<u8, E> = try { 1 }; Ok(x) }'],
    ['&_ inside fn pointer types', 'fn k() { let f = (|_| false) as fn(&_) -> _; }'],
    ['unicode escape with underscores', 'const S: &str = "\\u{1F_600}";']
];

for (const [name, source] of syntax) {
    test(`Rust syntax parses completely: ${name}`, async () => {
        const ir = await rs(source);
        assert.equal(ir.analysisStatus, 'complete', ir.facts.parseError ? JSON.stringify(ir.facts.parseError) : '');
    });
}

test('facts still found next to newer syntax', async () => {
    const ir = await rs([
        'unsafe extern "C" { pub safe fn getpid() -> i32; }',
        'const impl<T: [const] Clone> Run for T {}',
        'fn go(safe: bool) { if safe { std::fs::remove_file("x").unwrap(); } std::process::Command::new("sh").spawn().unwrap(); }'
    ].join('\n'));
    assert.equal(ir.analysisStatus, 'complete');
    assert.deepEqual(ops(ir), ['diskDelete', 'nativeCode', 'processSpawn']);
});

// web-tree-sitter copies at most 5119 UTF-16 code units per input chunk; a
// non-BMP character split across that boundary used to break the parse.
for (const offset of [4094, 4095, 5117, 5118, 5119, 8191, 32767]) {
    test(`astral character at UTF-16 offset ${offset} does not break a large file`, async () => {
        const head = 'const A: &str = "';
        const filler = 'x'.repeat(offset - head.length);
        const rust = `${head}${filler}\u{10C9C}";\npub fn run() { std::process::Command::new("sh").spawn().unwrap(); }\n${'// pad\n'.repeat(6000)}`;
        const rir = await rs(rust);
        assert.equal(rir.analysisStatus, 'complete');
        assert.deepEqual(ops(rir), ['processSpawn']);

        const jhead = 'const a = "';
        const js = `${jhead}${'x'.repeat(offset - jhead.length)}\u{1F600}";\nrequire("child_process").exec("ls");\n${'// pad\n'.repeat(6000)}`;
        const jir = await analyzeAsync(js, { language: 'javascript' });
        assert.equal(jir.analysisStatus, 'complete');
        assert.equal(jir.facts.operations.childProcess, true);
    });
}

test('macro bodies and arguments: env names, macro 2.0 bodies, exports', async () => {
    const env = await rs('fn f() { println!("{}", std::env::var("API_TOKEN").unwrap()); }');
    assert.deepEqual(env.facts.env, ['API_TOKEN']);

    const m2 = await rs('pub macro run($x:expr) { std::process::Command::new($x).spawn() }\npub trait Al = Clone + Send;');
    assert.deepEqual(ops(m2), ['processSpawn']);
    assert.deepEqual(m2.facts.exports, ['Al', 'run']);

    const rules = await rs('macro clean { ($p:expr) => { std::fs::remove_file($p) } }');
    assert.deepEqual(ops(rules), ['diskDelete']);

    const text = await rs('pub macro m() { "std::process::Command::new" }');
    assert.deepEqual(ops(text), []);
});

test('bundled Rust grammar matches the SHA-256 recorded in NOTICE', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    const crypto = require('node:crypto');
    const root = path.join(__dirname, '..');
    const notice = fs.readFileSync(path.join(root, 'NOTICE'), 'utf8');
    const recorded = notice.match(/scripts\/rust-grammar\/build\.sh rebuilds the file reproducibly \(SHA-256\s+([0-9a-f]{64})\)/);
    assert.ok(recorded, 'NOTICE must record the Rust grammar SHA-256');
    const actual = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, 'wasm/tree-sitter-rust.wasm'))).digest('hex');
    assert.equal(actual, recorded[1]);
});
