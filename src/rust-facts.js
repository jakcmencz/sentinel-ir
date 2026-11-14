"use strict";

/**
 * Structural facts for Rust, in the same shape as AstFacts.extract() gives
 * for JavaScript and TypeScript. Paths are resolved through the file's own
 * `use` declarations, so a call is judged by what it refers to:
 *   use std::process::Command as Cmd; Cmd::new("sh")   -> std::process::Command::new
 *   use std::fs::*; remove_dir_all(p)                    -> std::fs::remove_dir_all
 * Macro bodies are token trees, not syntax: paths called inside a macro
 * argument (println!("{}", fs::read_to_string(p)?)) are still found, but what
 * a macro expands to is not.
 */

const TreeParser = require("./tree-parser");
const { named, codeText, isComment, withoutComments } = require("./ir-text");
const { emptyFacts, dangerousOf } = require("./ast-facts");

const SECRETISH = /(token|secret|signature|api[_-]?key|apikey|password|passwd|credential|auth|hmac|digest)/i;

const FS_MODULES = ["std::fs", "tokio::fs", "async_std::fs", "fs_err", "fs_err::tokio"];
const FS_DELETE = ["remove_file", "remove_dir", "remove_dir_all"];
const FS_WRITE = ["write", "create_dir", "create_dir_all", "rename", "copy", "hard_link", "set_permissions", "soft_link", "File::create", "File::create_new"];
const FS_READ = ["read", "read_to_string", "read_dir", "read_link", "File::open"];
const FS_OPEN_OPTIONS = ["OpenOptions::new", "File::options"];

const fsCalls = names => new Set(FS_MODULES.flatMap(module => names.map(name => `${module}::${name}`)));

const DELETE_CALLS = fsCalls(FS_DELETE);
const WRITE_CALLS = new Set([
    ...fsCalls(FS_WRITE),
    "std::os::unix::fs::symlink", "std::os::windows::fs::symlink_file", "std::os::windows::fs::symlink_dir",
    "tempfile::tempfile", "tempfile::tempdir", "tempfile::NamedTempFile::new", "tempfile::Builder::new"
]);
const READ_CALLS = new Set([...fsCalls(FS_READ), "walkdir::WalkDir::new"]);
const OPEN_OPTIONS_CALLS = fsCalls(FS_OPEN_OPTIONS);
const OPEN_WRITE_METHODS = new Set(["write", "append", "create", "create_new", "truncate"]);

const COMMAND_TYPES = new Set([
    "std::process::Command", "tokio::process::Command", "async_std::process::Command",
    "async_process::Command", "smol::process::Command"
]);
const PROCESS_MODULES = new Set(["std::process", "tokio::process", "async_std::process", "async_process", "smol::process"]);
const SPAWN_CALLS = new Set([
    ...[...COMMAND_TYPES].map(type => `${type}::new`),
    "duct::cmd", "subprocess::Exec::cmd", "subprocess::Exec::shell", "subprocess::Popen::create",
    ...["execv", "execve", "execvp", "execvpe", "fexecve", "execveat", "fork"].map(name => `nix::unistd::${name}`),
    "nix::spawn::posix_spawn", "nix::spawn::posix_spawnp",
    ...["system", "popen", "fork", "vfork", "execv", "execve", "execvp", "execvpe", "execl", "execlp", "execle", "fexecve",
        "posix_spawn", "posix_spawnp"].map(name => `libc::${name}`)
]);
const SPAWN_MACROS = new Set(["duct::cmd", "xshell::cmd", "cmd_lib::run_cmd", "cmd_lib::run_fun", "cmd_lib::spawn"]);
const EXIT_CALLS = new Set(["std::process::exit", "std::process::abort", "libc::exit", "libc::_exit", "libc::abort"]);

const NATIVE_CALLS = new Set([
    "libloading::Library::new", "libloading::os::unix::Library::new", "libloading::os::unix::Library::open",
    "libloading::os::windows::Library::new", "libloading::os::windows::Library::load_with_flags",
    "dlopen2::wrapper::Container::load", "dlopen2::raw::Library::open", "dlopen::raw::Library::open",
    "libc::dlopen", "libc::dlsym",
    // Build-time C/C++ compilation and native library linking (build.rs).
    "cc::Build::new", "cmake::Config::new", "cmake::build", "pkg_config::probe_library", "vcpkg::find_package",
    ...["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress"].flatMap(name => [
        `windows::Win32::System::LibraryLoader::${name}`, `windows_sys::Win32::System::LibraryLoader::${name}`,
        `winapi::um::libloaderapi::${name}`
    ])
]);
const NATIVE_ATTRIBUTES = new Set(["no_mangle", "export_name", "link_section"]);
const ASM_MACROS = new Set(["asm", "global_asm", "naked_asm", "llvm_asm"]);

const EVAL_CALLS = new Set([
    "rhai::Engine::new", "rhai::Engine::new_raw", "mlua::Lua::new", "mlua::Lua::unsafe_new", "rlua::Lua::new",
    "boa_engine::Context::default", "deno_core::JsRuntime::new", "v8::Isolate::new", "v8::Script::compile",
    "pyo3::Python::run", "pyo3::Python::eval"
]);

const HTTP_VERBS = ["get", "post", "put", "delete", "patch", "head", "options", "trace", "connect"];
const OUTBOUND_CALLS = new Set([
    "reqwest::get", "reqwest::Client::new", "reqwest::Client::builder", "reqwest::ClientBuilder::new",
    "reqwest::blocking::get", "reqwest::blocking::Client::new", "reqwest::blocking::Client::builder",
    ...[...HTTP_VERBS, "request", "agent"].map(verb => `ureq::${verb}`), "ureq::Agent::new", "ureq::AgentBuilder::new",
    ...HTTP_VERBS.flatMap(verb => [`surf::${verb}`, `isahc::${verb}`, `attohttpc::${verb}`]),
    "surf::client", "isahc::HttpClient::new",
    "std::net::TcpStream::connect", "std::net::TcpStream::connect_timeout", "std::net::UdpSocket::bind",
    "tokio::net::TcpStream::connect", "tokio::net::UdpSocket::bind", "async_std::net::TcpStream::connect",
    "hyper::Client::new", "hyper::Client::builder", "hyper::client::conn::handshake",
    "hyper::client::conn::http1::handshake", "hyper::client::conn::http2::handshake",
    "hyper_util::client::legacy::Client::builder", "curl::easy::Easy::new", "curl::easy::Easy2::new",
    "tungstenite::connect", "tokio_tungstenite::connect_async", "awc::Client::new", "awc::Client::default"
]);
const INBOUND_CALLS = new Set([
    "std::net::TcpListener::bind", "tokio::net::TcpListener::bind", "async_std::net::TcpListener::bind",
    "std::os::unix::net::UnixListener::bind", "tokio::net::UnixListener::bind",
    "actix_web::HttpServer::new", "axum::serve", "axum::Server::bind", "hyper::Server::bind",
    "warp::serve", "tiny_http::Server::http", "rocket::build", "rocket::ignite", "tide::new",
    "poem::Server::new", "salvo::Server::new"
]);
const ROUTE_HANDLERS = new Set([
    ...[...HTTP_VERBS, "any", "on"].map(verb => `axum::routing::${verb}`),
    ...[...HTTP_VERBS, "route", "method"].map(verb => `actix_web::web::${verb}`)
]);
const ROUTE_ATTRIBUTE_CRATES = ["actix_web", "rocket", "ntex"];

const CRYPTO_CRATES = new Set([
    "sha1", "sha2", "sha3", "md5", "md_5", "hmac", "ring", "openssl", "aes", "aes_gcm", "chacha20poly1305",
    "rsa", "ed25519_dalek", "x25519_dalek", "argon2", "bcrypt", "scrypt", "pbkdf2", "jsonwebtoken", "blake2",
    "blake3", "orion", "sodiumoxide", "digest", "k256", "p256", "p384", "hkdf", "crypto_box", "aws_lc_rs"
]);
const CONSTANT_COMPARE_CALLS = new Set([
    "constant_time_eq::constant_time_eq", "ring::constant_time::verify_slices_are_equal", "openssl::memcmp::eq"
]);

const ENV_CALLS = new Set([
    "std::env::var", "std::env::var_os", "std::env::remove_var", "std::env::set_var",
    "dotenvy::var", "dotenvy::var_os", "dotenv::var", "dotenv::var_os"
]);
const ENV_ALL_CALLS = new Set(["std::env::vars", "std::env::vars_os"]);
const DOTENV_FILE_CALLS = new Set(["dotenvy", "dotenv"].flatMap(crate => [
    "dotenv", "dotenv_override", "from_path", "from_path_override", "from_filename", "from_filename_override",
    "from_path_iter", "from_filename_iter", "dotenv_iter"
].map(name => `${crate}::${name}`)));
const COMPILER_READS = /^(include|include_str|include_bytes)!$|^#\[path\]$/;
const LINK_DIRECTIVE = /^cargo::?rustc-link-(lib|search)=/;
const ENV_MACROS = new Set(["env", "option_env"]);
const INCLUDE_MACROS = new Set(["include", "include_str", "include_bytes"]);

// Paths that cannot be resolved from this file alone.
const LOCAL_ROOTS = new Set(["crate", "self", "super", "Self"]);
const ROOT_ALIASES = { core: "std", alloc: "std" };
const STD_CRATES = { std: true, core: true, alloc: true };

const KNOWN_CALLS = [
    DELETE_CALLS, WRITE_CALLS, READ_CALLS, OPEN_OPTIONS_CALLS, SPAWN_CALLS, EXIT_CALLS, NATIVE_CALLS, EVAL_CALLS,
    OUTBOUND_CALLS, INBOUND_CALLS, ROUTE_HANDLERS, ENV_CALLS, CONSTANT_COMPARE_CALLS, SPAWN_MACROS
];
const isKnown = q => KNOWN_CALLS.some(set => set.has(q)) || CRYPTO_CRATES.has(q.split("::")[0]);

function text(node) {
    return node ? node.text : "";
}

// The ABI string of `extern "C"`; anything that is not an ABI name is not copied.
function abiText(abi) {
    const literal = named(abi).find(child => child.type === "string_literal");
    if (!literal) return '"C"';
    return /^"[\w-]{1,32}"$/.test(literal.text) ? literal.text : '"…"';
}

function line(node) {
    return node.startPosition.row + 1;
}

function field(node, name) {
    return node ? node.childForFieldName(name) : null;
}

function walk(node, visit) {
    visit(node);
    for (const child of named(node)) walk(child, visit);
}

function stringLiteral(node) {
    if (!node) return null;
    if (node.type === "raw_string_literal" || node.type === "string_literal") {
        if (named(node).some(child => child.type === "escape_sequence")) return null;
        return named(node).filter(child => child.type === "string_content").map(child => child.text).join("");
    }
    return null;
}

function isIdent(node) {
    return !!node && (node.type === "identifier" || node.type === "crate" || node.type === "self" || node.type === "super");
}

// `a::b::c` as ["a", "b", "c"]; a leading `::` gives "" first; null when not a plain path.
function segmentsOf(node) {
    if (!node) return null;
    switch (node.type) {
        case "identifier":
        case "type_identifier":
        case "crate":
        case "self":
        case "super":
            return [node.text];
        case "scoped_identifier":
        case "scoped_type_identifier": {
            const path = field(node, "path");
            const name = field(node, "name");
            if (!name) return null;
            const head = path ? segmentsOf(path) : [""];
            return head ? [...head, name.text] : null;
        }
        case "generic_type":
            return segmentsOf(field(node, "type"));
        case "generic_function":
            return segmentsOf(field(node, "function"));
        default:
            return null;
    }
}

function createResolver() {
    const aliases = new Map();
    const globs = [];
    const imports = new Set();
    const crateAliases = new Map();
    // Each import's first `use`/`extern crate` declaration, for signal lines.
    const declarations = new Map();
    let declaration = null;
    const addImport = q => {
        imports.add(q);
        if (declaration && !declarations.has(q)) declarations.set(q, declaration);
    };

    const canonical = segments => {
        const parts = segments[0] === "" ? segments.slice(1) : [...segments];
        if (parts.length && crateAliases.has(parts[0])) parts[0] = crateAliases.get(parts[0]);
        if (parts.length && ROOT_ALIASES[parts[0]]) parts[0] = ROOT_ALIASES[parts[0]];
        return parts;
    };

    const bind = (name, segments) => {
        if (!name || name === "_" || name === "self") return;
        aliases.set(name, segments);
    };

    const visit = (node, prefix) => {
        switch (node.type) {
            case "identifier":
            case "scoped_identifier":
            case "crate":
            case "super": {
                const segments = segmentsOf(node);
                if (!segments) return;
                const full = canonical([...prefix, ...segments]);
                addImport(full.join("::"));
                bind(full[full.length - 1], full);
                return;
            }
            case "self": {
                if (!prefix.length) return;
                const full = canonical(prefix);
                addImport(full.join("::"));
                bind(full[full.length - 1], full);
                return;
            }
            case "use_as_clause": {
                const segments = segmentsOf(field(node, "path"));
                if (!segments) return;
                const full = canonical([...prefix, ...segments]);
                addImport(full.join("::"));
                bind(text(field(node, "alias")), full);
                return;
            }
            case "scoped_use_list": {
                const path = field(node, "path");
                const head = path ? segmentsOf(path) : [];
                const list = field(node, "list");
                if (head && list) visit(list, [...prefix, ...head]);
                return;
            }
            case "use_list":
                for (const child of named(node)) visit(child, prefix);
                return;
            case "use_wildcard": {
                const inner = named(node)[0];
                const segments = inner ? segmentsOf(inner) : [];
                if (!segments) return;
                const full = canonical([...prefix, ...segments]);
                globs.push(full);
                addImport(`${full.join("::")}::*`);
                return;
            }
            default:
                return;
        }
    };

    const visitUse = (node, prefix, decl = null) => {
        declaration = decl;
        try { visit(node, prefix); } finally { declaration = null; }
    };

    const addExternCrate = node => {
        const name = text(field(node, "name"));
        if (!name) return;
        declaration = node;
        addImport(name);
        declaration = null;
        const alias = field(node, "alias");
        if (alias) {
            bind(alias.text, [name]);
            // Only std crates (a renamed Cargo dependency's real name is not in the source),
            // and only at the crate root, where the alias reaches every module.
            if (name in STD_CRATES && node.parent?.type === "source_file") crateAliases.set(alias.text, name);
        }
    };

    // Full path of a referenced item, or null for local and unresolvable ones.
    const resolve = segments => {
        if (!segments || !segments.length) return null;
        if (segments[0] === "") return canonical(segments).join("::");
        if (LOCAL_ROOTS.has(segments[0])) return null;
        const bound = aliases.get(segments[0]);
        if (bound) return [...bound, ...segments.slice(1)].join("::");
        for (const glob of globs) {
            const candidate = [...glob, ...segments].join("::");
            if (isKnown(candidate)) return candidate;
        }
        return canonical(segments).join("::");
    };

    return { visitUse, addExternCrate, resolve, imports, declarations, crateAliases, globs, aliases };
}

function extract(content, options = {}) {
    const ast = TreeParser.parse(String(content || ""), "rust");
    try {
        return extractFrom(ast, options);
    } finally {
        TreeParser.release(ast);
    }
}

function extractFrom(ast, options) {
    const facts = emptyFacts();

    if (!ast.ok || !ast.root || ast.metrics?.hasError) {
        facts.error = ast.error || "source did not parse cleanly";
        if (ast.parseError) facts.parseError = ast.parseError;
        return facts;
    }

    facts.ast = true;
    const root = ast.root;
    const resolver = createResolver();
    const ops = facts.operations;
    const routes = new Map();
    const addRoute = (route, node) => {
        if (!routes.has(route) || routes.get(route) > node.startIndex) routes.set(route, node.startIndex);
    };
    const env = new Set();
    const calls = { network: new Set(), filesystem: new Set(), process: new Set(), crypto: new Set(), dynamic: new Set() };
    const signals = [];
    const signal = (name, evidence, node) => signals.push({ signal: name, evidence, line: line(node) });

    // A `mod reqwest` in the file shadows the crate of that name.
    const localModules = new Set();
    // `use` applies to its whole module wherever it is written, so collect all first,
    // after `extern crate x as y` so `use y::…` resolves to x.
    const uses = [];
    walk(root, node => {
        if (node.type === "use_declaration") {
            uses.push(node);
        } else if (node.type === "extern_crate_declaration") {
            resolver.addExternCrate(node);
        } else if (node.type === "mod_item") {
            localModules.add(text(field(node, "name")));
        }
    });
    for (const name of localModules) resolver.crateAliases.delete(name);
    for (const node of uses) {
        const argument = field(node, "argument");
        if (argument) resolver.visitUse(argument, [], node);
    }

    for (const q of resolver.imports) {
        const type = q.replace(/::\*$/, "");
        if (COMMAND_TYPES.has(type) || (q.endsWith("::*") && PROCESS_MODULES.has(type))) {
            ops.childProcess = true;
            signal("child_process_import", `use ${q}`, resolver.declarations.get(q) || root);
        }
        if (CRYPTO_CRATES.has(q.split("::")[0])) ops.cryptoUse = true;
    }

    const target = typeof options.target === "string" ? options.target : "";
    // src/build.rs is a module and tests/build.rs an integration test, not a Cargo build script.
    const buildScript = /(^|[\\/])build\.rs$/i.test(target) && !/(^|[\\/])(src|tests|examples|benches)[\\/]build\.rs$/i.test(target);
    if (buildScript) signal("build_script", "build.rs runs on the build machine at compile time", root);

    const addEnv = (name, evidence, node) => {
        env.add(name);
        if (SECRETISH.test(name)) signal("secret_access", evidence, node);
    };

    const native = (evidence, node) => {
        ops.nativeCode = true;
        signal("native_code", evidence, node);
    };

    const openOptions = (q, node) => {
        const methods = [];
        let current = node;
        for (;;) {
            const parent = current.parent;
            const grand = parent?.parent;
            if (!parent || parent.type !== "field_expression" || !grand || grand.type !== "call_expression") break;
            const arg = named(field(grand, "arguments"))[0];
            methods.push({ name: text(field(parent, "field")), on: !arg || text(arg) !== "false" });
            current = grand;
        }
        const writes = methods.some(m => m.on && OPEN_WRITE_METHODS.has(m.name));
        const reads = methods.some(m => m.on && m.name === "read");
        const opened = methods.some(m => m.name === "open");
        if (writes || !opened) {
            ops.diskWrite = true;
            signal("disk_write", q, node);
        }
        if (reads || !writes) ops.diskRead = true;
    };

    // `name` is a resolved path; `call` the call (or macro) node it came from.
    const visitCall = (q, call, args) => {
        if (!q) return;
        const root0 = q.split("::")[0];
        if (localModules.has(root0)) return;
        if (SPAWN_CALLS.has(q)) {
            ops.processSpawn = true;
            calls.process.add(q);
            signal("process_spawn", q, call);
        }
        if (EXIT_CALLS.has(q)) {
            ops.processExit = true;
            calls.process.add(q);
            signal("process_exit", q, call);
        }
        if (DELETE_CALLS.has(q)) {
            ops.diskDelete = true;
            calls.filesystem.add(q);
            signal("destructive_fs", q, call);
        }
        if (WRITE_CALLS.has(q)) {
            ops.diskWrite = true;
            calls.filesystem.add(q);
            signal("disk_write", q, call);
        }
        if (READ_CALLS.has(q)) {
            ops.diskRead = true;
            calls.filesystem.add(q);
        }
        if (OPEN_OPTIONS_CALLS.has(q)) {
            calls.filesystem.add(q);
            if (call.type === "call_expression") openOptions(q, call);
            else {
                ops.diskWrite = true;
                ops.diskRead = true;
                signal("disk_write", q, call);
            }
        }
        if (NATIVE_CALLS.has(q)) {
            calls.dynamic.add(q);
            native(q, call);
        }
        if (EVAL_CALLS.has(q)) {
            ops.dynamicEval = true;
            calls.dynamic.add(q);
            signal("dynamic_code", q, call);
        }
        if (OUTBOUND_CALLS.has(q)) {
            ops.outboundHttp = true;
            calls.network.add(q);
            signal("outbound_http", q, call);
        }
        if (INBOUND_CALLS.has(q)) {
            ops.inboundHttp = true;
            calls.network.add(q);
            signal("inbound_http", q, call);
        }
        if (CRYPTO_CRATES.has(root0)) {
            ops.cryptoUse = true;
            calls.crypto.add(q);
            signal("crypto_use", q, call);
        }
        if (CONSTANT_COMPARE_CALLS.has(q)) {
            ops.cryptoUse = true;
            ops.secretComparison = true;
            calls.crypto.add(q);
            signal("secret_comparison", q, call);
        }
        if (ENV_CALLS.has(q)) {
            const name = args ? stringLiteral(args) : null;
            if (name) addEnv(name, `${q}("${name}")`, call);
        }
        if (ENV_ALL_CALLS.has(q)) signal("secret_access", `${q}()`, call);
        if (DOTENV_FILE_CALLS.has(q)) {
            ops.diskRead = true;
            calls.filesystem.add(q);
            signal("secret_access", `${q}() loads .env`, call);
        }
    };

    const visitMacro = (segments, tokens, node) => {
        if (!segments) return;
        const name = segments[segments.length - 1];
        const q = resolver.resolve(segments);
        const firstString = tokens ? named(tokens).find(child => child.type === "string_literal" || child.type === "raw_string_literal") : null;
        if (ENV_MACROS.has(name) && segments.length === 1) {
            const value = stringLiteral(firstString);
            if (value) addEnv(value, `${name}!("${value}")`, node);
        }
        if (INCLUDE_MACROS.has(name) && segments.length === 1) {
            ops.diskRead = true;
            calls.filesystem.add(`${name}!`);
        }
        if (ASM_MACROS.has(name) && (segments.length === 1 || q === `std::arch::${name}`)) native(`${name}!`, node);
        if (buildScript && (name === "println" || name === "print") && segments.length === 1) {
            const directive = stringLiteral(firstString);
            if (directive && LINK_DIRECTIVE.test(directive)) native(`println!("${directive.slice(0, 60)}")`, node);
        }
        if (q && SPAWN_MACROS.has(q)) {
            ops.processSpawn = true;
            calls.process.add(`${q}!`);
            signal("process_spawn", `${q}!`, node);
        }
    };

    // Token trees (macro arguments and macro_rules! bodies) are flat tokens:
    // find `a::b(`, `a::b!(` and `unsafe {` in them.
    const scanTokens = tree => {
        const children = tree.children.filter(child => !isComment(child));
        for (let i = 0; i < children.length; i++) {
            const child = children[i];
            if (child.type === "token_tree") {
                scanTokens(child);
                continue;
            }
            if (child.type === "unsafe" && children[i + 1]?.type === "token_tree" && children[i + 1].child(0)?.type === "{") {
                native("unsafe {}", child);
                continue;
            }
            if (!isIdent(child)) continue;
            const prev = children[i - 1];
            if (prev && (prev.type === "." || prev.type === "$" || (prev.type === "::" && isIdent(children[i - 2])))) continue;
            const segments = prev?.type === "::" ? ["", child.text] : [child.text];
            let j = i;
            while (children[j + 1]?.type === "::" && isIdent(children[j + 2])) {
                segments.push(children[j + 2].text);
                j += 2;
            }
            const next = children[j + 1];
            if (next?.type === "token_tree" && next.child(0)?.type === "(") {
                visitCall(resolver.resolve(segments), child, named(next).find(arg => !isComment(arg)) || null);
            } else if (next?.type === "!" && children[j + 2]?.type === "token_tree") {
                visitMacro(segments, children[j + 2], child);
            }
            i = j;
        }
    };

    const visitAttribute = (attribute, node) => {
        const segments = segmentsOf(named(attribute).find(child => !isComment(child)));
        if (!segments) return;
        const name = segments[segments.length - 1];
        if (segments.length === 1 && name === "unsafe") {
            const inner = named(attribute).find(child => child.type === "token_tree");
            const first = named(inner).find(child => !isComment(child));
            if (first && NATIVE_ATTRIBUTES.has(first.text)) native(`#[unsafe(${first.text})]`, node);
            return;
        }
        if (segments.length === 1 && NATIVE_ATTRIBUTES.has(name)) {
            native(`#[${name}]`, node);
            return;
        }
        if (segments.length === 1 && name === "path" && named(attribute).some(child => child.type === "string_literal")) {
            ops.diskRead = true;
            calls.filesystem.add("#[path]");
            return;
        }
        if (segments.length === 1 && /^proc_macro(_derive|_attribute)?$/.test(name)) {
            signal("compile_time_code", `#[${name}]`, node);
            return;
        }
        if (!HTTP_VERBS.includes(name) && name !== "route") return;
        const q = resolver.resolve(segments);
        const crate = q ? q.split("::")[0] : "";
        const fromCrate = ROUTE_ATTRIBUTE_CRATES.includes(crate)
            || (segments.length === 1 && q === name && ROUTE_ATTRIBUTE_CRATES.some(c => [...resolver.imports].some(i => i.split("::")[0] === c)));
        if (!fromCrate) return;
        const args = named(attribute).find(child => child.type === "token_tree");
        const path = args ? stringLiteral(named(args).find(child => child.type === "string_literal")) : null;
        if (path === null) return;
        addRoute(name === "route" ? path : `${name.toUpperCase()} ${path}`, node);
        ops.inboundHttp = true;
        signal("inbound_http", `#[${segments.join("::")}("${path}")]`, node);
    };

    walk(root, node => {
        switch (node.type) {
            case "call_expression": {
                const fn = field(node, "function");
                const args = field(node, "arguments");
                if (fn?.type === "field_expression") {
                    const method = text(field(fn, "field"));
                    if (method === "route" && args) {
                        const [pathArg, handler] = named(args);
                        const path = stringLiteral(pathArg);
                        if (path !== null && handler) {
                            const verbs = [];
                            walk(handler, inner => {
                                if (inner.type !== "call_expression") return;
                                const q = resolver.resolve(segmentsOf(field(inner, "function")));
                                if (q && ROUTE_HANDLERS.has(q)) verbs.push(q.split("::").pop());
                            });
                            const methodVerbs = [];
                            let chain = handler;
                            while (chain?.type === "call_expression" && field(chain, "function")?.type === "field_expression") {
                                const name = text(field(field(chain, "function"), "field"));
                                if (HTTP_VERBS.includes(name)) methodVerbs.push(name);
                                chain = field(field(chain, "function"), "value");
                            }
                            const all = [...new Set([...verbs, ...methodVerbs])].filter(v => HTTP_VERBS.includes(v));
                            if (verbs.length) {
                                if (all.length) for (const verb of all) addRoute(`${verb.toUpperCase()} ${path}`, pathArg);
                                else addRoute(path, pathArg);
                                ops.inboundHttp = true;
                                signal("inbound_http", `.route("${path}")`, node);
                            }
                        }
                    }
                    if (method === "ct_eq" && resolver.imports.has("subtle::ConstantTimeEq")) {
                        ops.cryptoUse = true;
                        ops.secretComparison = true;
                        calls.crypto.add("subtle::ConstantTimeEq::ct_eq");
                        signal("secret_comparison", "subtle::ConstantTimeEq::ct_eq", node);
                    }
                    break;
                }
                visitCall(resolver.resolve(segmentsOf(fn)), node, named(args)[0] || null);
                break;
            }
            case "macro_invocation": {
                const tokens = named(node).find(child => child.type === "token_tree");
                visitMacro(segmentsOf(field(node, "macro")), tokens, node);
                if (tokens) scanTokens(tokens);
                break;
            }
            case "macro_definition":
                for (const rule of named(node)) {
                    const right = field(rule, "right");
                    if (right) scanTokens(right);
                }
                break;
            case "macro_2_definition":
                scanTokens(node);
                break;
            case "unsafe_block":
                native("unsafe {}", node);
                break;
            case "function_item":
            case "function_signature_item": {
                const modifiers = named(node).find(child => child.type === "function_modifiers");
                if (!modifiers) break;
                const name = text(field(node, "name"));
                if (modifiers.children.some(child => child.type === "unsafe")) native(`unsafe fn ${name}`, node);
                const abi = named(modifiers).find(child => child.type === "extern_modifier");
                if (abi && node.type === "function_item") native(`extern ${abiText(abi)} fn ${name}`, node);
                break;
            }
            case "impl_item":
                if (node.children.some(child => child.type === "unsafe")) native(`unsafe impl ${codeText(field(node, "trait"))}`.trim(), node);
                break;
            case "trait_item":
                if (node.children.some(child => child.type === "unsafe")) native(`unsafe trait ${text(field(node, "name"))}`, node);
                break;
            case "foreign_mod_item": {
                const abi = named(node).find(child => child.type === "extern_modifier");
                native(`extern ${abiText(abi)} {}`, node);
                break;
            }
            case "attribute_item": {
                const attribute = named(node).find(child => child.type === "attribute");
                if (attribute) visitAttribute(attribute, node);
                break;
            }
            case "binary_expression": {
                const operator = text(field(node, "operator"));
                if (operator !== "==" && operator !== "!=") break;
                const sides = [field(node, "left"), field(node, "right")].map(text);
                if (sides.some(side => SECRETISH.test(side))) {
                    ops.secretComparison = true;
                    signal("secret_comparison", codeText(node).slice(0, 80), node);
                }
                break;
            }
            default:
                break;
        }
    });

    facts.routes = [...routes].sort((a, b) => a[1] - b[1]).map(([route]) => route);
    facts.exports = exportsOf(root);
    facts.imports = [...resolver.imports].sort();
    facts.env = [...env].sort();
    facts.calls = {
        network: [...calls.network].sort(),
        filesystem: [...calls.filesystem].sort(),
        process: [...calls.process].sort(),
        crypto: [...calls.crypto].sort(),
        dynamic: [...calls.dynamic].sort()
    };
    facts.dangerous = dangerousOf(ops);
    facts.riskSignals = signals;
    return facts;
}

const EXPORTED_ITEMS = new Set([
    "function_item", "struct_item", "enum_item", "union_item", "trait_item", "type_item",
    "const_item", "static_item", "mod_item", "trait_alias_item", "macro_2_definition"
]);

// Top-level items marked plain `pub` (not pub(crate)), `pub use` names and
// #[macro_export] macros.
function exportsOf(root) {
    const names = new Set();
    const children = named(root);
    for (let i = 0; i < children.length; i++) {
        const node = children[i];
        if (node.type === "macro_definition") {
            let k = i - 1;
            while (k >= 0 && children[k].type === "attribute_item") {
                if (/^#\s*\[\s*macro_export\b/.test(withoutComments(children[k]))) names.add(text(field(node, "name")));
                k--;
            }
            continue;
        }
        const visibility = named(node).find(child => child.type === "visibility_modifier");
        if (!visibility || visibility.text !== "pub") continue;
        if (EXPORTED_ITEMS.has(node.type)) {
            const name = text(field(node, "name"));
            if (name) names.add(name);
        } else if (node.type === "use_declaration") {
            const local = createResolver();
            const argument = field(node, "argument");
            if (argument) local.visitUse(argument, []);
            for (const name of local.aliases.keys()) names.add(name);
        }
    }
    names.delete("");
    names.delete("_");
    return [...names].sort();
}

// build.rs and proc macros run on the developer's machine during `cargo build`,
// so file access at run time (not include!/#[path], which the compiler reads),
// the network or secret-like environment variables there are at least high.
function compileTimeRisk(facts, risk) {
    if (risk !== "low" && risk !== "medium") return risk;
    const signals = facts?.riskSignals || [];
    if (!signals.some(s => s.signal === "build_script" || s.signal === "compile_time_code")) return risk;
    const ops = facts.operations || {};
    const files = (facts.calls?.filesystem || []).some(call => !COMPILER_READS.test(call));
    const touches = ((ops.diskRead || ops.diskWrite) && files) || ops.outboundHttp || ops.inboundHttp
        || signals.some(s => s.signal === "secret_access");
    return touches ? "high" : risk;
}

module.exports = { extract, compileTimeRisk };
