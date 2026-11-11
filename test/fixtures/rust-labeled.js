"use strict";

// Labeled Rust cases: the risk signals each snippet must produce, no more.
// Written by the analyzer's author, so they test the intent, not an
// independent ground truth.

module.exports = [
    // process
    ["command_full_path", "fn f() { std::process::Command::new(\"ls\").status(); }", ["process_spawn"]],
    ["command_use", "use std::process::Command;\nfn f() { Command::new(\"ls\").spawn(); }", ["child_process_import", "process_spawn"]],
    ["command_alias", "use std::process::Command as Cmd;\nfn f() { Cmd::new(\"sh\"); }", ["child_process_import", "process_spawn"]],
    ["command_list", "use std::process::{self, Command};\nfn f() { Command::new(\"sh\"); }", ["child_process_import", "process_spawn"]],
    ["command_glob", "use std::process::*;\nfn f() { Command::new(\"sh\"); }", ["child_process_import", "process_spawn"]],
    ["command_module", "use std::process;\nfn f() { process::Command::new(\"sh\"); }", ["process_spawn"]],
    ["command_absolute", "fn f() { ::std::process::Command::new(\"sh\"); }", ["process_spawn"]],
    ["tokio_command", "use tokio::process::Command;\nasync fn f() { Command::new(\"ls\").output().await; }", ["child_process_import", "process_spawn"]],
    ["command_in_macro_arg", "use std::process::Command;\nfn f() { println!(\"{:?}\", Command::new(\"id\").output()); }", ["child_process_import", "process_spawn"]],
    ["command_in_macro_rules", "use std::process::Command;\nmacro_rules! run { () => { Command::new(\"sh\") } }", ["child_process_import", "process_spawn"]],
    ["nix_exec", "use nix::unistd::execvp;\nfn f() { execvp(&a, &b); }", ["process_spawn"]],
    ["libc_system", "fn f() { unsafe { libc::system(c.as_ptr()); } }", ["native_code", "process_spawn"]],
    ["duct_macro", "use duct::cmd;\nfn f() { cmd!(\"ls\").run(); }", ["process_spawn"]],
    ["core_alias_root", "fn f() { core::ptr::null::<u8>(); }", []],
    // filesystem
    ["remove_dir_all", "use std::fs;\nfn f() { fs::remove_dir_all(\"/tmp/x\"); }", ["destructive_fs"]],
    ["remove_file_glob", "use std::fs::*;\nfn f() { remove_file(p); }", ["destructive_fs"]],
    ["tokio_remove", "async fn f() { tokio::fs::remove_file(p).await; }", ["destructive_fs"]],
    ["fs_write", "fn f() { std::fs::write(\"a\", b\"x\"); }", ["disk_write"]],
    ["file_create", "use std::fs::File;\nfn f() { File::create(\"a\"); }", ["disk_write"]],
    ["open_options_write", "use std::fs::OpenOptions;\nfn f() { OpenOptions::new().append(true).open(\"log\"); }", ["disk_write"]],
    ["open_options_read", "use std::fs::OpenOptions;\nfn f() { OpenOptions::new().read(true).open(\"log\"); }", []],
    ["open_options_write_false", "use std::fs::OpenOptions;\nfn f() { OpenOptions::new().read(true).write(false).open(\"log\"); }", []],
    ["fs_read_only", "fn f() { std::fs::read_to_string(\"a\"); }", []],
    ["fs_err_remove", "fn f() { fs_err::remove_dir_all(p); }", ["destructive_fs"]],
    ["local_remove_file", "fn remove_file(p: &str) {}\nfn f() { remove_file(\"x\"); }", []],
    ["method_remove_file", "fn f(s: S) { s.remove_file(\"x\"); }", []],
    // network
    ["reqwest_get", "async fn f() { reqwest::get(\"https://x\").await; }", ["outbound_http"]],
    ["reqwest_client", "use reqwest::Client;\nfn f() { Client::new(); }", ["outbound_http"]],
    ["tcp_connect", "use std::net::TcpStream;\nfn f() { TcpStream::connect(\"1.2.3.4:80\"); }", ["outbound_http"]],
    ["ureq_get", "fn f() { ureq::get(\"https://x\").call(); }", ["outbound_http"]],
    // native code
    ["unsafe_block", "fn f() { unsafe { *p = 1; } }", ["native_code"]],
    ["unsafe_fn", "pub unsafe fn f() {}", ["native_code"]],
    ["unsafe_impl", "unsafe impl Send for S {}", ["native_code"]],
    ["unsafe_trait", "unsafe trait T {}", ["native_code"]],
    ["extern_block", "extern \"C\" { fn abs(x: i32) -> i32; }", ["native_code"]],
    ["extern_fn", "pub extern \"C\" fn cb() {}", ["native_code"]],
    ["no_mangle", "#[no_mangle]\npub fn f() {}", ["native_code"]],
    ["unsafe_no_mangle", "#[unsafe(no_mangle)]\npub fn f() {}", ["native_code"]],
    ["libloading", "use libloading::Library;\nfn f() { Library::new(\"x.so\"); }", ["native_code"]],
    ["unsafe_in_macro_arg", "fn f() { println!(\"{}\", unsafe { *p }); }", ["native_code"]],
    ["asm_macro", "use std::arch::asm;\nfn f() { asm!(\"nop\"); }", ["native_code"]],
    ["safe_code", "fn add(a: i32, b: i32) -> i32 { a + b }", []],
    ["forbid_unsafe_attr", "#![forbid(unsafe_code)]\nfn f() {}", []],
    ["unsafe_in_string", "fn f() { let s = \"unsafe { x }\"; }", []],
    ["unsafe_in_comment", "// unsafe { Command::new(\"sh\") }\nfn f() {}", []],
    // dynamic code
    ["rhai_engine", "fn f() { let e = rhai::Engine::new(); e.eval::<i64>(s); }", ["dynamic_code"]],
    ["mlua", "use mlua::Lua;\nfn f() { Lua::new(); }", ["dynamic_code"]],
    // crypto
    ["sha2", "use sha2::{Digest, Sha256};\nfn f() { Sha256::new(); }", ["crypto_use"]],
    ["ring_digest", "fn f() { ring::digest::digest(&ring::digest::SHA256, b); }", ["crypto_use"]]
];
