"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.join(__dirname, "..");

// Every local require() reachable from a packed file must be packed too.
test("npm pack contains every module the package requires", () => {
    const listed = new Set(require(path.join(ROOT, "package.json")).files);
    for (const file of [...listed].filter(f => f.endsWith(".js"))) {
        const source = fs.readFileSync(path.join(ROOT, file), "utf8");
        for (const [, spec] of source.matchAll(/require\(\s*["'](\.{1,2}\/[^"']+)["']\s*\)/g)) {
            if (spec.endsWith(".node")) continue;
            let target = path.relative(ROOT, path.resolve(path.dirname(path.join(ROOT, file)), spec)).split(path.sep).join("/");
            if (!target.endsWith(".js") && target !== "package.json") target += ".js";
            assert.ok(listed.has(target) || target === "package.json", `${file} requires ${target}, missing from package.json "files"`);
        }
    }
});

test("the packed tarball loads and analyzes every language", { timeout: 120000 }, () => {
    const dir = fs.mkdtempSync(path.join(ROOT, ".pack-"));
    try {
        const npm = process.platform === "win32" ? "npm.cmd" : "npm";
        const [{ filename }] = JSON.parse(execFileSync(npm, ["pack", "--json", "--pack-destination", dir], { cwd: ROOT, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }));
        execFileSync("tar", ["-xzf", path.join(dir, filename), "-C", dir]);
        const script = `
            const S = require(${JSON.stringify(path.join(dir, "package"))});
            (async () => {
                const out = [];
                for (const [code, target] of [["require('child_process').exec(c)", "a.js"], ["const x: number = 1", "a.ts"], ["import os\\nos.system(c)", "a.py"], ["fn main() { std::process::Command::new(c); }", "a.rs"]]) {
                    const ir = await S.analyzeAsync(code, { target });
                    out.push([ir.language, ir.analysisStatus, ir.risk]);
                }
                console.log(JSON.stringify(out));
            })();
        `;
        const out = JSON.parse(execFileSync(process.execPath, ["-e", script], { cwd: dir, encoding: "utf8" }));
        assert.deepEqual(out, [
            ["javascript", "complete", "critical"],
            ["typescript", "complete", "low"],
            ["python", "complete", "critical"],
            ["rust", "complete", "critical"]
        ]);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
