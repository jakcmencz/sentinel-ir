#!/usr/bin/env node
"use strict";

// Recall of the Python risk signals against Bandit's own example findings.
// Usage: node scripts/python-recall.js <bandit checkout>/examples
// A finding counts as found when the matching signal is on one of its lines.

const fs = require("fs");
const path = require("path");
const { analyzeAsync } = require("../src/sentinel-ir");
const fixture = require("../test/fixtures/bandit-1.8.6-findings.json");

const SIGNALS = {
    process_spawn: ["process_spawn"],
    dynamic_code: ["dynamic_code"],
    unsafe_deserialization: ["unsafe_deserialization"],
    crypto_use: ["crypto_use"],
    outbound_http: ["outbound_http"],
    filesystem: ["disk_write", "destructive_fs"]
};

// Recall below this fails the run (measured for 0.3.1). Bandit also reports
// client constructors (httpx.Client(), URLopener()) that do no I/O
// themselves; their later .get()/.open() calls are what sentinel-ir reports.
const MIN_RECALL = {
    process_spawn: 1, dynamic_code: 1, unsafe_deserialization: 1, crypto_use: 1, outbound_http: 0.81, filesystem: 1
};

async function main() {
    const dir = process.argv[2];
    if (!dir) throw new Error("usage: node scripts/python-recall.js <bandit>/examples");
    const signals = new Map();
    for (const file of new Set(fixture.findings.map(f => f.file))) {
        const ir = await analyzeAsync(fs.readFileSync(path.join(dir, file), "utf8"), { language: "python" });
        signals.set(file, ir.facts.riskSignals);
    }
    let failed = false;
    const missed = [];
    console.log("category                 found / bandit  recall  min");
    for (const [category, names] of Object.entries(SIGNALS)) {
        const findings = fixture.findings.filter(f => f.category === category);
        const found = findings.filter(f => signals.get(f.file).some(s =>
            names.includes(s.signal) && s.line >= f.lines[0] && s.line <= f.lines[1]));
        for (const f of findings) if (!found.includes(f)) missed.push(`${f.file}:${f.lines[0]} ${f.test} (${category})`);
        const recall = findings.length ? found.length / findings.length : 1;
        if (recall + 1e-9 < MIN_RECALL[category]) failed = true;
        console.log(`${category.padEnd(24)} ${String(found.length).padStart(5)} / ${String(findings.length).padEnd(6)}  ${recall.toFixed(2)}    ${MIN_RECALL[category]}`);
    }
    const total = fixture.findings.length;
    console.log(`total                    ${total - missed.length} / ${total}`);
    for (const m of missed) console.log(`missed ${m}`);
    if (failed) {
        console.error("recall dropped below the measured minimum");
        process.exit(1);
    }
}

main().catch(error => {
    console.error(error);
    process.exit(1);
});
