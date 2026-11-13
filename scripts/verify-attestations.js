// After `npm publish --provenance`, the registry should hold both the npm
// publish attestation (signed with a registry key; npm 10 needs it for
// `npm audit signatures`) and the SLSA provenance, and a fresh install must
// pass `npm audit signatures` on npm 10 and 11 as users run it. The registry
// is eventually consistent, so retry until the deadline, then fail the release.
const { spawn } = require("node:child_process");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const pkg = require("../package.json");
// Argument: a version of this package, or name@version (used by the CI self-test).
const spec = process.argv[2] || pkg.version, at = spec.lastIndexOf("@");
const name = at > 0 ? spec.slice(0, at) : pkg.name;
const version = at > 0 ? spec.slice(at + 1) : spec;
const want = ["https://github.com/npm/attestation/tree/main/specs/publish/v0.1", "https://slsa.dev/provenance/v0.2"];
const npms = ["10", "11"];
const timeoutMs = Number(process.env.ATTEST_TIMEOUT_MS || 600000);
if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
    console.error(`ATTEST_TIMEOUT_MS must be a non-negative number of milliseconds`);
    process.exit(2);
}
const deadline = Date.now() + timeoutMs;
const STEP_MS = 180000;

async function attestations() {
    let have = [];
    try {
        const res = await fetch(`https://registry.npmjs.org/-/npm/v1/attestations/${encodeURIComponent(name)}@${encodeURIComponent(version)}`,
            { headers: { "cache-control": "no-cache" }, signal: AbortSignal.timeout(30000) });
        if (res.ok) have = (await res.json()).attestations.map(a => a.predicateType);
    } catch {}
    const missing = want.filter(t => !have.includes(t));
    return missing.length ? `missing attestation(s): ${missing.join(", ")}` : null;
}

// npx runs in its own process group so a hung npm and its children are all
// killed, on timeout and when this job is cancelled.
let active = null;
for (const [sig, code] of [["SIGINT", 130], ["SIGTERM", 143]]) {
    process.on(sig, () => {
        if (active) {
            try { process.kill(-active.pid, "SIGKILL"); } catch {}
            fs.rmSync(active.dir, { recursive: true, force: true });
        }
        process.exit(code);
    });
}

function npx(args, dir) {
    return new Promise((resolve, reject) => {
        const child = spawn("npx", args, { cwd: dir, detached: true, stdio: ["ignore", "pipe", "pipe"] });
        active = { pid: child.pid, dir };
        let out = "", err = "";
        child.stdout.on("data", d => { out = (out + d).slice(-4000); });
        child.stderr.on("data", d => { err = (err + d).slice(-4000); });
        const timer = setTimeout(() => {
            try { process.kill(-child.pid, "SIGKILL"); } catch {}
            reject(new Error(`timed out after ${STEP_MS / 1000}s`));
        }, STEP_MS);
        child.on("error", e => { clearTimeout(timer); reject(e); });
        child.on("close", code => {
            clearTimeout(timer);
            code === 0 ? resolve(out) : reject(new Error(`${out}\n${err}`.trim() || `exit code ${code}`));
        });
    });
}

async function audit(npm) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-"));
    const run = args => npx(["-y", `npm@${npm}`, ...args, "--cache", path.join(dir, ".npm-cache"), "--prefer-online"], dir);
    try {
        fs.writeFileSync(path.join(dir, "package.json"), "{}");
        await run(["install", "--ignore-scripts", "--no-audit", "--no-fund", `${name}@${version}`]);
        const installed = JSON.parse(fs.readFileSync(path.join(dir, "node_modules", name, "package.json"), "utf8")).version;
        if (installed !== version) throw new Error(`installed ${installed}, expected ${version}`);
        const out = await run(["audit", "signatures"]);
        if (!/verified attestation/.test(out)) throw new Error(`no verified attestations reported: ${out.trim() || "(no output)"}`);
        return null;
    } catch (e) {
        const lines = e.message.split("\n").filter(l => l.trim() && !l.includes("complete log"));
        return `npm ${npm} audit signatures: ${lines.slice(-2).join(" | ")}`;
    } finally {
        active = null;
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

async function check() {
    const missing = await attestations();
    if (missing) return missing;
    for (const npm of npms) {
        const problem = await audit(npm);
        if (problem) return problem;
    }
    return null;
}

(async () => {
    for (;;) {
        const problem = await check();
        if (!problem) return console.log(`${name}@${version}: attestations present, npm audit signatures passes on npm ${npms.join(" and ")}`);
        if (Date.now() > deadline) {
            console.error(`${name}@${version}: ${problem}`);
            process.exit(1);
        }
        console.log(`${name}@${version}: ${problem}; retrying`);
        await new Promise(r => setTimeout(r, 15000));
    }
})();
