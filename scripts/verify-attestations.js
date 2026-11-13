// After `npm publish --provenance`, the registry should hold both the npm
// publish attestation (signed with a registry key; npm 10 needs it for
// `npm audit signatures`) and the SLSA provenance, and a fresh install must
// pass `npm audit signatures` on npm 10 and 11 as users run it. The registry
// is eventually consistent, so retry until the deadline, then fail the release.
const { spawn } = require("node:child_process");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const pkg = require("../package.json");
const name = pkg.name, version = process.argv[2] || pkg.version;
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

// npx runs in its own process group so a hung npm and its children are all killed.
function npx(args, cwd) {
    return new Promise((resolve, reject) => {
        const child = spawn("npx", args, { cwd, detached: true, stdio: ["ignore", "ignore", "pipe"] });
        let stderr = "";
        child.stderr.on("data", d => { stderr = (stderr + d).slice(-4000); });
        const timer = setTimeout(() => {
            try { process.kill(-child.pid, "SIGKILL"); } catch {}
            reject(new Error(`timed out after ${STEP_MS / 1000}s`));
        }, STEP_MS);
        child.on("error", e => { clearTimeout(timer); reject(e); });
        child.on("close", code => {
            clearTimeout(timer);
            code === 0 ? resolve() : reject(new Error(stderr || `exit code ${code}`));
        });
    });
}

async function audit(npm) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-"));
    const run = args => npx(["-y", `npm@${npm}`, ...args, "--cache", path.join(dir, ".npm-cache"), "--prefer-online"], dir);
    try {
        fs.writeFileSync(path.join(dir, "package.json"), "{}");
        await run(["install", "--ignore-scripts", "--no-audit", "--no-fund", `${name}@${version}`]);
        await run(["audit", "signatures"]);
        return null;
    } catch (e) {
        const lines = e.message.split("\n").filter(l => l.trim() && !l.includes("complete log"));
        return `npm ${npm} audit signatures: ${lines.slice(-2).join(" | ")}`;
    } finally {
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
