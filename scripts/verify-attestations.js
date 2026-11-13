// After `npm publish --provenance`, the registry should hold both the npm
// publish attestation (signed with a registry key; npm 10 needs it for
// `npm audit signatures`) and the SLSA provenance, and a fresh install must
// pass `npm audit signatures` on npm 10 and 11 as users run it. The registry
// is eventually consistent, so retry until the deadline, then fail the release.
const { execFileSync } = require("node:child_process");
const fs = require("node:fs"), os = require("node:os"), path = require("node:path");
const pkg = require("../package.json");
const name = pkg.name, version = process.argv[2] || pkg.version;
const want = ["https://github.com/npm/attestation/tree/main/specs/publish/v0.1", "https://slsa.dev/provenance/v0.2"];
const npms = ["10", "11"];
const deadline = Date.now() + Number(process.env.ATTEST_TIMEOUT_MS || 600000);

async function attestations() {
    let have = [];
    try {
        const res = await fetch(`https://registry.npmjs.org/-/npm/v1/attestations/${name}@${version}`, { headers: { "cache-control": "no-cache" } });
        if (res.ok) have = (await res.json()).attestations.map(a => a.predicateType);
    } catch {}
    const missing = want.filter(t => !have.includes(t));
    return missing.length ? `missing attestation(s): ${missing.join(", ")}` : null;
}

function audit(npm) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "verify-"));
    const run = args => execFileSync("npx", ["-y", `npm@${npm}`, ...args], { cwd: dir, stdio: "pipe", encoding: "utf8" });
    try {
        fs.writeFileSync(path.join(dir, "package.json"), "{}");
        run(["install", "--ignore-scripts", "--no-audit", "--no-fund", `${name}@${version}`]);
        run(["audit", "signatures"]);
        return null;
    } catch (e) {
        const lines = String(e.stderr || e.message).split("\n").filter(l => l.trim() && !l.includes("complete log"));
        return `npm ${npm} audit signatures: ${lines.slice(-2).join(" | ")}`;
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

(async () => {
    for (;;) {
        const problem = await attestations() || npms.map(audit).find(Boolean);
        if (!problem) return console.log(`${name}@${version}: attestations present, npm audit signatures passes on npm ${npms.join(" and ")}`);
        if (Date.now() > deadline) {
            console.error(`${name}@${version}: ${problem}`);
            process.exit(1);
        }
        console.log(`${name}@${version}: ${problem}; retrying`);
        await new Promise(r => setTimeout(r, 15000));
    }
})();
