// After `npm publish --provenance`, the registry should hold both the npm
// publish attestation (signed with a registry key; npm 10 needs it for
// `npm audit signatures`) and the SLSA provenance. Fail the release if not.
const pkg = require("../package.json");
const name = pkg.name, version = process.argv[2] || pkg.version;
const want = ["https://github.com/npm/attestation/tree/main/specs/publish/v0.1", "https://slsa.dev/provenance/v0.2"];
const deadline = Date.now() + Number(process.env.ATTEST_TIMEOUT_MS || 600000);

(async () => {
    let have = [];
    for (;;) {
        try {
            const res = await fetch(`https://registry.npmjs.org/-/npm/v1/attestations/${name}@${version}`, { headers: { "cache-control": "no-cache" } });
            if (res.ok) have = (await res.json()).attestations.map(a => a.predicateType);
        } catch {}
        const missing = want.filter(t => !have.includes(t));
        if (!missing.length) return console.log(`${name}@${version}: publish attestation and provenance present`);
        if (Date.now() > deadline) {
            console.error(`${name}@${version}: missing attestation(s): ${missing.join(", ")}`);
            process.exit(1);
        }
        await new Promise(r => setTimeout(r, 15000));
    }
})();
