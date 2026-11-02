const test = require('node:test');
const assert = require('node:assert/strict');

const { analyzeAsync } = require('../src/sentinel-ir');
const CASES = require('./fixtures/python-labeled');

const RISK = new Set(['process_spawn', 'dynamic_code', 'unsafe_deserialization', 'native_code', 'destructive_fs', 'disk_write', 'outbound_http', 'crypto_use']);

for (const [id, code, expected] of CASES) {
    test(`labeled Python case: ${id}`, async () => {
        const ir = await analyzeAsync(code, { language: 'python' });
        assert.equal(ir.analysisStatus, 'complete');
        const got = [...new Set(ir.facts.riskSignals.map(s => s.signal).filter(s => RISK.has(s)))].sort();
        assert.deepEqual(got, [...expected].sort());
    });
}
