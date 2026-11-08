import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/docker-entrypoint.sh', import.meta.url));
const cases = [
  { name: 'failed id command', source: '#!/bin/sh\nexit 1\n', message: /cannot determine container user/ },
  { name: 'invalid user ID', source: '#!/bin/sh\necho invalid-user\n', message: /invalid container user ID/ }
];

for (const item of cases) {
  test(`entrypoint refuses startup with ${item.name}`, { skip: process.platform === 'win32' }, async t => {
    const dir = await mkdtemp(join(tmpdir(), 'trust-entrypoint-identity-'));
    t.after(() => rm(dir, { recursive: true, force: true }));
    const bin = join(dir, 'bin');
    await mkdir(bin);
    await writeFile(join(bin, 'id'), item.source, { mode: 0o755 });
    const marker = join(dir, 'command-executed');
    const data = join(dir, 'data');
    const result = spawnSync('/bin/sh', [script, process.execPath, '-e', 'require("node:fs").writeFileSync(process.argv[1], "executed")', marker], {
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, DATA_DIR: data },
      encoding: 'utf8',
      timeout: 5000
    });
    assert.ifError(result.error);
    assert.equal(result.status, 70, result.stderr);
    assert.match(result.stderr, item.message);
    await assert.rejects(access(marker), { code: 'ENOENT' });
    await assert.rejects(access(data), { code: 'ENOENT' });
  });
}
