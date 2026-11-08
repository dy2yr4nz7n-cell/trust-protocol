import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, stat, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/docker-entrypoint.sh', import.meta.url));

test('entrypoint overrides an open umask for new runtime directories and files', { skip: process.platform === 'win32' }, async t => {
  const dir = await mkdtemp(join(tmpdir(), 'trust-private-data-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin');
  const data = join(dir, 'runtime data');
  await mkdir(bin);
  // Simulate the non-root branch; this test does not change OS identity.
  await writeFile(join(bin, 'id'), '#!/bin/sh\necho 1000\n', { mode: 0o755 });
  const childCode = 'require("node:fs").writeFileSync(require("node:path").join(process.env.DATA_DIR, "audit.json"), "{}")';
  const result = spawnSync('/bin/sh', [
    '-c', 'umask 000; exec /bin/sh "$@"',
    'test-entrypoint', script, process.execPath, '-e', childCode
  ], {
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, DATA_DIR: data },
    encoding: 'utf8',
    timeout: 5000
  });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
  assert.equal((await stat(data)).mode & 0o777, 0o700);
  assert.equal((await stat(join(data, 'audit.json'))).mode & 0o777, 0o600);
});
