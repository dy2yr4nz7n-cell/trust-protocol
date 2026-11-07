import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../scripts/docker-entrypoint.sh', import.meta.url));

async function setup(t, uid) {
  const dir = await mkdtemp(join(tmpdir(), 'trust-entrypoint-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const bin = join(dir, 'bin');
  await mkdir(bin);
  const log = join(dir, 'calls');
  await writeFile(log, '');
  const commands = {
    id: `#!/bin/sh\nprintf '%s\\n' '${uid}'\n`,
    chown: '#!/bin/sh\nprintf \'chown\\n\' >> "$ENTRYPOINT_TEST_LOG"\n',
    gosu: '#!/bin/sh\nprintf \'gosu:%s\\n\' "$1" >> "$ENTRYPOINT_TEST_LOG"\nshift\nexec "$@"\n'
  };
  for (const [name, source] of Object.entries(commands)) {
    await writeFile(join(bin, name), source.replaceAll('\\n', '\n'), { mode: 0o755 });
  }
  const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, DATA_DIR: join(dir, 'runtime data'), ENTRYPOINT_TEST_LOG: log };
  return { env, log };
}

for (const uid of [0, 1000]) {
  test(`entrypoint executes command and exports DATA_DIR for uid ${uid}`, { skip: process.platform === 'win32' }, async t => {
    const { env, log } = await setup(t, uid);
    const result = spawnSync('/bin/sh', [script, process.execPath, '-e', 'process.stdout.write(JSON.stringify({data:process.env.DATA_DIR,args:process.argv.slice(1)}))', 'argument with spaces'], { env, encoding: 'utf8', timeout: 5000 });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { data: env.DATA_DIR, args: ['argument with spaces'] });
    assert.equal(await readFile(log, 'utf8'), uid === 0 ? 'chown\ngosu:node\n' : '');
  });
}

test('entrypoint rejects an absent command before touching the data directory', { skip: process.platform === 'win32' }, () => {
  const result = spawnSync('/bin/sh', [script], { env: { ...process.env, DATA_DIR: '/not-used-by-this-test' }, encoding: 'utf8', timeout: 5000 });
  assert.ifError(result.error);
  assert.equal(result.status, 64);
  assert.match(result.stderr, /no container command supplied/);
});
