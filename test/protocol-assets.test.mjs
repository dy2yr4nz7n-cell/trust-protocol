import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PROTOCOL_ASSETS, copyProtocolAssets } from '../scripts/protocol-assets.mjs';

test('protocol build copies only explicitly approved browser assets', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'trust-public-assets-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const source = join(dir, 'source');
  const target = join(dir, 'public');
  await mkdir(source);
  await mkdir(target);
  for (const file of PROTOCOL_ASSETS) await writeFile(join(source, file), `fixture:${file}`);
  for (const file of ['server.js', 'vitest.config.js', 'private-config.js', 'sw.js', '.env']) {
    await writeFile(join(source, file), 'MUST NOT BE PUBLISHED');
  }
  await copyProtocolAssets(source, target);
  assert.deepEqual((await readdir(target)).sort(), [...PROTOCOL_ASSETS].sort());
  for (const file of PROTOCOL_ASSETS) {
    assert.equal(await readFile(join(target, file), 'utf8'), `fixture:${file}`);
  }
});

test('protocol build fails when a required asset is missing', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'trust-missing-assets-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const target = join(dir, 'public');
  await mkdir(target);
  await assert.rejects(copyProtocolAssets(dir, target), { code: 'ENOENT' });
});
