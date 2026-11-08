import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, chmod, stat, lstat, symlink, readdir, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { writePrivateFile } from '../scripts/private-file.mjs';

async function directory(t) {
  const dir = await mkdtemp(join(tmpdir(), 'trust-private-write-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

test('new token files are private', { skip: process.platform === 'win32' }, async t => {
  const dir = await directory(t);
  const token = join(dir, 'access-token.txt');
  await writePrivateFile(token, 'test-token\n');
  assert.equal(await readFile(token, 'utf8'), 'test-token\n');
  assert.equal((await stat(token)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(dir), ['access-token.txt']);
});

test('replacement removes previously open file permissions', { skip: process.platform === 'win32' }, async t => {
  const dir = await directory(t);
  const token = join(dir, 'access-token.txt');
  await writeFile(token, 'old');
  await chmod(token, 0o666);
  await writePrivateFile(token, 'replacement');
  assert.equal(await readFile(token, 'utf8'), 'replacement');
  assert.equal((await stat(token)).mode & 0o777, 0o600);
});

test('a destination symlink is replaced without writing its target', { skip: process.platform === 'win32' }, async t => {
  const dir = await directory(t);
  const target = join(dir, 'untouched.txt');
  const token = join(dir, 'access-token.txt');
  await writeFile(target, 'original');
  await symlink(target, token);
  await writePrivateFile(token, 'test-token');
  assert.equal(await readFile(target, 'utf8'), 'original');
  assert.equal(await readFile(token, 'utf8'), 'test-token');
  assert.equal((await lstat(token)).isSymbolicLink(), false);
});

test('failed replacement removes the temporary directory', async t => {
  const dir = await directory(t);
  const target = join(dir, 'existing-directory');
  await mkdir(target);
  await assert.rejects(writePrivateFile(target, 'test-token'));
  assert.deepEqual(await readdir(dir), ['existing-directory']);
});
