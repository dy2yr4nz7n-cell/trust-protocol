import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

// Static policy test: Docker build-context matching is checked by Docker,
// not reimplemented here. This does not scan image layers for secrets.
const ignoreFile = new URL('../.dockerignore', import.meta.url);

test('Docker context policy excludes local sensitive and generated files', async () => {
  const lines = (await readFile(ignoreFile, 'utf8'))
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  const required = [
    '**/.git', '**/node_modules',
    '.env', '.env.*', '**/.env', '**/.env.*',
    'access-token.txt', '**/access-token.txt',
    '.npmrc', '**/.npmrc', '**/.ssh', '**/.aws',
    'data', '**/data', 'uploads', '**/uploads',
    '**/*.sqlite', '**/*.sqlite3', '**/*.sqlite-*', '**/*.sqlite3-*',
    '**/coverage', '**/playwright-report', '**/test-results', '**/blob-report'
  ];
  for (const pattern of required) {
    assert.ok(lines.includes(pattern), `Missing Docker exclusion: ${pattern}`);
  }
  assert.deepEqual(
    lines.filter(line => line.startsWith('!')),
    ['!/.env.example'],
    'Only the root environment example may be explicitly re-included'
  );
  const exampleIndex = lines.indexOf('!/.env.example');
  assert.ok(exampleIndex > lines.indexOf('**/.env.*'));
});
