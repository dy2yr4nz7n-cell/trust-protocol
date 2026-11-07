import test from 'node:test';
import assert from 'node:assert/strict';
import { createRuntime } from '../server.js';
import { readFile } from 'node:fs/promises';
import { createAuth } from '../apps/verifier/auth.js';

test('workspace serves only public files and degrades safely without credentials', async () => {
  const runtime = await createRuntime({ secret: '' });
  await new Promise(resolve => runtime.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${runtime.server.address().port}`;
  try {
    const health = await fetch(base + '/health');
    assert.equal(health.status, 200);
    assert.equal((await health.json()).apiConfigured, false);
    for (const path of ['/', '/protocol/', '/simulator/', '/verifier/']) {
      const response = await fetch(base + path);
      assert.equal(response.status, 200, path);
      assert.match(await response.text(), /<!doctype html>/i);
    }
    assert.equal((await fetch(base + '/api/capabilities')).status, 503);
    for (const path of ['/.env', '/.git/config', '/server.js', '/package.json', '/%2e%2e%2fserver.js', '/missing']) {
      assert.equal((await fetch(base + path)).status, 404, path);
    }
    assert.equal((await fetch(base, { method: 'POST' })).status, 405);
  } finally { await runtime.close(); }
});

test('protected API requires signed access token; invalid secret fails startup', async () => {
  await assert.rejects(createRuntime({ secret: 'short' }), /JWT_SECRET/);
  const runtime = await createRuntime({ secret: 'test-only-secret-that-is-long-enough-for-tests', databasePath: ':memory:' });
  await new Promise(resolve => runtime.server.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${runtime.server.address().port}/api/capabilities`);
    assert.equal(response.status, 401);
  } finally { await runtime.close(); }
});

test('real C2PA CLI and authenticated multipart API', { skip: !process.env.C2PA_TEST_SIGNED_FILE }, async () => {
  const secret = 'test-only-secret-that-is-long-enough-for-tests';
  const runtime = await createRuntime({ secret, origin: 'http://127.0.0.1:3000', databasePath: ':memory:' });
  await new Promise(resolve => runtime.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${runtime.server.address().port}`;
  try {
    const token = createAuth(secret).createAccessToken({ id: 'integration-test' });
    const headers = { Authorization: `Bearer ${token}`, Origin: 'http://127.0.0.1:3000' };
    const capabilities = await fetch(base + '/api/capabilities', { headers });
    assert.equal(capabilities.status, 200);
    assert.equal((await capabilities.json()).available, true);
    for (const [filename, expected] of [[process.env.C2PA_TEST_SIGNED_FILE, 'valid_untrusted'], [null, 'absent']]) {
      const form = new FormData();
      const bytes = filename ? await readFile(filename) : Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64');
      form.append('file', new Blob([bytes], { type: filename ? 'image/jpeg' : 'image/png' }), filename ? 'test.jpg' : 'test.png');
      const result = await fetch(base + '/api/verify', { method: 'POST', headers, body: form });
      assert.equal(result.status, 200);
      const body = await result.json();
      assert.equal(body.provenance, expected);
      assert.equal(body.generation.detectorUsed, false);
    }
    assert.equal((await fetch(base + '/api/capabilities', { headers: { ...headers, Origin: 'https://unrelated.invalid' } })).status, 403);
  } finally { await runtime.close(); }
});
