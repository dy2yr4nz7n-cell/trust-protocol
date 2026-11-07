import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createRuntime } from '../server.js';
import { createAuth } from '../apps/verifier/auth.js';

test('inspection stores reports across restart and isolates token owners', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'trust-audit-test-'));
  const secret = 'test-only-secret-with-at-least-thirty-two-bytes';
  const options = { secret, origin: 'http://127.0.0.1:3000', databasePath: join(dir, 'audits.sqlite') };
  const auth = createAuth(secret);
  const headers = id => ({ Authorization: `Bearer ${auth.createAccessToken({ id })}`, Origin: options.origin });
  const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64');
  let runtime;
  async function start() {
    runtime = await createRuntime(options);
    await new Promise(resolve => runtime.server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${runtime.server.address().port}/api/inspection`;
  }
  try {
    let base = await start();
    assert.equal((await fetch(base + '/audits')).status, 401);
    const form = new FormData();
    form.append('file', new Blob([png], { type: 'application/octet-stream' }), 'unsafe-name.png');
    form.append('consent', 'yes');
    const response = await fetch(base + '/verify', { method: 'POST', headers: headers('alice'), body: form });
    assert.equal(response.status, 200);
    const report = await response.json();
    assert.equal(report.file.mime, 'image/png');
    assert.equal(report.file.bytes, png.length);
    assert.equal(report.file.sha256.length, 64);
    assert.equal(report.interpretation.authenticity, 'NOT_DETERMINED');
    assert.equal((await (await fetch(base + '/audits', { headers: headers('alice') })).json()).audits.length, 1);
    assert.equal((await (await fetch(base + '/audits', { headers: headers('bob') })).json()).audits.length, 0);
    assert.equal((await fetch(`${base}/audits/${report.id}`, { headers: headers('bob') })).status, 404);
    const download = await fetch(`${base}/audits/${report.id}/export`, { headers: headers('alice') });
    assert.equal(download.status, 200);
    assert.match(download.headers.get('content-disposition'), /attachment/);
    assert.equal((await download.json()).file.sha256, report.file.sha256);
    const noConsent = new FormData(); noConsent.append('file', new Blob([png]), 'test.png');
    assert.equal((await fetch(base + '/verify', { method: 'POST', headers: headers('alice'), body: noConsent })).status, 400);
    const invalid = new FormData(); invalid.append('file', new Blob(['not an image']), 'fake.jpg'); invalid.append('consent', 'yes');
    assert.equal((await fetch(base + '/verify', { method: 'POST', headers: headers('alice'), body: invalid })).status, 415);
    await runtime.close(); runtime = null;
    base = await start();
    assert.equal((await (await fetch(base + '/audits', { headers: headers('alice') })).json()).audits.length, 1);
  } finally { if (runtime) await runtime.close(); await rm(dir, { recursive: true, force: true }); }
});
