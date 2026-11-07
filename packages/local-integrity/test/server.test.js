import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';
import http from 'node:http';
async function withApp(t, options = {}) {
  const server = createApp({ rateLimit: 1000, ...options });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const base = `http://127.0.0.1:${server.address().port}`;
  return (path, init) => fetch(base + path, init);
}
const upload = (body = 'abc') => ({ method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'X-Trust-Protocol': '1' }, body });
test('Startseite und CSP', async t => { const call = await withApp(t), r = await call('/'); assert.equal(r.status, 200); assert.ok(r.headers.get('content-security-policy').includes("script-src 'self'")); assert.ok((await r.text()).includes('Trust Protocol')); });
test('Health meldet Grenzen explizit', async t => { const call = await withApp(t), d = await (await call('/v1/health')).json(); assert.equal(d.capabilities.c2pa, false); assert.equal(d.capabilities.sha256, true); });
test('Upload, Abfrage und Löschen', async t => {
  const call = await withApp(t), r = await call('/v1/analyze?filename=test.txt', upload()); assert.equal(r.status, 202);
  const created = await r.json(), result = await (await call(created.status_url)).json();
  assert.equal(result.filename, 'test.txt'); assert.equal(result.verdict, 'UNVERIFIED'); assert.equal(result.size_bytes, 3);
  assert.equal((await call(created.status_url, { method: 'DELETE', headers: { 'X-Trust-Protocol': '1' } })).status, 204);
  assert.equal((await call(created.status_url)).status, 404);
});
test('Keine Uploads ohne Client-Header', async t => { const call = await withApp(t); assert.equal((await call('/v1/analyze', { method: 'POST', body: 'abc' })).status, 403); });
test('Fremder Origin abgelehnt', async t => { const call = await withApp(t); assert.equal((await call('/v1/health', { headers: { Origin: 'https://evil.example' } })).status, 403); });
test('DNS-Rebinding-Host abgelehnt', async t => {
  const server = createApp();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const status = await new Promise((resolve, reject) => {
    const req = http.get({ hostname: '127.0.0.1', port: server.address().port, path: '/v1/health', headers: { Host: 'evil.example:3000' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
  });
  assert.equal(status, 403);
});
test('Übergröße abgelehnt', async t => { const call = await withApp(t, { maxBytes: 2 }); assert.equal((await call('/v1/analyze', upload())).status, 413); });
test('Übergröße auch ohne Content-Length abgelehnt', async t => {
  const call = await withApp(t, { maxBytes: 2 });
  const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode('abc')); c.close(); } });
  assert.equal((await call('/v1/analyze', { ...upload(stream), duplex: 'half' })).status, 413);
});
test('Leerer Upload abgelehnt', async t => { const call = await withApp(t); assert.equal((await call('/v1/analyze', upload(''))).status, 400); });
test('Falscher Content-Type abgelehnt', async t => { const call = await withApp(t); const opts = upload(); opts.headers['Content-Type'] = 'text/plain'; assert.equal((await call('/v1/analyze', opts)).status, 415); });
test('Ungültiger Referenzwert abgelehnt', async t => { const call = await withApp(t); assert.equal((await call('/v1/analyze?expected_sha256=bad', upload())).status, 400); });
test('Befunde laufen ab', async t => { const call = await withApp(t, { ttlMs: 25 }); const job = await (await call('/v1/analyze', upload())).json(); await new Promise(r => setTimeout(r, 50)); assert.equal((await call(job.status_url)).status, 404); });
test('Begrenzter Ergebnisspeicher', async t => { const call = await withApp(t, { maxJobs: 1 }); assert.equal((await call('/v1/analyze', upload())).status, 202); assert.equal((await call('/v1/analyze', upload())).status, 503); });
test('Rate-Limit greift', async t => { const call = await withApp(t, { rateLimit: 1 }); assert.equal((await call('/v1/health')).status, 200); assert.equal((await call('/v1/health')).status, 429); });
test('Dateien außerhalb Allowlist nicht erreichbar', async t => { const call = await withApp(t); assert.equal((await call('/server.js')).status, 404); assert.equal((await call('/lib/encrypt.js')).status, 404); });
test('Simulation und unbekannte Demo', async t => { const call = await withApp(t); assert.equal((await (await call('/v1/demo/revoked_cert')).json()).mode, 'SIMULATION'); assert.equal((await call('/v1/demo/toString')).status, 404); });
