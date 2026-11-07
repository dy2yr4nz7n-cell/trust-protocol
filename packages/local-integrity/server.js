import http from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { InputError, validateExpectedHash, createResult, getDemo } from './engine.js';

const root = fileURLToPath(new URL('./frontend/', import.meta.url));
const assets = new Map([
  ['/', ['text/html; charset=utf-8', readFileSync(root + 'index.html')]],
  ['/app.js', ['text/javascript; charset=utf-8', readFileSync(root + 'app.js')]],
  ['/styles.css', ['text/css; charset=utf-8', readFileSync(root + 'styles.css')]]
]);

function hashRequest(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256'), start = performance.now();
    let size = 0, header = Buffer.alloc(0), settled = false;
    const fail = err => { if (!settled) { settled = true; reject(err); } };
    req.on('data', chunk => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) return fail(new InputError('Datei zu groß.', 413));
      hash.update(chunk);
      if (header.length < 12) header = Buffer.concat([header, chunk.subarray(0, 12 - header.length)]);
    });
    req.once('end', () => {
      if (settled) return;
      settled = true;
      if (!size) return reject(new InputError('Leere Datei.'));
      resolve({ size, header, sha256: hash.digest('hex'), durationMs: performance.now() - start });
    });
    req.once('aborted', () => fail(new InputError('Upload abgebrochen.')));
    req.once('error', () => fail(new InputError('Upload konnte nicht gelesen werden.')));
  });
}

export function createApp({ maxBytes = 15 * 1024 * 1024, maxJobs = 100, ttlMs = 10 * 60 * 1000, rateLimit = 180, maxConcurrent = 4 } = {}) {
  for (const value of [maxBytes, maxJobs, ttlMs, rateLimit, maxConcurrent]) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error('Ungültige Serverbegrenzung.');
  }
  const jobs = new Map();
  let active = 0, windowStart = Date.now(), requests = 0;
  const cleanup = () => { for (const [id, job] of jobs) if (job.expires_at_ms <= Date.now()) jobs.delete(id); };
  const timer = setInterval(cleanup, Math.min(ttlMs, 30000)); timer.unref();
  const server = http.createServer({ requestTimeout: 30000, headersTimeout: 10000, maxHeaderSize: 8192 }, async (req, res) => {
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cache-Control', 'no-store');
    const json = (status, data) => {
      if (res.destroyed) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify(data));
    };
    let uploadSlot = false;
    try {
      const port = server.address()?.port;
      const hosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
      if (!hosts.has(req.headers.host)) throw new InputError('Nur lokaler Host erlaubt.', 403);
      if (req.headers.origin && req.headers.origin !== `http://${req.headers.host}`) throw new InputError('Fremder Origin abgelehnt.', 403);
      if (req.headers['sec-fetch-site'] === 'cross-site') throw new InputError('Cross-Site-Anfrage abgelehnt.', 403);
      if ((req.url || '').length > 2048) throw new InputError('URL zu lang.', 414);
      const url = new URL(req.url, `http://${req.headers.host}`);
      if (Date.now() - windowStart >= 60000) { windowStart = Date.now(); requests = 0; }
      if (++requests > rateLimit) { res.setHeader('Retry-After', '60'); throw new InputError('Zu viele Anfragen. Nach einer Minute erneut versuchen.', 429); }
      cleanup();
      if (!['GET', 'HEAD', 'POST', 'DELETE'].includes(req.method)) throw new InputError('Methode nicht erlaubt.', 405);
      if (['POST', 'DELETE'].includes(req.method) && req.headers['x-trust-protocol'] !== '1') throw new InputError('X-Trust-Protocol: 1 erforderlich.', 403);
      if (assets.has(url.pathname) && ['GET', 'HEAD'].includes(req.method)) {
        const [type, bytes] = assets.get(url.pathname);
        res.writeHead(200, { 'Content-Type': type, 'Content-Length': bytes.length });
        res.end(req.method === 'HEAD' ? undefined : bytes); return;
      }
      if (req.method === 'GET' && url.pathname === '/v1/health') {
        json(200, { status: 'ok', version: '0.4.0', mode: 'local-integrity-only', max_file_bytes: maxBytes,
          capabilities: { sha256: true, reference_comparison: true, c2pa: false, signature: false, x509: false, revocation: false, hardware: false, ai_detection: false },
          retention: { raw_file_stored: false, result_ttl_ms: ttlMs } }); return;
      }
      if (req.method === 'GET' && url.pathname.startsWith('/v1/demo/')) { json(200, getDemo(url.pathname.slice(9))); return; }
      if (req.method === 'POST' && url.pathname === '/v1/analyze') {
        if ((req.headers['content-type'] || '').toLowerCase() !== 'application/octet-stream') throw new InputError('Binärer Body mit Content-Type application/octet-stream erforderlich. Kein Multipart.', 415);
        if (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity') throw new InputError('Komprimierte HTTP-Bodies werden nicht unterstützt.', 415);
        const declared = req.headers['content-length'];
        if (declared && Number(declared) > maxBytes) throw new InputError('Datei zu groß.', 413);
        const expectedHash = validateExpectedHash(url.searchParams.get('expected_sha256') || '');
        if (jobs.size + active >= maxJobs) throw new InputError('Ergebnisspeicher voll. Alte Ergebnisse löschen oder Ablauf abwarten.', 503);
        if (active >= maxConcurrent) throw new InputError('Zu viele gleichzeitige Uploads.', 503);
        active++; uploadSlot = true;
        const data = await hashRequest(req, maxBytes);
        const id = randomUUID(), now = Date.now();
        const job = { job_id: id, status: 'completed', created_at: new Date(now).toISOString(), expires_at: new Date(now + ttlMs).toISOString(), expires_at_ms: now + ttlMs,
          ...createResult({ ...data, filename: url.searchParams.get('filename') || 'upload', expectedHash }) };
        jobs.set(id, job);
        json(202, { job_id: id, status: 'completed', status_url: `/v1/jobs/${id}` }); return;
      }
      const match = /^\/v1\/jobs\/([a-f0-9-]{36})$/.exec(url.pathname);
      if (match && ['GET', 'DELETE'].includes(req.method)) {
        const job = jobs.get(match[1]);
        if (!job) throw new InputError('Ergebnis nicht gefunden oder abgelaufen.', 404);
        if (req.method === 'DELETE') { jobs.delete(match[1]); res.writeHead(204); res.end(); return; }
        const { expires_at_ms, ...safe } = job; json(200, safe); return;
      }
      throw new InputError('Route nicht gefunden.', 404);
    } catch (error) {
      const status = error instanceof InputError ? error.status : 500;
      res.setHeader('Connection', 'close');
      json(status, { error: status === 500 ? 'Interner Serverfehler.' : error.message });
      if (!req.complete) res.once('finish', () => req.destroy());
      if (status === 500) console.error('Interner Fehler:', error.message);
    } finally { if (uploadSlot) active--; }
  });
  server.setTimeout(35000, socket => socket.destroy());
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 100;
  server.once('close', () => clearInterval(timer));
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT muss zwischen 1 und 65535 liegen.');
  const server = createApp();
  server.once('error', error => { console.error('Start fehlgeschlagen:', error.message); process.exitCode = 1; });
  server.listen(port, '127.0.0.1', () => console.log(`Trust Protocol: http://127.0.0.1:${port}\nNur lokale Integritätsanalyse – keine C2PA-/KI-Verifikation. Strg+C beendet den Server.`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { server.close(); server.closeAllConnections(); });
}
