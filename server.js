import { createServer } from 'node:http';
import './scripts/load-env.mjs';
import { readFile, stat } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createC2paService } from './apps/verifier/c2pa.js';

export async function createRuntime({ secret = process.env.JWT_SECRET, origin = process.env.PUBLIC_ORIGIN, directory = fileURLToPath(new URL('./dist/public', import.meta.url)), databasePath = resolve(process.env.DATA_DIR || './data', 'proto_audits.sqlite') } = {}) {
  const service = await createC2paService();
  let api, inspection;
  if (secret) {
    try {
      const { createApp } = await import('./apps/verifier/app.js');
      const { createInspection } = await import('./apps/verifier/inspection.js');
      inspection = await createInspection({ service, databasePath });
      api = createApp({ service, secret, origin: origin || 'http://127.0.0.1:3000', inspection: inspection.router });
    } catch (error) { await inspection?.close(); await service.close(); throw error; }
  }
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };
  const server = createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ status: 'ok', apiConfigured: Boolean(api), c2pa: service.status() }));
      }
      if (url.pathname.startsWith('/api/')) {
        if (api) return api(req, res);
        res.writeHead(503, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({ error: 'API not configured. Set JWT_SECRET and PUBLIC_ORIGIN on the server.' }));
      }
      if (!['GET', 'HEAD'].includes(req.method)) { res.writeHead(405); return res.end(); }
      const path = decodeURIComponent(url.pathname);
      if (path.includes('\\') || path.split('/').some(part => part.startsWith('.'))) { res.writeHead(404); return res.end('Not found'); }
      let target = resolve(directory, '.' + path);
      if (!target.startsWith(resolve(directory) + sep) && target !== resolve(directory)) { res.writeHead(404); return res.end('Not found'); }
      if ((await stat(target)).isDirectory()) {
        if (!path.endsWith('/')) { res.writeHead(302, { Location: path + '/' }); return res.end(); }
        target = resolve(target, 'index.html');
      }
      const data = await readFile(target);
      res.writeHead(200, { 'Content-Type': types[extname(target)] || 'application/octet-stream' });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch { res.writeHead(404); res.end('Not found'); }
  });
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  return { server, close: async () => { await new Promise(resolve => server.close(resolve)); await inspection?.close(); await service.close(); } };
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid PORT');
  if (process.env.JWT_SECRET && !process.env.PUBLIC_ORIGIN) throw new Error('Set PUBLIC_ORIGIN when enabling the API');
  const runtime = await createRuntime();
  runtime.server.listen(port, process.env.HOST || '0.0.0.0', () => console.log(`TRUST workspace listening on ${port}`));
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, () => runtime.close().catch(console.error));
}
