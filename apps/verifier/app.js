import express from 'express';
import helmet from 'helmet';
import multer from 'multer';
import { rateLimit } from 'express-rate-limit';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { createAuth } from './auth.js';
import { validateMetadata } from './schema.js';
import { MAX_BYTES } from './c2pa.js';

export function createApp({ service, secret = process.env.JWT_SECRET, origin = 'http://127.0.0.1:3000', inspection }) {
  if (new URL(origin).origin !== origin || !/^https?:/.test(origin)) throw new Error('PUBLIC_ORIGIN must be an exact HTTP(S) origin');
  const auth = createAuth(secret), app = express();
  app.disable('x-powered-by');
  app.use(helmet({ contentSecurityPolicy: { directives: { 'upgrade-insecure-requests': null } } }));
  app.use('/api', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    if (req.headers.origin && req.headers.origin !== origin) return res.status(403).json({ error: 'Origin not allowed' });
    next();
  });
  app.use('/api', rateLimit({ windowMs: 60000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false }));
  app.use('/api', auth.verifyToken);
  if (inspection) app.use('/api/inspection', inspection);
  app.get('/api/capabilities', (_req, res) => res.json(service.status()));
  let active = 0;
  const gate = (req, res, next) => {
    if (!service.status().available) return res.status(503).json({ error: 'C2PA verifier unavailable' });
    if (active >= 2) return res.status(503).json({ error: 'Verifier busy' });
    active++;
    let released = false;
    req.releaseSlot = () => { if (!released) { released = true; active--; } };
    const idle = () => { if (!req.checkRunning) req.releaseSlot(); };
    res.once('finish', idle); res.once('close', idle);
    next();
  };
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_BYTES, files: 1, fields: 1, fieldSize: 8192, parts: 2 } }).single('file');
  app.post('/api/verify', gate, (req, res, next) => {
    if (!req.is('multipart/form-data')) return res.status(415).json({ error: 'Use multipart/form-data with a file field' });
    next();
  }, upload, validateMetadata, async (req, res) => {
    if (!req.file?.buffer?.length) return res.status(400).json({ error: 'file is required' });
    req.checkRunning = true;
    try {
      const result = await service.verify(req.file.buffer);
      res.json({ schemaVersion: 'trust-check/1', checkedAt: new Date().toISOString(), file: { size: req.file.size, sha256: createHash('sha256').update(req.file.buffer).digest('hex') }, ...result, clientTools: req.metadata.tools, clientToolsTrusted: false });
    } finally { req.checkRunning = false; req.releaseSlot(); }
  });
  app.use(express.static(fileURLToPath(new URL('./public/', import.meta.url)), { dotfiles: 'deny' }));
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((error, _req, res, _next) => {
    const status = error instanceof multer.MulterError ? (error.code === 'LIMIT_FILE_SIZE' ? 413 : 400) : Number.isInteger(error.status) && error.status >= 400 && error.status <= 599 ? error.status : 500;
    res.status(status).json({ error: status === 500 ? 'Internal server error' : error.message });
  });
  return app;
}
