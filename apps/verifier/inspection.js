import express from 'express';
import multer from 'multer';
import sqlite3 from 'sqlite3';
import ExifReader from 'exifreader';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash } from 'node:crypto';
import { mediaExtension } from './c2pa.js';

export const INSPECTION_LIMIT = 25 * 1024 * 1024;
const summaries = {
  verified_offline: ['VALIDATED_BY_ENGINE', 'Signatur und Dateibindung offline gegen konfigurierte Vertrauensanker geprüft.'],
  valid_untrusted: ['VALID_UNTRUSTED', 'Signatur und Dateibindung gültig; der Aussteller ist nicht als vertrauenswürdig bestätigt.'],
  absent: ['NOT_PRESENT', 'Kein eingebetteter C2PA-Herkunftsnachweis gefunden.'],
  invalid: ['INVALID_OR_WARNING', 'Validierungsprobleme im C2PA-Nachweis. Details und Prüfgrenzen beachten.'],
  unknown: ['UNKNOWN', 'Der Herkunftsnachweis konnte nicht eindeutig geprüft werden.'],
};

export async function createInspection({ service, databasePath }) {
  if (databasePath !== ':memory:') await mkdir(dirname(databasePath), { recursive: true });
  const db = await new Promise((resolve, reject) => {
    const connection = new sqlite3.Database(databasePath, error => error ? reject(error) : resolve(connection));
  });
  const run = (sql, params = []) => new Promise((resolve, reject) => db.run(sql, params, function (error) { error ? reject(error) : resolve(this); }));
  const all = (sql, params = []) => new Promise((resolve, reject) => db.all(sql, params, (error, rows) => error ? reject(error) : resolve(rows)));
  // Inspect existing schema first; only add a new namespaced table and index.
  await all('PRAGMA table_info(inspection_audits)');
  await run(`CREATE TABLE IF NOT EXISTS inspection_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id TEXT NOT NULL,
    created_at TEXT NOT NULL, filename TEXT NOT NULL, mime TEXT NOT NULL,
    bytes INTEGER NOT NULL, sha256 TEXT NOT NULL, c2pa_state TEXT NOT NULL,
    c2pa_summary TEXT NOT NULL, metadata_json TEXT NOT NULL, report_json TEXT NOT NULL
  )`);
  await run('CREATE INDEX IF NOT EXISTS idx_inspection_owner ON inspection_audits(owner_id, id DESC)');
  const router = express.Router();
  const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: INSPECTION_LIMIT, files: 1, fields: 1, parts: 2, fieldSize: 32 } }).single('file');
  let active = 0;
  router.post('/verify', (req, res, next) => {
    if (active >= 2) return res.status(503).json({ error: 'Prüfserver ausgelastet. Bitte erneut versuchen.' });
    active++; let released = false;
    req.releaseInspection = () => { if (!released) { active--; released = true; } };
    res.once('finish', () => { if (!req.inspectionRunning) req.releaseInspection(); });
    res.once('close', () => { if (!req.inspectionRunning) req.releaseInspection(); });
    next();
  }, upload, async (req, res, next) => {
    req.inspectionRunning = true;
    try {
      if (req.body?.consent !== 'yes') return res.status(400).json({ error: 'Einwilligung zur Verarbeitung und Speicherung des Berichts fehlt.' });
      const buffer = req.file?.buffer;
      if (!buffer?.length) return res.status(400).json({ error: 'Bitte eine nicht leere Datei auswählen.' });
      const extension = mediaExtension(buffer, true);
      const mime = { '.jpg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.mp4': 'video/mp4', '.pdf': 'application/pdf', '.tif': 'image/tiff' }[extension];
      const metadata = { extracted: false, fields: {}, note: 'Metadaten können fehlen, entfernt oder gefälscht sein.' };
      if (mime.startsWith('image/')) {
        try {
          const tags = ExifReader.load(buffer, { expanded: false });
          for (const name of ['Make', 'Model', 'Software', 'DateTimeOriginal', 'DateTime', 'Orientation', 'ImageWidth', 'ImageLength', 'LensModel', 'Artist', 'Copyright']) {
            if (tags[name]?.description != null) metadata.fields[name] = String(tags[name].description).slice(0, 300);
          }
          metadata.extracted = Boolean(Object.keys(metadata.fields).length);
        } catch { metadata.note = 'Metadaten nicht lesbar. Das ist kein Manipulationsnachweis.'; }
      }
      let c2pa;
      if (service.status().available) {
        try {
          const result = await service.verify(buffer, { maxBytes: INSPECTION_LIMIT, extended: true });
          const [state, summary] = summaries[result.provenance] || summaries.unknown;
          c2pa = { state, summary, engine: service.status().version, details: result };
        } catch (error) {
          if (![422, 502].includes(error.status)) throw error;
          c2pa = { state: 'UNKNOWN', summary: 'C2PA-Auswertung nicht eindeutig möglich. Kein positiver Herkunftsnachweis.', engine: service.status().version };
        }
      } else c2pa = { state: 'ENGINE_MISSING', summary: 'C2PA-Engine nicht verfügbar; kein Herkunftsnachweis geprüft.', engine: null };
      const filename = String(req.file.originalname || 'upload').split(/[\\/]/).pop().replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
      const report = {
        schema: 'proto-audit/1.0', createdAt: new Date().toISOString(), filename,
        file: { mime, bytes: buffer.length, sha256: createHash('sha256').update(buffer).digest('hex') },
        c2pa, metadata,
        interpretation: { authenticity: 'NOT_DETERMINED', statement: 'Kein Beweis für die Wahrheit des dargestellten Inhalts.', limitations: ['Fehlende C2PA-Daten beweisen keine Manipulation.', 'Keine KI-Erkennung.', 'Audit-Datensätze sind nicht manipulationssicher signiert.', 'Keine aktuelle Online-Widerrufsprüfung.'] },
      };
      const row = await run('INSERT INTO inspection_audits(owner_id,created_at,filename,mime,bytes,sha256,c2pa_state,c2pa_summary,metadata_json,report_json) VALUES(?,?,?,?,?,?,?,?,?,?)',
        [req.user.id, report.createdAt, filename, mime, buffer.length, report.file.sha256, c2pa.state, c2pa.summary, JSON.stringify(metadata), JSON.stringify(report)]);
      res.json({ id: row.lastID, ...report });
    } catch (error) { next(error); }
    finally { req.inspectionRunning = false; req.releaseInspection(); }
  });
  router.get('/audits', async (req, res, next) => {
    try { res.json({ audits: await all('SELECT id,created_at,filename,mime,bytes,sha256,c2pa_state,c2pa_summary FROM inspection_audits WHERE owner_id=? ORDER BY id DESC LIMIT 100', [req.user.id]) }); }
    catch (error) { next(error); }
  });
  router.get('/audits/:id{/:export}', async (req, res, next) => {
    try {
      if (!/^[1-9]\d{0,14}$/.test(req.params.id)) return res.status(400).json({ error: 'Ungültige Audit-ID.' });
      if (req.params.export && req.params.export !== 'export') return res.status(404).json({ error: 'Nicht gefunden.' });
      const rows = await all('SELECT id,report_json FROM inspection_audits WHERE id=? AND owner_id=?', [Number(req.params.id), req.user.id]);
      if (!rows.length) return res.status(404).json({ error: 'Prüfbericht nicht gefunden.' });
      if (req.params.export) res.attachment(`proto-audit-${rows[0].id}.json`);
      res.json({ id: rows[0].id, ...JSON.parse(rows[0].report_json) });
    } catch (error) { next(error); }
  });
  return { router, close: () => new Promise((resolve, reject) => db.close(error => error ? reject(error) : resolve())) };
}
