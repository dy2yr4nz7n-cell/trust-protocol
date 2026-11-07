'use strict';
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const ExifReader = require('exifreader');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';
const C2PATOOL = process.env.C2PATOOL_PATH || 'c2patool';
const MAX_FILE_BYTES = 25 * 1024 * 1024;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, '..', 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, '..', 'frontend'), { extensions: ['html'] }));

const db = new sqlite3.Database(path.join(DATA_DIR, 'proto_audits.sqlite'));
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    filename TEXT NOT NULL,
    mime TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    c2pa_state TEXT NOT NULL,
    c2pa_summary TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    report_json TEXT NOT NULL
  )`);
  db.run('CREATE INDEX IF NOT EXISTS idx_audits_created ON audits(created_at DESC)');
});
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: MAX_FILE_BYTES, files: 1 },
  fileFilter: (_req, file, cb) => cb(null, true)
});

function detectType(b) {
  if (!b || b.length < 4) return { mime: 'application/octet-stream', ext: 'bin' };
  if (b.subarray(0, 3).toString('hex') === 'ffd8ff') return { mime: 'image/jpeg', ext: 'jpg' };
  if (b.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return { mime: 'image/png', ext: 'png' };
  if (b.subarray(0, 4).toString() === 'RIFF' && b.subarray(8, 12).toString() === 'WEBP') return { mime: 'image/webp', ext: 'webp' };
  if (b.subarray(4, 8).toString() === 'ftyp') return { mime: 'video/mp4', ext: 'mp4' };
  if (b.subarray(0, 4).toString() === '%PDF') return { mime: 'application/pdf', ext: 'pdf' };
  if (b.subarray(0, 4).toString('hex') === '49492a00' || b.subarray(0, 4).toString('hex') === '4d4d002a') return { mime: 'image/tiff', ext: 'tif' };
  return { mime: 'application/octet-stream', ext: 'bin' };
}
function safeName(name) {
  return path.basename(String(name || 'upload')).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120) || 'upload';
}
function sha256(buffer) { return crypto.createHash('sha256').update(buffer).digest('hex'); }
function flattenC2PA(obj) {
  const strings = [];
  const seen = new Set();
  function walk(v, depth) {
    if (depth > 8 || v == null) return;
    if (typeof v === 'string') { if (v.length < 300) strings.push(v); return; }
    if (typeof v !== 'object' || seen.has(v)) return;
    seen.add(v);
    if (Array.isArray(v)) v.forEach(x => walk(x, depth + 1));
    else Object.entries(v).forEach(([k, x]) => { strings.push(k); walk(x, depth + 1); });
  }
  walk(obj, 0);
  return strings.join(' ').toLowerCase();
}
async function runC2PA(buffer, detected) {
  let version = null;
  try {
    const v = await execFileAsync(C2PATOOL, ['--version'], { timeout: 5000, maxBuffer: 1024 * 1024 });
    version = (v.stdout || v.stderr || '').trim().slice(0, 100) || 'installed';
  } catch (_) {
    return { state: 'ENGINE_MISSING', summary: 'c2patool ist auf diesem Server nicht installiert. C2PA wurde nicht verifiziert.', engine: null, manifest: null, raw: null };
  }
  const tmp = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'proto-c2pa-'));
  const file = path.join(tmp, `asset.${detected.ext}`);
  try {
    await fs.promises.writeFile(file, buffer, { flag: 'wx' });
    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    try {
      const result = await execFileAsync(C2PATOOL, [file], { timeout: 20000, maxBuffer: 8 * 1024 * 1024 });
      stdout = result.stdout || ''; stderr = result.stderr || '';
    } catch (e) {
      stdout = e.stdout || ''; stderr = e.stderr || ''; exitCode = typeof e.code === 'number' ? e.code : 1;
      if (!stdout.trim()) {
        const msg = `${stderr} ${e.message || ''}`.toLowerCase();
        if (/no claim|no manifest|not found|does not contain|no c2pa/.test(msg)) return { state: 'NOT_PRESENT', summary: 'Keine C2PA-Manifestdaten gefunden.', engine: version, manifest: null, raw: null };
        return { state: 'ERROR', summary: 'Die C2PA-Engine konnte die Datei nicht eindeutig auswerten.', engine: version, manifest: null, raw: stderr.slice(0, 2000) };
      }
    }
    let parsed;
    try { parsed = JSON.parse(stdout); }
    catch (_) {
      if (/no claim|no manifest|not found|does not contain|no c2pa/i.test(stderr + stdout)) return { state: 'NOT_PRESENT', summary: 'Keine C2PA-Manifestdaten gefunden.', engine: version, manifest: null, raw: null };
      return { state: 'ERROR', summary: 'Die Engine lieferte keine auswertbare JSON-Antwort.', engine: version, manifest: null, raw: (stdout + '\n' + stderr).slice(0, 2000) };
    }
    const all = flattenC2PA(parsed);
    const hasManifest = Boolean(parsed && (parsed.active_manifest || parsed.manifests || parsed.validation_results || parsed.validation_status || parsed.claim_generator));
    if (!hasManifest && /no claim|no manifest/.test(all)) return { state: 'NOT_PRESENT', summary: 'Keine C2PA-Manifestdaten gefunden.', engine: version, manifest: null, raw: null };
    if (!hasManifest) return { state: 'UNKNOWN', summary: 'Antwort erhalten, aber Manifest-/Validierungsstatus nicht eindeutig erkennbar.', engine: version, manifest: parsed, raw: null };
    const failures = /failure|invalid|mismatch|untrusted|revoked|error/.test(all);
    const successes = /success|valid|passed/.test(all);
    let state = 'PRESENT_UNCLEAR';
    let summary = 'C2PA-Daten vorhanden; das Ergebnis ist anhand der verfügbaren Ausgabe nicht eindeutig.';
    if (failures || exitCode !== 0) { state = 'INVALID_OR_WARNING'; summary = 'Die C2PA-Ausgabe enthält Validierungsfehler oder Warnhinweise. Details im Rohbericht prüfen.'; }
    else if (successes) { state = 'VALIDATED_BY_ENGINE'; summary = 'Die C2PA-Engine meldet erfolgreiche Validierung. Das belegt die Signatur-/Manifestprüfung, nicht die Wahrheit des Bildinhalts.'; }
    return { state, summary, engine: version, manifest: parsed, raw: null };
  } finally { await fs.promises.rm(tmp, { recursive: true, force: true }); }
}
async function inspectMetadata(buffer, mime) {
  const out = { extracted: false, fields: {}, note: 'Metadaten sind optional und können entfernt oder verändert worden sein.' };
  if (!mime.startsWith('image/')) return out;
  try {
    const tags = await ExifReader.load(buffer, { expanded: false });
    const wanted = ['Make','Model','Software','DateTimeOriginal','DateTime','Orientation','ImageWidth','ImageLength','LensModel','Artist','Copyright'];
    for (const k of wanted) if (tags[k] && tags[k].description != null) out.fields[k] = String(tags[k].description).slice(0, 300);
    out.extracted = Object.keys(out.fields).length > 0;
    if (!out.extracted) out.note = 'Keine der unterstützten EXIF-Angaben gefunden. Das ist kein Manipulationsnachweis.';
  } catch (_) { out.note = 'Metadaten konnten nicht gelesen werden. Das ist kein Manipulationsnachweis.'; }
  return out;
}
function run(dbMethod, sql, params=[]) { return new Promise((resolve, reject) => db[dbMethod](sql, params, function(err, rows) { if (err) reject(err); else resolve(dbMethod === 'run' ? this : rows); })); }

app.get('/api/health', async (_req, res) => {
  let engine = false; let engineVersion = null;
  try { const r = await execFileAsync(C2PATOOL, ['--version'], { timeout: 3000 }); engine = true; engineVersion = (r.stdout || r.stderr || '').trim().slice(0,100); } catch (_) {}
  res.json({ ok: true, app: 'Proto Trust Protocol', version: '12.0.0', c2paEngine: engine, c2paEngineVersion: engineVersion, maxUploadBytes: MAX_FILE_BYTES });
});
app.post('/api/verify', upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Bitte eine Datei auswählen.' });
  const buffer = req.file.buffer;
  const detected = detectType(buffer);
  if (detected.mime === 'application/octet-stream') return res.status(415).json({ error: 'Dateityp nicht unterstützt oder nicht eindeutig erkennbar. Erlaubt: JPEG, PNG, WebP, MP4, PDF und TIFF.' });
  const filename = safeName(req.file.originalname);
  const hash = sha256(buffer);
  const metadata = await inspectMetadata(buffer, detected.mime);
  const c2pa = await runC2PA(buffer, detected);
  const report = {
    schema: 'proto-audit/1.0', createdAt: new Date().toISOString(), filename,
    file: { mime: detected.mime, bytes: buffer.length, sha256: hash },
    c2pa,
    metadata,
    interpretation: {
      authenticity: 'NOT_DETERMINED',
      statement: 'Diese Prüfung bestimmt nicht, ob der dargestellte Inhalt wahr oder die Szene tatsächlich so aufgenommen wurde.',
      limitations: ['Fehlende C2PA-Daten beweisen keine Manipulation.', 'Metadaten können fehlen, entfernt oder gefälscht sein.', 'Ein gültiges C2PA-Manifest belegt nicht die Wahrheit des Inhalts.', 'Automatische Bildforensik/KI-Erkennung ist in dieser Version nicht aktiviert.']
    }
  };
  const summary = c2pa.summary;
  try {
    const result = await run('run', `INSERT INTO audits (created_at,filename,mime,bytes,sha256,c2pa_state,c2pa_summary,metadata_json,report_json) VALUES (?,?,?,?,?,?,?,?,?)`, [report.createdAt, filename, detected.mime, buffer.length, hash, c2pa.state, summary, JSON.stringify(metadata), JSON.stringify(report)]);
    res.json({ id: result.lastID, ...report });
  } catch (e) { res.status(500).json({ error: 'Prüfbericht konnte nicht gespeichert werden.', detail: e.message }); }
});
app.get('/api/audits', async (_req, res) => {
  try { const rows = await run('all', 'SELECT id,created_at,filename,mime,bytes,sha256,c2pa_state,c2pa_summary FROM audits ORDER BY id DESC LIMIT 100'); res.json({ audits: rows }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/audits/:id', async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Ungültige Audit-ID.' });
  try { const rows = await run('all', 'SELECT id,report_json FROM audits WHERE id=?', [Number(req.params.id)]); if (!rows.length) return res.status(404).json({ error: 'Prüfbericht nicht gefunden.' }); res.json({ id: rows[0].id, ...JSON.parse(rows[0].report_json) }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/audits/:id/export', async (req, res) => {
  if (!/^\d+$/.test(req.params.id)) return res.status(400).json({ error: 'Ungültige Audit-ID.' });
  try { const rows = await run('all', 'SELECT report_json FROM audits WHERE id=?', [Number(req.params.id)]); if (!rows.length) return res.status(404).json({ error: 'Prüfbericht nicht gefunden.' }); res.type('application/json').attachment(`proto-audit-${req.params.id}.json`).send(JSON.stringify(JSON.parse(rows[0].report_json), null, 2)); }
  catch (e) { res.status(500).json({ error: e.message }); }
});
app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Datei zu groß. Maximum: 25 MB.' });
  res.status(500).json({ error: 'Interner Serverfehler.' });
});
app.listen(PORT, HOST, () => console.log(`Proto Trust Protocol v12.0 läuft auf http://${HOST}:${PORT}`));
