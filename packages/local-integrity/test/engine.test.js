import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeBuffer, getDemo, cleanFilename, detectFormat } from '../engine.js';
const abcHash = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
test('SHA-256 bekannter Testvektor abc; ohne Referenz unverified', async () => {
  const r = await analyzeBuffer(Buffer.from('abc'));
  assert.equal(r.integrity.sha256, abcHash); assert.equal(r.verdict, 'UNVERIFIED');
  assert.equal(r.checks.c2pa_manifest, 'NOT_IMPLEMENTED'); assert.equal(r.forensics.ai_synthetic_probability, null);
});
test('Referenzvergleich akzeptiert Großschreibung ohne Echtheit zu behaupten', async () => {
  const r = await analyzeBuffer(Buffer.from('abc'), { expectedHash: abcHash.toUpperCase() });
  assert.equal(r.verdict, 'INTEGRITY_MATCH'); assert.equal(r.authenticity, 'NOT_EVALUATED');
});
test('Abweichender Referenzwert wird erkannt', async () => {
  assert.equal((await analyzeBuffer(Buffer.from('abc'), { expectedHash: '0'.repeat(64) })).verdict, 'INTEGRITY_MISMATCH');
});
test('Ungültiger Referenzwert wird abgelehnt', async () => { await assert.rejects(analyzeBuffer(Buffer.from('a'), { expectedHash: 'bad' })); });
test('Leere Datei wird abgelehnt', async () => { await assert.rejects(analyzeBuffer(Buffer.alloc(0))); });
test('Größenlimit greift', async () => { await assert.rejects(analyzeBuffer(Buffer.alloc(2), { maxBytes: 1 }), { status: 413 }); });
test('Pfad und Steuerzeichen im Dateinamen entfernt', () => { assert.equal(cleanFilename('C:\\folder\\x\n.txt'), 'x.txt'); });
test('Header-Typ bleibt ausdrücklich nur Hinweis', async () => {
  const r = await analyzeBuffer(Buffer.from('89504e470d0a1a0a', 'hex'));
  assert.equal(r.detected_media_type, 'image/png'); assert.equal(r.format_validation, 'HEADER_HINT_ONLY_NOT_DECODED');
  assert.equal(detectFormat(Buffer.from('abc')), 'application/octet-stream');
});
test('Alle Demos klar markiert', () => { for (const key of ['authentic', 'ai_manipulated', 'revoked_cert', 'corrupted_manifest']) assert.equal(getDemo(key).mode, 'SIMULATION'); });
test('Geerbte Objekt-Keys sind keine Demos', () => { assert.throws(() => getDemo('__proto__')); assert.throws(() => getDemo('toString')); });
