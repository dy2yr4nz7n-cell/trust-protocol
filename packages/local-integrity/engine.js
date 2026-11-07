import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';

export class InputError extends Error {
  constructor(message, status = 400) { super(message); this.status = status; }
}

export function validateExpectedHash(value = '') {
  if (typeof value !== 'string') throw new InputError('Referenz-Hash muss Text sein.');
  const hash = value.trim().toLowerCase();
  if (hash && !/^[a-f0-9]{64}$/.test(hash)) throw new InputError('SHA-256 benötigt genau 64 Hex-Zeichen.');
  return hash || null;
}

export function cleanFilename(value = 'upload') {
  return String(value).split(/[\\/]/).pop().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, 180) || 'upload';
}

export function detectFormat(bytes) {
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from('89504e470d0a1a0a', 'hex'))) return 'image/png';
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.length >= 12 && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') return 'image/webp';
  return 'application/octet-stream';
}

export function createResult({ filename, size, sha256, header, expectedHash, durationMs }) {
  const comparison = expectedHash ? (sha256 === expectedHash ? 'MATCH' : 'MISMATCH') : 'NOT_PROVIDED';
  return {
    schema_version: '0.4', mode: 'LIVE',
    verdict: comparison === 'MATCH' ? 'INTEGRITY_MATCH' : comparison === 'MISMATCH' ? 'INTEGRITY_MISMATCH' : 'UNVERIFIED',
    authenticity: 'NOT_EVALUATED',
    filename: cleanFilename(filename), size_bytes: size,
    detected_media_type: detectFormat(header),
    format_validation: 'HEADER_HINT_ONLY_NOT_DECODED',
    integrity: { algorithm: 'SHA-256', sha256, expected_sha256: expectedHash, comparison },
    checks: {
      c2pa_manifest: 'NOT_IMPLEMENTED', signature: 'NOT_IMPLEMENTED',
      x509_chain: 'NOT_IMPLEMENTED', revocation: 'NOT_IMPLEMENTED',
      hardware_attestation: 'NOT_IMPLEMENTED', ai_detection: 'NOT_IMPLEMENTED'
    },
    forensics: { ai_synthetic_probability: null, ela: null, copy_move: null },
    processing_time_ms: Number(durationMs.toFixed(3)),
    notices: [
      'Ein Datei-Hash ist kein Herkunfts-, Signatur- oder Echtheitsnachweis.',
      'Ein Referenz-Hash muss aus einer unabhängig vertrauenswürdigen Quelle stammen.',
      'Medientypen sind nur Header-Hinweise. Es erfolgt keine vollständige Dateidekodierung.'
    ]
  };
}

export async function analyzeBuffer(buffer, { filename = 'upload', expectedHash = '', maxBytes = 15 * 1024 * 1024 } = {}) {
  if (!Buffer.isBuffer(buffer)) throw new InputError('Buffer erforderlich.');
  if (!buffer.length) throw new InputError('Leere Datei.');
  if (buffer.length > maxBytes) throw new InputError('Datei überschreitet die Größenbegrenzung.', 413);
  const expected = validateExpectedHash(expectedHash);
  const started = performance.now();
  const sha256 = createHash('sha256').update(buffer).digest('hex');
  return createResult({ filename, size: buffer.length, sha256, header: buffer.subarray(0, 12), expectedHash: expected, durationMs: performance.now() - started });
}

export const demoScenarios = {
  authentic: { title: 'Simulierter gültiger Herkunftsnachweis', status: 'DEMO_VALID', signature: 'SIMULATED_VALID', revocation: 'SIMULATED_ACTIVE' },
  ai_manipulated: { title: 'Simulierte KI-Warnung', status: 'DEMO_AI_WARNING', signature: 'SIMULATED_VALID', revocation: 'SIMULATED_ACTIVE' },
  revoked_cert: { title: 'Simulierter Zertifikatswiderruf', status: 'DEMO_REVOKED', signature: 'SIMULATED_VALID', revocation: 'SIMULATED_REVOKED' },
  corrupted_manifest: { title: 'Simulierter Manifest-Fehler', status: 'DEMO_HASH_MISMATCH', signature: 'SIMULATED_INVALID', revocation: 'SIMULATED_NOT_RUN' }
};

export function getDemo(key) {
  const scenario = demoScenarios[key];
  if (!Object.hasOwn(demoScenarios, key)) throw new InputError('Unbekanntes Demo-Szenario.', 404);
  return { schema_version: '0.4', mode: 'SIMULATION', synthetic: true, ...scenario,
    notices: ['Fiktives Szenario. Keine Datei wurde geprüft. Keine reale Zertifikats- oder KI-Analyse.'] };
}
