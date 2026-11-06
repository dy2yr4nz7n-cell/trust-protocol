import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const TOOL_VERSION = '0.28.6';
export const MAX_BYTES = 8 * 1024 * 1024;
const execute = promisify(execFile);
const limits = [
  'Kein allgemeiner KI-Detektor: keine KI-Angabe bedeutet nicht menschliche Erstellung.',
  'Herkunft und Dateiintegrität beweisen nicht die Wahrheit einer Darstellung.',
  'Offline-Prüfung: entfernte Manifeste und aktuelle Online-Widerrufsdaten werden nicht abgerufen.'
];
export class CheckError extends Error {
  constructor(message, status = 422) { super(message); this.status = status; }
}
export function mediaExtension(bytes) {
  if (!Buffer.isBuffer(bytes)) throw new CheckError('Expected file bytes', 400);
  if (bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255) return '.jpg';
  if (bytes.length >= 8 && bytes.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) return '.png';
  if (bytes.length >= 12 && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') return '.webp';
  throw new CheckError('Only JPEG, PNG and WebP file signatures are accepted', 415);
}
export function summariseReport(report, trustConfigured = false) {
  const manifest = report?.manifests?.[report?.active_manifest];
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) throw new CheckError('Unsupported C2PA report shape', 502);
  const result = report.validation_results?.activeManifest;
  const success = Array.isArray(result?.success) ? result.success : [];
  const issues = [...(Array.isArray(result?.failure) ? result.failure : []), ...(Array.isArray(report.validation_status) ? report.validation_status : [])];
  const has = code => success.some(item => item?.code === code);
  const signature = has('claimSignature.validated');
  const contentBinding = success.some(item => /^assertion\.(?:dataHash|bmffHash|boxesHash|collectionHash)\.match$/.test(item?.code || ''));
  const trusted = trustConfigured && has('signingCredential.trusted') && !issues.some(item => item?.code === 'signingCredential.untrusted');
  const errors = issues.filter(item => item?.code !== 'signingCredential.untrusted');
  const valid = ['Valid', 'Trusted'].includes(report.validation_state) && signature && contentBinding && !errors.length;
  const provenance = valid ? (trusted ? 'verified_offline' : 'valid_untrusted') : report.validation_state === 'Invalid' || errors.length ? 'invalid' : 'unknown';
  const types = new Set();
  for (const assertion of Array.isArray(manifest.assertions) ? manifest.assertions : []) {
    if (!/^c2pa\.actions(?:\.v[0-9]+)?$/.test(assertion?.label || '')) continue;
    for (const action of Array.isArray(assertion.data?.actions) ? assertion.data.actions : []) {
      const type = action?.digitalSourceType;
      if (typeof type === 'string' && /^https?:\/\/cv\.iptc\.org\/newscodes\/digitalsourcetype\/[A-Za-z]+$/.test(type)) types.add(type.split('/').pop());
    }
  }
  const aiDeclared = types.has('trainedAlgorithmicMedia') || types.has('compositeWithTrainedAlgorithmicMedia');
  return {
    provenance,
    checks: { signature, contentBinding, trustedSigner: valid && trusted, onlineRevocation: false },
    generation: { aiDeclared, sourceTypes: [...types], status: aiDeclared ? (valid && trusted ? 'ai_declared_trusted' : 'ai_claim_unverified') : 'undetermined', detectorUsed: false },
    issues: [...new Set(issues.map(item => String(item?.code || 'unknown')))], limits
  };
}
export async function createC2paService({ binary = process.env.C2PATOOL_PATH || 'c2patool', anchorsPath = process.env.C2PA_TRUST_ANCHORS, run = execute } = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'trust-settings-'));
  const settings = join(dir, 'settings.json');
  let anchors;
  try {
    if (anchorsPath) {
      anchors = await readFile(anchorsPath, 'utf8');
      if (Buffer.byteLength(anchors) > 2 * 1024 * 1024 || !anchors.includes('-----BEGIN CERTIFICATE-----')) throw new Error('Invalid trust anchor PEM');
    }
    await writeFile(settings, JSON.stringify({ version: 1, core: { allowed_network_hosts: [], max_decompressed_manifest_size_in_mb: 16 }, verify: { verify_after_reading: true, verify_trust: true, verify_timestamp_trust: true, remote_manifest_fetch: false, ocsp_fetch: false }, ...(anchors ? { trust: { trust_anchors: anchors } } : {}) }), { mode: 0o600 });
  } catch (error) { await rm(dir, { recursive: true, force: true }); throw error; }
  const options = { shell: false, timeout: 20000, maxBuffer: 4 * 1024 * 1024, windowsHide: true, env: { PATH: process.env.PATH, HOME: dir, XDG_CONFIG_HOME: dir, ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) } };
  let available = false, version = null, closed = false;
  try { version = (await run(binary, ['--version'], options)).stdout.trim(); available = version === `c2patool ${TOOL_VERSION}`; } catch { /* reported via capabilities */ }
  return {
    status: () => ({ available: available && !closed, version, requiredVersion: TOOL_VERSION, trustConfigured: Boolean(anchors), aiDetectorAvailable: false }),
    async verify(bytes) {
      if (!available || closed) throw new CheckError('C2PA verifier unavailable or unsupported version', 503);
      if (!Buffer.isBuffer(bytes) || !bytes.length || bytes.length > MAX_BYTES) throw new CheckError('Invalid file size (maximum 8 MiB)', 413);
      const extension = mediaExtension(bytes), work = await mkdtemp(join(tmpdir(), 'trust-upload-'));
      try {
        const path = join(work, `asset${extension}`);
        await writeFile(path, bytes, { mode: 0o600 });
        let stdout;
        try { ({ stdout } = await run(binary, [path, '--settings', settings], options)); }
        catch (error) {
          const text = `${error.stdout || ''}\n${error.stderr || ''}`.trim();
          if (/^(?:Error: )?No claim found\s*$/i.test(text)) return { provenance: 'absent', checks: { signature: false, contentBinding: false, trustedSigner: false, onlineRevocation: false }, generation: { aiDeclared: false, status: 'undetermined', detectorUsed: false }, issues: [], limits };
          throw new CheckError(error.killed ? 'C2PA timeout' : 'C2PA verification failed', error.killed ? 504 : 422);
        }
        let report;
        try { report = JSON.parse(stdout); } catch { throw new CheckError('Invalid C2PA JSON output', 502); }
        return summariseReport(report, Boolean(anchors));
      } finally { await rm(work, { recursive: true, force: true }); }
    },
    async close() { closed = true; await rm(dir, { recursive: true, force: true }); }
  };
}
