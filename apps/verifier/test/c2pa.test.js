import test from 'node:test';
import assert from 'node:assert/strict';
import { access, readFile } from 'node:fs/promises';
import { createC2paService, summariseReport, mediaExtension } from '../c2pa.js';

const jpeg = Buffer.from([255,216,255,217]);
function report() { return { active_manifest: 'm', manifests: { m: { assertions: [] } }, validation_state: 'Valid', validation_results: { activeManifest: { success: [{ code: 'claimSignature.validated' }, { code: 'assertion.dataHash.match' }], failure: [] } } }; }
test('empty successes do not verify anything', () => {
  const r = report(); r.validation_results.activeManifest.success = [];
  assert.equal(summariseReport(r).provenance, 'unknown');
});
test('signature and binding do not establish signer trust', () => {
  const r = summariseReport(report());
  assert.equal(r.provenance, 'valid_untrusted'); assert.equal(r.checks.trustedSigner, false);
});
test('trusted result requires configured anchors and explicit CLI evidence', () => {
  const r = report(); r.validation_results.activeManifest.success.push({ code: 'signingCredential.trusted' });
  assert.equal(summariseReport(r).provenance, 'valid_untrusted');
  assert.equal(summariseReport(r, true).provenance, 'verified_offline');
});
test('hash mismatch prevents positive results', () => {
  const r = report(); r.validation_results.activeManifest.failure = [{ code: 'assertion.dataHash.mismatch' }];
  assert.equal(summariseReport(r, true).provenance, 'invalid');
});
test('untrusted failure prevents trusted signer result', () => {
  const r = report(); r.validation_results.activeManifest.success.push({ code: 'signingCredential.trusted' });
  r.validation_status = [{ code: 'signingCredential.untrusted' }];
  assert.equal(summariseReport(r, true).provenance, 'valid_untrusted');
});
test('AI declaration is not pixel detection', () => {
  const r = report(); r.manifests.m.assertions = [{ label: 'c2pa.actions.v2', data: { actions: [{ digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia' }] } }];
  const result = summariseReport(r);
  assert.equal(result.generation.aiDeclared, true); assert.equal(result.generation.status, 'ai_claim_unverified'); assert.equal(result.generation.detectorUsed, false);
});
test('arbitrary assertions cannot declare the active file AI-generated', () => {
  const r = report(); r.manifests.m.assertions = [{ label: 'other', data: { actions: [{ digitalSourceType: 'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia' }] } }];
  assert.equal(summariseReport(r).generation.aiDeclared, false);
});
test('malformed reports fail closed', () => {
  for (const r of [null, [], {}, 'text']) assert.throws(() => summariseReport(r));
});
test('file signature is checked', () => {
  assert.equal(mediaExtension(jpeg), '.jpg'); assert.throws(() => mediaExtension(Buffer.from('<script>')), error => error.status === 415);
});
test('missing CLI yields unavailable, not success', async () => {
  const service = await createC2paService({ run: async () => { throw new Error('ENOENT'); } });
  try { assert.equal(service.status().available, false); await assert.rejects(service.verify(jpeg), error => error.status === 503); } finally { await service.close(); }
});
test('unsupported CLI version is unavailable', async () => {
  const service = await createC2paService({ run: async () => ({ stdout: 'c2patool 0.0.0' }) });
  try { assert.equal(service.status().available, false); } finally { await service.close(); }
});
test('CLI invocation has bounded output, no shell, offline settings, and cleanup', async () => {
  let file, settings;
  const service = await createC2paService({ run: async (_binary, args, options) => {
    assert.equal(options.shell, false); assert.equal(options.timeout, 20000); assert.ok(options.maxBuffer > 0);
    if (args[0] === '--version') return { stdout: 'c2patool 0.28.6' };
    [file, , settings] = args;
    const config = JSON.parse(await readFile(settings, 'utf8'));
    assert.equal(config.verify.remote_manifest_fetch, false); assert.equal(config.verify.ocsp_fetch, false); assert.deepEqual(config.core.allowed_network_hosts, []);
    assert.deepEqual(await readFile(file), jpeg);
    return { stdout: JSON.stringify(report()) };
  } });
  try { assert.equal((await service.verify(jpeg)).provenance, 'valid_untrusted'); await assert.rejects(access(file)); } finally { await service.close(); }
  await assert.rejects(access(settings));
});
test('CLI absence, malformed JSON and timeout are distinct; uploads are removed', async () => {
  for (const kind of ['absent', 'json', 'timeout', 'error']) {
    let path;
    const service = await createC2paService({ run: async (_binary, args) => {
      if (args[0] === '--version') return { stdout: 'c2patool 0.28.6' };
      path = args[0];
      if (kind === 'json') return { stdout: 'not JSON' };
      throw Object.assign(new Error(), kind === 'absent' ? { stderr: 'Error: No claim found' } : { killed: kind === 'timeout' });
    } });
    try {
      if (kind === 'absent') assert.equal((await service.verify(jpeg)).provenance, 'absent');
      else await assert.rejects(service.verify(jpeg), error => error.status === ({ json: 502, timeout: 504, error: 422 })[kind]);
      await assert.rejects(access(path));
    } finally { await service.close(); }
  }
});
