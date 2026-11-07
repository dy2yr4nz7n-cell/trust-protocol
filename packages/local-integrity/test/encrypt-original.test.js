import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, encryptRecord, decryptRecord } from '../lib/encrypt.js';

const rec = () => ({
  id: 'rec-001',
  origin: { creator: 'Alice' },
  integrity: { hash: 'abc' },
  fingerprint: { value: 'f00d' },
  evidence: [{ type: 'c2pa', detail: 'geheim' }],
});

test('Roundtrip', async () => {
  const k = await generateKeyPair();
  const e = await encryptRecord(rec(), [k.publicJwk]);
  assert.equal(e.evidence, undefined);
  assert.deepEqual(e.origin, rec().origin);
  assert.deepEqual(await decryptRecord(e, k.privateJwk), rec());
});

test('Mehrere Empfänger', async () => {
  const a = await generateKeyPair(), b = await generateKeyPair();
  const e = await encryptRecord(rec(), [a.publicJwk, b.publicJwk]);
  assert.deepEqual((await decryptRecord(e, a.privateJwk)).evidence, rec().evidence);
  assert.deepEqual((await decryptRecord(e, b.privateJwk)).evidence, rec().evidence);
});

test('Falscher Schlüssel scheitert', async () => {
  const a = await generateKeyPair(), x = await generateKeyPair();
  const e = await encryptRecord(rec(), [a.publicJwk]);
  await assert.rejects(decryptRecord(e, x.privateJwk));
});

test('Manipulierter Ciphertext scheitert', async () => {
  const k = await generateKeyPair();
  const e = await encryptRecord(rec(), [k.publicJwk]);
  const c = Buffer.from(e.encryption.ciphertext, 'base64url'); c[0] ^= 1;
  e.encryption.ciphertext = c.toString('base64url');
  await assert.rejects(decryptRecord(e, k.privateJwk));
});

test('Umhängen an andere Record-ID scheitert', async () => {
  const k = await generateKeyPair();
  const e = await encryptRecord(rec(), [k.publicJwk]);
  await assert.rejects(decryptRecord({ ...e, id: 'rec-999' }, k.privateJwk));
});

test('Doppelte Verschlüsselung und leere Empfänger abgelehnt', async () => {
  const k = await generateKeyPair();
  const e = await encryptRecord(rec(), [k.publicJwk]);
  await assert.rejects(encryptRecord(e, [k.publicJwk]));
  await assert.rejects(encryptRecord(rec(), []));
});
