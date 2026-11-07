import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, encryptRecord, decryptRecord } from '../lib/encrypt.js';
const rec = () => ({ id: 'rec-001', origin: { creator: 'Alice' }, evidence: { detail: 'privat' } });
test('Fehlende ID abgelehnt', async () => { const k = await generateKeyPair(); await assert.rejects(encryptRecord({ evidence: [] }, [k.publicJwk])); });
test('Reservierte und doppelte Felder abgelehnt', async () => {
  const k = await generateKeyPair();
  for (const fields of [['id'], ['encryption'], ['__proto__'], ['evidence', 'evidence']]) await assert.rejects(encryptRecord(rec(), [k.publicJwk], { fields }));
});
test('Doppelte Empfänger abgelehnt', async () => { const k = await generateKeyPair(); await assert.rejects(encryptRecord(rec(), [k.publicJwk, k.publicJwk])); });
test('Ungültiger Nonce abgelehnt', async () => { const k = await generateKeyPair(), e = await encryptRecord(rec(), [k.publicJwk]); e.encryption.nonce = 'AA'; await assert.rejects(decryptRecord(e, k.privateJwk)); });
test('Klartext-Schattenfeld abgelehnt', async () => { const k = await generateKeyPair(), e = await encryptRecord(rec(), [k.publicJwk]); e.evidence = 'shadow'; await assert.rejects(decryptRecord(e, k.privateJwk)); });
test('Beschädigter Wrapped Key abgelehnt', async () => { const k = await generateKeyPair(), e = await encryptRecord(rec(), [k.publicJwk]); const b = Buffer.from(e.encryption.recipients[0].wrapped_key, 'base64url'); b[0] ^= 1; e.encryption.recipients[0].wrapped_key = b.toString('base64url'); await assert.rejects(decryptRecord(e, k.privateJwk)); });
test('Unverschlüsselte Metadaten sind NICHT authentifiziert: dokumentierte Grenze', async () => {
  const k = await generateKeyPair(), e = await encryptRecord(rec(), [k.publicJwk]); e.origin.creator = 'Mallory';
  assert.equal((await decryptRecord(e, k.privateJwk)).origin.creator, 'Mallory');
});
