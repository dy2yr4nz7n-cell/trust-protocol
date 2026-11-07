// Kompatibilität mit dem vorhandenen 0.3-Envelope. Kein standardisiertes JWE, kein Audit.
import * as legacy from './encrypt-legacy.js';
export const ENC_VERSION = legacy.ENC_VERSION;
const reserved = new Set(['id', 'encryption', '__proto__', 'prototype', 'constructor']);
const plainObject = value => value && typeof value === 'object' && !Array.isArray(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value));
function check(condition, message) { if (!condition) throw new Error(message); }
function bytes(value, length, min = length) {
  check(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value) && value.length <= 24 * 1024 * 1024, 'Ungültige Base64url-Daten.');
  const decoded = Buffer.from(value, 'base64url');
  check(decoded.toString('base64url') === value && decoded.length >= min && decoded.length <= length, 'Ungültige Kodierung oder Länge.');
}
function jwk(key, privateKey = false) {
  check(plainObject(key) && key.kty === 'EC' && key.crv === 'P-256', 'P-256-JWK erforderlich.');
  bytes(key.x, 32); bytes(key.y, 32);
  if (privateKey) bytes(key.d, 32);
}
function recordCheck(record) {
  check(plainObject(record), 'Record muss ein JSON-Objekt sein.');
  check(typeof record.id === 'string' && /^[A-Za-z0-9._:-]{1,200}$/.test(record.id), 'Eindeutige Record-ID ohne Trennzeichen erforderlich.');
}
function fieldCheck(fields) {
  check(Array.isArray(fields) && fields.length > 0 && fields.length <= 32 && new Set(fields).size === fields.length, 'Ungültige oder doppelte Feldliste.');
  for (const field of fields) check(typeof field === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(field) && !reserved.has(field), 'Reserviertes oder ungültiges Feld.');
}
export const generateKeyPair = legacy.generateKeyPair;
export async function keyId(key) { jwk(key); return legacy.keyId(key); }
export async function encryptRecord(record, recipients, { fields = ['evidence'] } = {}) {
  recordCheck(record); fieldCheck(fields);
  check(!Object.hasOwn(record, 'encryption'), 'Record hat bereits ein Verschlüsselungsfeld.');
  check(Array.isArray(recipients) && recipients.length > 0 && recipients.length <= 64, '1 bis 64 Empfänger erforderlich.');
  const ids = new Set();
  for (const key of recipients) { jwk(key); const id = await keyId(key); check(!ids.has(id), 'Doppelter Empfänger.'); ids.add(id); }
  const safe = JSON.parse(JSON.stringify(record));
  const selected = fields.filter(field => Object.hasOwn(safe, field));
  check(selected.length > 0, 'Keines der Felder vorhanden.');
  check(Buffer.byteLength(JSON.stringify(safe)) <= 15 * 1024 * 1024, 'Record zu groß.');
  return legacy.encryptRecord(safe, recipients, { fields: selected });
}
export async function decryptRecord(record, privateJwk) {
  recordCheck(record); jwk(privateJwk, true);
  const e = record.encryption;
  check(plainObject(e) && e.v === ENC_VERSION && e.alg === 'A256GCM' && e.kem === 'ECDH-ES-P256+HKDF-SHA256', 'Nicht unterstütztes Verschlüsselungsprofil.');
  fieldCheck(e.fields);
  for (const field of e.fields) check(!Object.hasOwn(record, field), 'Verschlüsseltes Feld darf nicht zugleich im Klartext vorkommen.');
  bytes(e.nonce, 12); bytes(e.ciphertext, 16 * 1024 * 1024, 16);
  check(Array.isArray(e.recipients) && e.recipients.length > 0 && e.recipients.length <= 64, 'Ungültige Empfängerliste.');
  const ids = new Set();
  for (const r of e.recipients) {
    check(plainObject(r) && typeof r.kid === 'string' && /^[A-Za-z0-9_-]{16}$/.test(r.kid) && !ids.has(r.kid), 'Ungültige oder doppelte Empfänger-ID.');
    ids.add(r.kid); jwk(r.epk); bytes(r.nonce, 12); bytes(r.wrapped_key, 48);
  }
  const result = await legacy.decryptRecord(record, privateJwk);
  const expectedKeys = new Set([...Object.keys(record).filter(key => key !== 'encryption'), ...e.fields]);
  check(Object.keys(result).length === expectedKeys.size && Object.keys(result).every(key => expectedKeys.has(key)), 'Unerwartete entschlüsselte Felder.');
  return result;
}
