// TRUST:// Record Format 0.3 – Feldverschlüsselung (Envelope Encryption)
// AES-256-GCM für Inhalt, ECDH-ES (P-256) + HKDF-SHA256 zum Wrappen des Content-Keys.
// Reihenfolge im Gesamtablauf: erst verschlüsseln, dann signieren.

const subtle = globalThis.crypto.subtle;
const rnd = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64u = (buf) => Buffer.from(buf).toString('base64url');
const unb64u = (s) => new Uint8Array(Buffer.from(s, 'base64url'));

export const ENC_VERSION = '0.3';
const KEM = 'ECDH-ES-P256+HKDF-SHA256';
const DEFAULT_FIELDS = ['evidence'];

export async function generateKeyPair() {
  const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const publicJwk = await subtle.exportKey('jwk', kp.publicKey);
  const privateJwk = await subtle.exportKey('jwk', kp.privateKey);
  return { publicJwk, privateJwk, kid: await keyId(publicJwk) };
}

export async function keyId(publicJwk) {
  const canon = JSON.stringify({ crv: publicJwk.crv, kty: publicJwk.kty, x: publicJwk.x, y: publicJwk.y });
  return b64u(new Uint8Array(await subtle.digest('SHA-256', enc.encode(canon))).slice(0, 12));
}

const importPub = (jwk) => subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
const importPriv = (jwk) => subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);

async function wrapKey(priv, pub, epkJwk) {
  const bits = await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  const hk = await subtle.importKey('raw', bits, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('TRUST://wrap|' + epkJwk.x + epkJwk.y) },
    hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// AAD bindet Ciphertext an Record-ID, Version und Feldliste.
const makeAad = (id, fields) => enc.encode(`TRUST://${ENC_VERSION}|${id ?? ''}|${[...fields].sort().join(',')}`);

export async function encryptRecord(record, recipientPublicJwks, { fields = DEFAULT_FIELDS } = {}) {
  if (!recipientPublicJwks?.length) throw new Error('Mindestens ein Empfänger nötig');
  if (record.encryption) throw new Error('Record ist bereits verschlüsselt');
  const present = fields.filter((f) => f in record);
  if (!present.length) throw new Error('Keines der Felder im Record vorhanden');

  const plain = {};
  const out = { ...record };
  for (const f of present) { plain[f] = record[f]; delete out[f]; }

  const cekRaw = rnd(32);
  const cek = await subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['encrypt']);
  const nonce = rnd(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: makeAad(record.id, present) }, cek, enc.encode(JSON.stringify(plain)));

  const recipients = [];
  for (const pubJwk of recipientPublicJwks) {
    const eph = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const epk = await subtle.exportKey('jwk', eph.publicKey);
    const wrapNonce = rnd(12);
    const kek = await wrapKey(eph.privateKey, await importPub(pubJwk), epk);
    const wrapped = await subtle.encrypt({ name: 'AES-GCM', iv: wrapNonce }, kek, cekRaw);
    recipients.push({
      kid: await keyId(pubJwk),
      epk: { kty: epk.kty, crv: epk.crv, x: epk.x, y: epk.y },
      nonce: b64u(wrapNonce),
      wrapped_key: b64u(new Uint8Array(wrapped)),
    });
  }
  cekRaw.fill(0);

  out.encryption = { v: ENC_VERSION, alg: 'A256GCM', kem: KEM, fields: present, nonce: b64u(nonce), ciphertext: b64u(new Uint8Array(ct)), recipients };
  return out;
}

export async function decryptRecord(record, privateJwk) {
  const e = record.encryption;
  if (!e) throw new Error('Record ist nicht verschlüsselt');
  if (e.v !== ENC_VERSION || e.alg !== 'A256GCM' || e.kem !== KEM) throw new Error('Nicht unterstütztes Verschlüsselungsprofil');

  const kid = await keyId(privateJwk);
  const r = e.recipients.find((x) => x.kid === kid);
  if (!r) throw new Error('Kein Schlüsseleintrag für diesen Empfänger');

  const kek = await wrapKey(await importPriv(privateJwk), await importPub(r.epk), r.epk);
  let cekRaw;
  try {
    cekRaw = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(r.nonce) }, kek, unb64u(r.wrapped_key)));
  } catch { throw new Error('Schlüssel konnte nicht entpackt werden'); }

  const cek = await subtle.importKey('raw', cekRaw, 'AES-GCM', false, ['decrypt']);
  cekRaw.fill(0);
  let plain;
  try {
    plain = await subtle.decrypt({ name: 'AES-GCM', iv: unb64u(e.nonce), additionalData: makeAad(record.id, e.fields) }, cek, unb64u(e.ciphertext));
  } catch { throw new Error('Entschlüsselung fehlgeschlagen (manipuliert oder falsche Bindung)'); }

  const { encryption, ...rest } = record;
  return { ...rest, ...JSON.parse(dec.decode(plain)) };
}
