/* Shared fixture builders for the benchmarks.
 *
 * Everything here is deterministic or minted once at module load, so the
 * benchmarks measure the library code and not fixture construction. The DER
 * and JUMBF/COSE builders mirror the ones in the test suites.
 */

const subtle = globalThis.crypto.subtle;
const encoder = new TextEncoder();

/* ------------------------------------------------------------------ *
 * Hashes and record inputs
 * ------------------------------------------------------------------ */

export function hexOf(seed) {
  let out = "";
  let x = seed >>> 0 || 1;
  while (out.length < 64) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    out += x.toString(16).padStart(8, "0");
  }
  return out.slice(0, 64);
}

export const CONTENT_HASH = hexOf(42);
export const OTHER_HASH = hexOf(1337);

/** Replaces the "<BERECHNET>" / "<ANDERER HASH>" placeholders used by presets. */
export function fillPreset(preset) {
  const evidence = (preset.evidence ?? []).map((e) => {
    if (e.content_hash === "<BERECHNET>") return { ...e, content_hash: CONTENT_HASH };
    if (e.content_hash === "<ANDERER HASH>") return { ...e, content_hash: OTHER_HASH };
    return { ...e };
  });
  return {
    subject: preset.subject,
    issuer: preset.issuer,
    evidence,
    content_hash: CONTENT_HASH,
    checked_at: "2026-10-08T12:00:00Z",
  };
}

const GENERATION_KINDS = ["trainedAlgorithmicMedia", "digitalCapture", "compositeWithTrainedAlgorithmicMedia"];

/** A large, mixed evidence list: attestations, assertions and generation claims. */
export function makeEvidence(count) {
  const list = [];
  for (let i = 0; i < count; i++) {
    const r = i % 4;
    if (r === 0 || r === 1) {
      list.push({
        kind: "attestation",
        id: `urn:c2pa:${i}`,
        label: "C2PA manifest",
        state: i % 8 === 0 ? "valid" : "unknown",
        chain: i % 3 === 0 ? "intact" : "unavailable",
        content_hash: i % 5 === 0 ? CONTENT_HASH : hexOf(i + 7),
        generation: { kind: GENERATION_KINDS[i % GENERATION_KINDS.length] },
        issued_at: "2026-09-30T08:12:00Z",
      });
    } else if (r === 2) {
      list.push({ kind: "assertion", id: `urn:claim:${i}`, label: "Publisher states authorship", issued_at: "2026-10-01T10:00:00Z" });
    } else {
      list.push({
        kind: "generation_claim",
        generation_kind: GENERATION_KINDS[i % GENERATION_KINDS.length],
        source: `detector-${i}`,
        confidence: (i % 100) / 100,
        issued_at: "2026-10-06T08:00:00Z",
      });
    }
  }
  return list;
}

/* ------------------------------------------------------------------ *
 * C2PA container: JPEG / APP11 / JUMBF / COSE_Sign1
 * ------------------------------------------------------------------ */

const JUMBF_PREFIX = [0x4a, 0x55, 0x4d, 0x42, 0x46];

function catArr(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function box(type, payload) {
  const out = new Uint8Array(8 + payload.length);
  const len = out.length;
  out[0] = (len >>> 24) & 0xff;
  out[1] = (len >>> 16) & 0xff;
  out[2] = (len >>> 8) & 0xff;
  out[3] = len & 0xff;
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(payload, 8);
  return out;
}

/* c2pa-verifier.js expects the APP11 payload to open with the five-byte
 * "JUMBF" word, immediately followed by the box tree. */
function jumbfPayload(inner) {
  return catArr([Uint8Array.from(JUMBF_PREFIX), inner]);
}

function segment(marker, payload) {
  const segLen = payload.length + 2;
  const out = new Uint8Array(2 + segLen);
  out[0] = 0xff;
  out[1] = marker;
  out[2] = (segLen >>> 8) & 0xff;
  out[3] = segLen & 0xff;
  out.set(payload, 4);
  return out;
}

/** CBOR byte string header for any length. */
function bstrHeader(n) {
  if (n < 24) return Uint8Array.of(0x40 | n);
  if (n < 256) return Uint8Array.of(0x58, n);
  if (n < 65536) return Uint8Array.of(0x59, n >> 8, n & 0xff);
  return Uint8Array.of(0x5a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

function bstr(bytes) {
  return catArr([bstrHeader(bytes.length), bytes]);
}

function protectedHeader(alg, cert) {
  return catArr([Uint8Array.of(0xa2, 0x01, 0x18, alg & 0xff), Uint8Array.of(0x18, 0x21, 0x81), bstr(cert)]);
}

/** A claim map with `extra` filler assertions followed by the asset hash. */
export function claim(digest32, extra = 0) {
  const n = extra + 1;
  const parts = [n < 24 ? Uint8Array.of(0xa0 | n) : Uint8Array.of(0xb8, n)];
  for (let i = 0; i < extra; i++) {
    const key = encoder.encode(`assertion-${i}`);
    const value = encoder.encode(`c2pa.actions.${i}`);
    parts.push(Uint8Array.of(0x60 | key.length), key, Uint8Array.of(0x60 | value.length), value);
  }
  parts.push(Uint8Array.of(0x64), encoder.encode("hash"), Uint8Array.of(0x58, 32), digest32);
  return catArr(parts);
}

export function coseSign1(prot, payload, sig) {
  return catArr([Uint8Array.of(0x84), bstr(prot), Uint8Array.of(0xa0), bstr(payload), bstr(sig)]);
}

/** A JPEG with `fillerSegments` APP1 segments before the APP11 manifest, so
 * the marker scan has real work to do. */
export function jpegWith(coseBytes, assetBytes = new Uint8Array(0), fillerSegments = 8) {
  const parts = [Uint8Array.of(0xff, 0xd8)];
  for (let i = 0; i < fillerSegments; i++) {
    const filler = new Uint8Array(1024);
    for (let j = 0; j < filler.length; j++) filler[j] = (i + j) & 0x7f;
    parts.push(segment(0xe1, filler));
  }
  const tree = jumbfPayload(box("jumb", catArr([box("jumd", encoder.encode("c2pa.manifest")), box("cbor", coseBytes)])));
  parts.push(segment(0xeb, tree), Uint8Array.of(0xff, 0xda, 0x00, 0x02), assetBytes);
  return catArr(parts);
}

/** A full C2PA-style file whose claim digest matches the trailing asset bytes. */
export async function makeManifestFile({ assetSize = 4096, extraAssertions = 16, certSize = 512 } = {}) {
  const asset = new Uint8Array(assetSize);
  for (let i = 0; i < asset.length; i++) asset[i] = (i * 31 + 7) & 0xff;
  const digest = new Uint8Array(await subtle.digest("SHA-256", asset));
  const cert = new Uint8Array(certSize).fill(0x30);
  const payload = claim(digest, extraAssertions);
  const cose = coseSign1(protectedHeader(26, cert), payload, new Uint8Array(64).fill(0x5a));
  const bytes = jpegWith(cose, asset);
  return { bytes, cose, payload, assetRange: [bytes.length - asset.length, bytes.length] };
}

/* ------------------------------------------------------------------ *
 * X.509: a minimal DER encoder that mints real ECDSA certificates
 * ------------------------------------------------------------------ */

function cat(...parts) {
  return catArr(parts.flat());
}

function derLength(n) {
  if (n < 128) return Uint8Array.of(n);
  const bytes = [];
  let x = n;
  while (x > 0) {
    bytes.unshift(x & 0xff);
    x >>= 8;
  }
  return cat(Uint8Array.of(0x80 | bytes.length), Uint8Array.from(bytes));
}

function tlv(tag, value) {
  return cat(Uint8Array.of(tag), derLength(value.length), value);
}

export function encodeOid(dotted) {
  const parts = dotted.split(".").map(Number);
  const bytes = [40 * parts[0] + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const stack = [];
    do {
      stack.unshift(v & 0x7f);
      v >>= 7;
    } while (v > 0);
    for (let j = 0; j < stack.length - 1; j++) stack[j] |= 0x80;
    bytes.push(...stack);
  }
  return tlv(0x06, Uint8Array.from(bytes));
}

function attribute(oidDotted, value) {
  return tlv(0x31, tlv(0x30, cat(encodeOid(oidDotted), tlv(0x0c, encoder.encode(value)))));
}

function name(c, o, cn) {
  return tlv(0x30, cat(attribute("2.5.4.6", c), attribute("2.5.4.10", o), attribute("2.5.4.3", cn)));
}

function ecdsaInt(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  let value = bytes.slice(start);
  if (value[0] & 0x80) value = cat(Uint8Array.of(0), value);
  return tlv(0x02, value);
}

/* Same curve OIDs as the parser's lookup table and the x509 test suite. */
const CURVE_OID = { "P-256": "1.2.840.10045.3.1.1", "P-384": "1.3.132.0.34", "P-521": "1.3.132.0.35" };

export async function mintCert({ subjectCN, issuerCN, keyPair, issuerKeyPair, curve = "P-256" } = {}) {
  const kp = keyPair || (await subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]));
  const signer = issuerKeyPair || kp;
  const subject = name("DE", "TRUST Bench CA", subjectCN);
  const issuer = name("DE", "TRUST Bench CA", issuerCN || subjectCN);
  const algorithm = tlv(0x30, cat(encodeOid("1.2.840.10045.2.1"), encodeOid(CURVE_OID[curve])));
  const sigAlg = tlv(0x30, encodeOid("1.2.840.10045.4.3.2"));
  const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));

  const tbs = tlv(
    0x30,
    cat(
      tlv(0xa0, tlv(0x02, Uint8Array.of(2))),
      tlv(0x02, Uint8Array.of(1, 0, 1)),
      sigAlg,
      issuer,
      tlv(0x30, cat(tlv(0x17, encoder.encode("260101000000Z")), tlv(0x17, encoder.encode("261231235959Z")))),
      subject,
      tlv(0x30, cat(algorithm, tlv(0x03, cat(Uint8Array.of(0), spki))))
    )
  );

  const rawSig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, tbs));
  const derSig = tlv(0x30, cat(ecdsaInt(rawSig.slice(0, rawSig.length / 2)), ecdsaInt(rawSig.slice(rawSig.length / 2))));
  return { der: tlv(0x30, cat(tbs, sigAlg, tlv(0x03, cat(Uint8Array.of(0), derSig)))), tbs, signature: derSig, keyPair: kp, spki };
}

/** A root -> intermediate -> leaf chain, returned leaf first. P-384 is used
 * because its curve OID in a WebCrypto-exported SPKI is one the parser knows. */
export async function mintChain(curve = "P-384") {
  const root = await mintCert({ subjectCN: "Bench Root", curve });
  const intermediate = await mintCert({ subjectCN: "Bench Intermediate", issuerCN: "Bench Root", issuerKeyPair: root.keyPair, curve });
  const leaf = await mintCert({ subjectCN: "Bench Signer", issuerCN: "Bench Intermediate", issuerKeyPair: intermediate.keyPair, curve });
  return { root, intermediate, leaf, chain: [leaf.der, intermediate.der, root.der] };
}
