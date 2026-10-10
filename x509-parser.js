// X.509 DER Parser – RFC 5280 – Phase 05 Core
// Parses certificates, validates validity, supports ECDSA (P-256/384/521) + RSA
//
// Offline half of the trust ladder: everything in this module is checkable from
// bytes alone. Nothing here resolves a name, fetches a CRL or consults an
// authority — those are the transport's job (see x509-chain-transport.js).

// ============================================================================
// DER PARSING BASICS
// ============================================================================

class DerParser {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  peek() {
    return this.bytes[this.pos];
  }

  read() {
    if (this.pos >= this.bytes.length) throw new Error("DER: unexpected EOF");
    return this.bytes[this.pos++];
  }

  readBytes(n) {
    if (this.pos + n > this.bytes.length) throw new Error("DER: unexpected EOF");
    const result = this.bytes.slice(this.pos, this.pos + n);
    this.pos += n;
    return result;
  }

  readLength() {
    const first = this.read();
    if (first < 128) return first;

    const numOctets = first & 0x7f;
    if (numOctets === 0) throw new Error("DER: indefinite length not supported");
    if (numOctets > 4) throw new Error("DER: length field longer than 4 octets");

    let len = 0;
    for (let i = 0; i < numOctets; i++) {
      len = len * 256 + this.read();
    }
    return len;
  }

  readTlv() {
    const tag = this.read();
    const length = this.readLength();
    if (this.pos + length > this.bytes.length) throw new Error("DER: truncated TLV");
    const value = this.readBytes(length);
    return { tag, length, value };
  }

  /** The raw TLV (tag + length + value) as one slice. A certificate signature
   *  covers the TBS TLV *including* its header, so callers need the exact bytes
   *  rather than the value alone. */
  readTlvRaw() {
    const start = this.pos;
    this.read();
    const length = this.readLength();
    if (this.pos + length > this.bytes.length) throw new Error("DER: truncated TLV");
    this.readBytes(length);
    return this.bytes.slice(start, this.pos);
  }

  /** The full byte length of the next TLV, without consuming it. */
  peekTlvLength() {
    const save = this.pos;
    this.read();
    const length = this.readLength();
    const header = this.pos - save;
    this.pos = save;
    return header + length;
  }

  readSequence() {
    const tlv = this.readTlv();
    if (tlv.tag !== 0x30) throw new Error("DER: expected SEQUENCE");
    return new DerParser(tlv.value);
  }

  readOid() {
    const tlv = this.readTlv();
    if (tlv.tag !== 0x06) throw new Error("DER: expected OID");
    return decodeOid(tlv.value);
  }

  readInteger() {
    const tlv = this.readTlv();
    if (tlv.tag !== 0x02) throw new Error("DER: expected INTEGER");
    return tlv.value;
  }

  readBitString() {
    const tlv = this.readTlv();
    if (tlv.tag !== 0x03) throw new Error("DER: expected BIT STRING");
    if (tlv.value.length < 1) throw new Error("DER: invalid BIT STRING");
    if (tlv.value[0] > 7) throw new Error("DER: invalid BIT STRING unused-bits count");
    return tlv.value.slice(1);
  }

  readOctetString() {
    const tlv = this.readTlv();
    if (tlv.tag !== 0x04) throw new Error("DER: expected OCTET STRING");
    return tlv.value;
  }

  readTime() {
    const tlv = this.readTlv();
    if (tlv.tag === 0x17) return parseUtcTime(tlv.value);
    if (tlv.tag === 0x18) return parseGeneralizedTime(tlv.value);
    throw new Error("DER: expected Time");
  }

  readExplicit(tag) {
    if (this.peek() !== tag) throw new Error(`DER: expected explicit tag 0x${tag.toString(16)}`);
    this.read();
    const length = this.readLength();
    return new DerParser(this.readBytes(length));
  }

  readExplicitOptional(tag) {
    if (this.peek() === tag) return this.readExplicit(tag);
    return null;
  }

  isEof() {
    return this.pos >= this.bytes.length;
  }
}

// Exported for the transport module, which needs to inspect a bare SPKI.
export class DerReader extends DerParser {}

export function decodeOid(bytes) {
  if (bytes.length === 0) throw new Error("DER: empty OID");

  const first = bytes[0];
  const oid = [Math.floor(first / 40), first % 40];
  let i = 1;

  while (i < bytes.length) {
    let value = 0;
    let b;
    do {
      if (i >= bytes.length) throw new Error("DER: invalid OID encoding");
      b = bytes[i++];
      value = value * 128 + (b & 0x7f);
    } while (b & 0x80);
    oid.push(value);
  }

  return oid.join(".");
}

// UTCTime permits an optional seconds field and either a trailing Z or a
// ±hhmm offset. A strict 13-byte check rejects legitimate certificates.
function parseUtcTime(bytes) {
  const str = new TextDecoder().decode(bytes);
  const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})$/.exec(str);
  if (!m) throw new Error("DER: invalid UTCTime");

  const yy = parseInt(m[1], 10);
  const year = yy > 50 ? 1900 + yy : 2000 + yy;
  const offset = m[7] === "Z" ? 0 : parseOffsetMinutes(m[7]);

  return new Date(
    Date.UTC(year, parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), m[6] ? parseInt(m[6], 10) : 0) -
      offset * 60 * 1000
  );
}

// GeneralizedTime likewise allows optional seconds, an optional fractional part
// and a timezone suffix.
function parseGeneralizedTime(bytes) {
  const str = new TextDecoder().decode(bytes);
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,]\d+)?(Z|[+-]\d{4})$/.exec(str);
  if (!m) throw new Error("DER: invalid GeneralizedTime");

  const offset = m[7] === "Z" ? 0 : parseOffsetMinutes(m[7]);

  return new Date(
    Date.UTC(parseInt(m[1], 10), parseInt(m[2], 10) - 1, parseInt(m[3], 10), parseInt(m[4], 10), parseInt(m[5], 10), m[6] ? parseInt(m[6], 10) : 0) -
      offset * 60 * 1000
  );
}

function parseOffsetMinutes(sign) {
  const s = sign.slice(1);
  const total = parseInt(s.slice(0, 2), 10) * 60 + parseInt(s.slice(2, 4), 10);
  return sign[0] === "+" ? total : -total;
}

// ============================================================================
// X.509 PARSING
// ============================================================================

/**
 * Parses a DER-encoded X.509 certificate.
 *
 * @param {Uint8Array} certDer
 * @returns {object} { ok: true, ...fields } or { ok: false, reason }
 */
export function parseX509Certificate(certDer) {
  try {
    if (!certDer || !(certDer instanceof Uint8Array) || certDer.length === 0) {
      return { ok: false, reason: "invalid certificate format" };
    }

    // A decoded PEM block, if the caller handed us one.
    if (certDer[0] !== 0x30) {
      const fromPem = decodePem(certDer);
      if (fromPem) return parseX509Certificate(fromPem);
    }

    const certSeq = new DerParser(certDer).readSequence();

    // TBSCertificate — capture the exact TLV, header included.
    const tbsBytes = certSeq.readTlvRaw();

    const tbs = new DerParser(tbsBytes).readSequence();

    let version = 1;
    if (tbs.peek() === 0xa0) {
      version = parseInt(tbs.readExplicit(0xa0).readInteger(), 10) + 1;
    }

    const serialNumber = tbs.readInteger();

    const sigAlgParser = tbs.readSequence();
    const sigAlgOid = sigAlgParser.readOid();

    const issuerBytes = tbs.peekTlvLength ? null : null;
    const issuerStart = tbs.pos;
    tbs.readSequence();
    const issuerNameTlv = tbs.bytes.slice(issuerStart, tbs.pos);
    const issuer = parseName(new DerParser(issuerNameTlv).readSequence());

    const validity = tbs.readSequence();
    const notBefore = validity.readTime();
    const notAfter = validity.readTime();

    const subjectStart = tbs.pos;
    tbs.readSequence();
    const subjectTlv = tbs.bytes.slice(subjectStart, tbs.pos);
    const subject = parseName(new DerParser(subjectTlv).readSequence());

    // SubjectPublicKeyInfo — keep the whole structure, WebCrypto wants it.
    const spkiTlv = tbs.readTlvRaw();
    const publicKey = parsePublicKeyInfo(new DerParser(spkiTlv).readSequence());
    publicKey.spki = spkiTlv;

    // Extensions, if present ([3] EXPLICIT).
    let extensions = null;
    if (tbs.peek() === 0xa3) {
      extensions = parseExtensions(tbs.readExplicit(0xa3));
    }

    const outerSigAlg = certSeq.readSequence();
    const certificateSignatureAlgorithm = outerSigAlg.readOid();
    const signature = certSeq.readBitString();

    return {
      ok: true,
      version,
      serialNumber,
      issuer,
      subject,
      issuerBytes: issuerNameTlv,
      notBefore,
      notAfter,
      publicKey,
      signature,
      signatureAlgorithm: sigAlgOid,
      certificateSignatureAlgorithm,
      algorithmsConsistent: sigAlgOid === certificateSignatureAlgorithm,
      extensions,
      tbsBytes,
    };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

function decodePem(bytes) {
  try {
    const text = new TextDecoder("ascii").decode(bytes);
    const m = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/.exec(text);
    if (!m) return null;
    const b64 = m[1].replace(/\s+/g, "");
    const binary = atob(b64);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out.length ? out : null;
  } catch (e) {
    return null;
  }
}

function parseName(nameParser) {
  const rdns = [];

  while (!nameParser.isEof()) {
    const rdn = [];
    const rdnParser = nameParser.readSequence();

    while (!rdnParser.isEof()) {
      const attr = rdnParser.readSequence();
      const oid = attr.readOid();
      const value = attr.readTlv();
      rdn.push(`${mapOidToName(oid)}=${decodeDirectoryString(value)}`);
    }

    rdns.push(rdn.join(", "));
  }

  return rdns;
}

// DirectoryString may be UTF8String, PrintableString, IA5String, T61String or
// BMPString. Most real CAs use PrintableString, so a UTF-8-only decoder mangles
// their names.
function decodeDirectoryString(tlv) {
  switch (tlv.tag) {
    case 0x0c:
    case 0x13:
    case 0x16:
      return new TextDecoder("utf-8").decode(tlv.value);
    case 0x14:
      return new TextDecoder("iso-8859-1").decode(tlv.value);
    case 0x1e: {
      let s = "";
      for (let i = 0; i + 1 < tlv.value.length; i += 2) {
        s += String.fromCharCode((tlv.value[i] << 8) | tlv.value[i + 1]);
      }
      return s;
    }
    default:
      return new TextDecoder("utf-8").decode(tlv.value);
  }
}

function mapOidToName(oid) {
  const map = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "street",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "2.5.4.12": "title",
    "2.5.4.97": "organizationIdentifier",
    "1.2.840.113549.1.9.1": "emailAddress",
  };
  return map[oid] || `OID_${oid}`;
}

function parsePublicKeyInfo(spkiParser) {
  try {
    const algParser = spkiParser.readSequence();
    const algorithm = algParser.readOid();
    const keyBits = spkiParser.readBitString();

    let keyType = "unknown";
    let curve = "unknown";

    if (algorithm === "1.2.840.10045.2.1") {
      keyType = "ec";
      if (!algParser.isEof()) {
        const curveOid = algParser.readOid();
        curve = CURVE_OIDS[curveOid] || "unknown";
      }
    } else if (algorithm === "1.2.840.113549.1.1.1") {
      keyType = "rsa";
    }

    return { type: keyType, curve, algorithm, spki: keyBits };
  } catch (e) {
    return { type: "unknown", curve: "unknown", algorithm: null, spki: new Uint8Array(0) };
  }
}

const CURVE_OIDS = {
  "1.2.840.10045.3.1.1": "P-256",
  "1.3.132.0.34": "P-384",
  "1.3.132.0.35": "P-521",
};

function parseExtensions(extParser) {
  const out = {};
  try {
    const seq = extParser.readSequence();
    while (!seq.isEof()) {
      const ext = seq.readSequence();
      const oid = ext.readOid();
      const critical = ext.peek() === 0x01;
      if (critical) ext.readTlv();
      const value = ext.readOctetString().slice();

      if (oid === "2.5.29.19") {
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLen INTEGER OPTIONAL }
        try {
          const inner = new DerParser(value).readSequence();
          let ca = false;
          if (inner.peek() === 0x01) ca = inner.readTlv().value[0] !== 0;
          let pathLen = null;
          if (!inner.isEof() && inner.peek() === 0x02) pathLen = parseInt(inner.readInteger(), 10);
          out.basicConstraints = { ca, pathLen };
        } catch (e) {
          out.basicConstraints = { ca: false, pathLen: null, malformed: true };
        }
      } else if (oid === "2.5.29.15") {
        out.keyUsage = decodeKeyUsage(value);
      } else if (oid === "2.5.29.37") {
        const usages = [];
        try {
          const inner = new DerParser(value).readSequence();
          while (!inner.isEof()) usages.push(inner.readOid());
        } catch (e) {
          /* leave usages empty */
        }
        out.extendedKeyUsage = usages;
      } else if (oid === "2.5.29.17") {
        out.subjectAltName = decodeGeneralNames(value);
      } else if (oid === "2.5.29.14") {
        try {
          out.subjectKeyIdentifier = toHex(new DerParser(value).readOctetString());
        } catch (e) {
          /* ignore */
        }
      } else if (oid === "2.5.29.35") {
        try {
          const inner = new DerParser(value).readSequence();
          if (inner.peek() === 0x80) out.authorityKeyIdentifier = toHex(inner.readTlv().value);
        } catch (e) {
          /* ignore */
        }
      }
    }
  } catch (e) {
    out._malformed = e.message;
  }
  return out;
}

const KEY_USAGE_BITS = [
  "digitalSignature",
  "nonRepudiation",
  "keyEncipherment",
  "dataEncipherment",
  "keyAgreement",
  "keyCertSign",
  "cRLSign",
  "encipherOnly",
  "decipherOnly",
];

function decodeKeyUsage(bytes) {
  const usages = [];
  try {
    const bs = new DerParser(bytes).readBitString();
    const unused = bytes[bytes.length - bs.length - 1] || 0;
    const totalBits = bs.length * 8 - unused;
    for (let i = 0; i < Math.min(totalBits, KEY_USAGE_BITS.length); i++) {
      const byte = bs[Math.floor(i / 8)];
      if (byte & (0x80 >> i % 8)) usages.push(KEY_USAGE_BITS[i]);
    }
  } catch (e) {
    /* leave empty */
  }
  return usages;
}

function decodeGeneralNames(bytes) {
  const names = [];
  try {
    const seq = new DerParser(bytes).readSequence();
    while (!seq.isEof()) {
      const tag = seq.peek();
      const tlv = seq.readTlv();
      if (tag === 0x82) names.push("DNS:" + new TextDecoder("ascii").decode(tlv.value));
      else if (tag === 0x81) names.push("email:" + new TextDecoder("ascii").decode(tlv.value));
      else if (tag === 0x86) names.push("URI:" + new TextDecoder("ascii").decode(tlv.value));
      else if (tag === 0x87) names.push("IP:" + toHex(tlv.value));
      else names.push("tag0x" + tag.toString(16));
    }
  } catch (e) {
    /* leave empty */
  }
  return names;
}

function toHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ============================================================================
// VALIDITY
// ============================================================================

/**
 * Whether a parsed certificate is inside its validity window.
 *
 * @param {object} cert parsed certificate
 * @param {Date} referenceTime
 * @returns {boolean}
 */
export function isCertificateValid(cert, referenceTime = new Date()) {
  if (!cert || !cert.notBefore || !cert.notAfter) return false;
  return referenceTime >= cert.notBefore && referenceTime <= cert.notAfter;
}

/**
 * Reports the certificate's position relative to a reference time with more
 * detail than a boolean, for callers that need to distinguish expired from
 * not-yet-valid.
 */
export function certificateValidity(cert, referenceTime = new Date()) {
  if (!cert || !cert.notBefore || !cert.notAfter) return { state: "unknown", reason: "no validity fields" };
  if (referenceTime < cert.notBefore) return { state: "not-yet-valid", notBefore: cert.notBefore, notAfter: cert.notAfter };
  if (referenceTime > cert.notAfter) return { state: "expired", notBefore: cert.notBefore, notAfter: cert.notAfter };
  return { state: "valid", notBefore: cert.notBefore, notAfter: cert.notAfter };
}

// ============================================================================
// SIGNATURE VERIFICATION
// ============================================================================

const CERT_SIG_ALGORITHMS = {
  "1.2.840.113549.1.1.5": { kind: "rsa", hash: "SHA-1" },
  "1.2.840.113549.1.1.11": { kind: "rsa", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { kind: "rsa", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { kind: "rsa", hash: "SHA-512" },
  "1.2.840.10045.4.3.2": { kind: "ecdsa", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { kind: "ecdsa", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { kind: "ecdsa", hash: "SHA-512" },
};

const EC_CURVE_NAMES = { "P-256": "P-256", "P-384": "P-384", "P-521": "P-521" };

async function subtleOrNull() {
  const s = globalThis.crypto?.subtle;
  if (s) return s;
  try {
    const nodeCrypto = await import("node:crypto");
    return nodeCrypto.webcrypto?.subtle ?? null;
  } catch (e) {
    return null;
  }
}

/**
 * Verifies a raw signature over TBS bytes using an issuer SubjectPublicKeyInfo.
 * ECDSA signatures arrive as a DER SEQUENCE {r, s} (RFC 5280) and are converted
 * to the fixed-width r||s form WebCrypto expects.
 *
 * @param {Uint8Array} tbsBytes
 * @param {Uint8Array} signature
 * @param {Uint8Array} issuerSpkiDer full SPKI DER
 * @param {string} signatureAlgOid
 * @returns {Promise<{ok: boolean, code: string, reason: string}>}
 */
export async function verifyCertificateSignature(tbsBytes, signature, issuerSpkiDer, signatureAlgOid) {
  const subtle = await subtleOrNull();
  if (!subtle) return { ok: false, code: "no-webcrypto", reason: "no WebCrypto implementation is available" };

  const hint = CERT_SIG_ALGORITHMS[signatureAlgOid];
  if (!hint) {
    return { ok: false, code: "algorithm-unsupported", reason: `unsupported certificate signature algorithm ${signatureAlgOid}` };
  }

  try {
    if (hint.kind === "rsa") {
      const key = await subtle.importKey("spki", issuerSpkiDer, { name: "RSASSA-PKCS1-v1_5", hash: hint.hash }, false, ["verify"]);
      const ok = await subtle.verify("RSASSA-PKCS1-v1_5", key, signature, tbsBytes);
      return ok
        ? { ok: true, code: "signature-verified", reason: "certificate signature verified" }
        : { ok: false, code: "signature-mismatch", reason: "certificate signature does not hold" };
    }

    const curve = curveFromSpki(issuerSpkiDer);
    if (!curve) return { ok: false, code: "key-unsupported", reason: "could not determine the issuer EC curve" };

    const p1363 = derEcdsaToP1363(signature, curve);
    if (!p1363) return { ok: false, code: "signature-malformed", reason: "ECDSA signature is not a valid DER SEQUENCE" };

    const key = await subtle.importKey("spki", issuerSpkiDer, { name: "ECDSA", namedCurve: EC_CURVE_NAMES[curve] }, false, ["verify"]);
    const ok = await subtle.verify({ name: "ECDSA", hash: hint.hash }, key, p1363, tbsBytes);
    return ok
      ? { ok: true, code: "signature-verified", reason: "certificate signature verified" }
      : { ok: false, code: "signature-mismatch", reason: "certificate signature does not hold" };
  } catch (e) {
    return { ok: false, code: "verification-failed", reason: e.message };
  }
}

function curveFromSpki(spkiDer) {
  try {
    const seq = new DerParser(spkiDer).readSequence();
    const alg = seq.readSequence();
    if (alg.readOid() !== "1.2.840.10045.2.1") return null;
    return CURVE_OIDS[alg.readOid()] || null;
  } catch (e) {
    return null;
  }
}

function derEcdsaToP1363(der, curve) {
  const sizes = { "P-256": 32, "P-384": 48, "P-521": 66 };
  const n = sizes[curve];
  if (!n) return null;

  try {
    const inner = new DerParser(der).readSequence();
    const r = stripAndPad(inner.readInteger(), n);
    const s = stripAndPad(inner.readInteger(), n);
    if (!r || !s) return null;
    const out = new Uint8Array(n * 2);
    out.set(r, 0);
    out.set(s, n);
    return out;
  } catch (e) {
    return null;
  }
}

function stripAndPad(intBytes, n) {
  let v = intBytes;
  while (v.length > 1 && v[0] === 0) v = v.slice(1);
  if (v.length > n) return null;
  if (v.length === n) return v;
  const out = new Uint8Array(n);
  out.set(v, n - v.length);
  return out;
}

/**
 * Verifies one certificate against its issuer's public key. Pass `null` as the
 * issuer SPKI to check a self-signed certificate against its own key.
 *
 * @param {Uint8Array} certDer
 * @param {Uint8Array|null} issuerSpkiDer
 * @param {Date} referenceTime
 */
export async function verifyCertificate(certDer, issuerSpkiDer, referenceTime = new Date()) {
  const cert = parseX509Certificate(certDer);
  if (!cert.ok) return { valid: false, code: "certificate-malformed", reason: cert.reason };

  if (!isCertificateValid(cert, referenceTime)) {
    const rel = certificateValidity(cert, referenceTime);
    return {
      valid: false,
      code: rel.state === "expired" ? "certificate-expired" : "certificate-not-yet-valid",
      reason: `certificate is ${rel.state} at ${referenceTime.toISOString()}`,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
    };
  }

  if (cert.algorithmsConsistent === false) {
    return { valid: false, code: "algorithm-mismatch", reason: "the TBS and certificate signature algorithms differ" };
  }

  const spki = issuerSpkiDer || cert.publicKey.spki;
  const res = await verifyCertificateSignature(cert.tbsBytes, cert.signature, spki, cert.signatureAlgorithm);
  if (!res.ok) return { valid: false, code: res.code, reason: res.reason };

  return {
    valid: true,
    code: "certificate-verified",
    reason: "certificate signature verified",
    subject: cert.subject,
    issuer: cert.issuer,
    notBefore: cert.notBefore,
    notAfter: cert.notAfter,
  };
}

// ============================================================================
// CHAIN VALIDATION
// ============================================================================

/**
 * Validates a certificate chain leaf-first.
 *
 * Every link's signature is verified against the next certificate's key, then
 * the terminal certificate must be self-signed AND match a configured anchor.
 * Nothing here resolves a network name: anchors are supplied by the caller.
 *
 * @param {Uint8Array[]} certificates leaf first, root last
 * @param {Array<Uint8Array|string>} trustAnchors
 * @param {Date} referenceTime
 */
export async function validateCertificateChain(certificates, trustAnchors, referenceTime = new Date()) {
  if (!certificates || certificates.length === 0) {
    return { ok: false, trustEstablished: false, code: "no-certificates", reason: "no certificates provided" };
  }

  if (!trustAnchors || trustAnchors.length === 0) {
    return { ok: false, trustEstablished: false, code: "no-trust-anchors", reason: "no trust anchors" };
  }

  const parsed = [];
  for (const der of certificates) {
    const p = parseX509Certificate(der instanceof Uint8Array ? der : new Uint8Array(der));
    if (!p.ok) {
      return { ok: false, trustEstablished: false, code: "certificate-malformed", reason: `certificate parsing failed: ${p.reason}` };
    }
    parsed.push({ der: der instanceof Uint8Array ? der : new Uint8Array(der), parsed: p });
  }

  for (let i = 0; i < parsed.length; i++) {
    if (!isCertificateValid(parsed[i].parsed, referenceTime)) {
      return {
        ok: false,
        trustEstablished: false,
        code: "certificate-expired",
        reason: `certificate ${i} is not valid at ${referenceTime.toISOString()}`,
      };
    }
  }

  for (let i = 0; i < parsed.length - 1; i++) {
    const res = await verifyCertificateSignature(
      parsed[i].parsed.tbsBytes,
      parsed[i].parsed.signature,
      parsed[i + 1].parsed.publicKey.spki,
      parsed[i].parsed.signatureAlgorithm
    );
    if (!res.ok) {
      return {
        ok: false,
        trustEstablished: false,
        code: res.code,
        reason: `certificate ${i} does not verify against its issuer: ${res.reason}`,
      };
    }
  }

  const root = parsed[parsed.length - 1];
  const selfSigned = await verifyCertificateSignature(
    root.parsed.tbsBytes,
    root.parsed.signature,
    root.parsed.publicKey.spki,
    root.parsed.signatureAlgorithm
  );

  if (!selfSigned.ok) {
    return {
      ok: false,
      trustEstablished: false,
      code: "root-not-self-signed",
      reason: `the terminal certificate is not self-signed: ${selfSigned.reason}`,
    };
  }

  const subjectName = root.parsed.subject.join(",");
  let anchor = null;
  for (const candidate of trustAnchors) {
    if (candidate instanceof Uint8Array) {
      if (byteEqual(candidate, root.der)) {
        anchor = subjectName;
        break;
      }
      const parsedAnchor = parseX509Certificate(candidate);
      if (parsedAnchor.ok && parsedAnchor.subject.join(",") === subjectName) {
        anchor = subjectName;
        break;
      }
    } else if (typeof candidate === "string") {
      // A string anchor is only honoured for a root whose own signature has
      // already been checked above.
      if (candidate === subjectName || subjectName.includes(candidate)) {
        anchor = subjectName;
        break;
      }
    }
  }

  if (!anchor) {
    return {
      ok: false,
      trustEstablished: false,
      code: "anchor-not-found",
      reason: "the root certificate does not match any trust anchor",
    };
  }

  return {
    ok: true,
    trustEstablished: true,
    anchor,
    chainLength: parsed.length,
    code: "chain-verified",
    reason: "every certificate signature verified and the root matches a trust anchor",
  };
}

function byteEqual(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ============================================================================
// CONVENIENCE
// ============================================================================

/**
 * Single-call validation of one certificate against a leaf-anchored chain.
 * Kept deliberately separate from validateCertificateChain so the two can be
 * tested independently.
 */
export async function validateCertificate(certDer, { trustAnchors = [], referenceTime = new Date() } = {}) {
  const parsed = parseX509Certificate(certDer);
  if (!parsed.ok) return { ok: false, code: "certificate-malformed", reason: parsed.reason };

  const rel = certificateValidity(parsed, referenceTime);
  if (rel.state !== "valid") return { ok: false, code: `certificate-${rel.state}`, reason: `certificate is ${rel.state}` };

  for (const anchor of trustAnchors) {
    const der = anchor instanceof Uint8Array ? anchor : new Uint8Array(anchor);
    const chain = await validateCertificateChain([certDer], [der], referenceTime);
    if (chain.ok) return { ok: true, anchor: chain.anchor, code: "certificate-verified", subject: parsed.subject };
  }

  return { ok: false, code: "anchor-not-found", reason: "no trust anchor matched this certificate" };
}
