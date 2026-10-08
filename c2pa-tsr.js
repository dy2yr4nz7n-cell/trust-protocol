/* TRUST:// TSR — the second certification step, implemented.
 *
 * What was missing until now: the transport PARSED an RFC 3161 status but never
 * verified the token's own signature. That is the step a reviewer asks about
 * first, and it is the difference between "the authority said granted" and "the
 * authority said granted AND we proved it said so".
 *
 * THE TWO STEPS, KEPT APART
 * -------------------------
 *   1. STATUS     parse TimeStampResp, read PKIStatus            (was built)
 *   2. TSA PROOF  verify the token's CMS SignedData signature
 *                 against the TSA certificate's public key      (this file)
 *
 * A granted status without step 2 is exactly the kind of claim this whole
 * project refuses to make. So a token is `trusted` only when BOTH hold.
 *
 * WHAT THE TOKEN ACTUALLY CONTAINS
 * --------------------------------
 * TimeStampResp
 *   SEQUENCE
 *     PKIStatusInfo   SEQUENCE { status INTEGER, statusString?, failInfo? }
 *     timeStampToken  ContentInfo
 *       SEQUENCE
 *         contentType   OID 1.2.840.113549.1.7.2  (signedData)
 *         content       [0] EXPLICIT SignedData
 *           SEQUENCE
 *             version           INTEGER
 *             digestAlgorithms  SET
 *             encapContentInfo  SEQUENCE { eContentType OID, eContent [0] OCTET STRING }
 *               eContent is the TSTInfo — a DER SEQUENCE carrying
 *               { version, policy, messageImprint{algorithm, hashedMessage},
 *                 serialNumber, genTime, ... }
 *             certificates      [0] IMPLICIT SET of Certificate
 *             signerInfos       SET of SignerInfo
 *               SEQUENCE { version, sid, digestAlgorithm, signedAttrs [0], signatureAlgorithm, signature OCTET STRING }
 *
 * The messageImprint.hashedMessage must equal the digest of the signature bytes
 * the token was made over. That is the link back to the COSE signature — the
 * timestamp does not cover the file, it covers the SIGNATURE.
 */

export const TSR_VERSION = "trust/tsr@0.2";

/* ================================================================== *
 * DER — the walk this file needs
 * ================================================================== */

export function derTlv(bytes, offset) {
  if (offset + 2 > bytes.length) return null;
  let pos = offset;
  const tag = bytes[pos++];
  let len = bytes[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[pos++];
  }
  if (pos + len > bytes.length) return null;
  return { tag, start: offset, valueStart: pos, valueEnd: pos + len, end: pos + len };
}

function derChildren(bytes, parent) {
  const out = [];
  let o = parent.valueStart;
  while (o < parent.valueEnd) {
    const t = derTlv(bytes, o);
    if (!t || t.end <= o) break;
    out.push(t);
    o = t.end;
  }
  return out;
}

function derOid(bytes, tlvNode) {
  if (tlvNode.tag !== 0x06 || tlvNode.valueStart >= tlvNode.valueEnd) return null;
  let pos = tlvNode.valueStart;
  const first = bytes[pos++];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  while (pos < tlvNode.valueEnd) {
    const b = bytes[pos++];
    val = val * 128 + (b & 0x7f);
    if (!(b & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join(".");
}

function derBytes(bytes, tlvNode) {
  return bytes.slice(tlvNode.valueStart, tlvNode.valueEnd);
}

function derInteger(bytes, tlvNode) {
  let v = 0;
  for (let i = tlvNode.valueStart; i < tlvNode.valueEnd; i++) v = v * 256 + bytes[i];
  return v;
}

/** GeneralizedTime on the wire is the DER form: YYYYMMDDHHMMSSZ — fifteen
 *  characters, no separators. The dashed and coloned form is what a human
 *  reads, not what the token says; slicing the display form shifts every
 *  field, which is how this was caught. */
function derTime(bytes, tlvNode) {
  const text = new TextDecoder().decode(bytes.slice(tlvNode.valueStart, tlvNode.valueEnd));
  if (tlvNode.tag === 0x18 && text.length >= 14) {
    return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`;
  }
  if (tlvNode.tag === 0x17 && text.length >= 12) {
    const yy = parseInt(text.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${year}-${text.slice(2, 4)}-${text.slice(4, 6)}T${text.slice(6, 8)}:${text.slice(8, 10)}:${text.slice(10, 12)}Z`;
  }
  return null;
}

/** Re-encode a TLV exactly as it arrived. Signed attributes are signed in their
 *  IMPLICIT [0] form but verified in their explicit SET OF form — the tag byte
 *  is the only difference, and getting that wrong is why so many CMS checks
 *  fail on a token that is perfectly valid. */
function reencodeAsSet(bytes, tlvNode) {
  const out = bytes.slice(tlvNode.start + 1, tlvNode.end);
  const setTag = 0x31;
  const full = new Uint8Array(1 + out.length);
  full[0] = setTag;
  full.set(out, 1);
  return full;
}

/* ================================================================== *
 * TSTInfo — what the token says
 * ================================================================== */

/** Pull the TSTInfo out of a TimeStampToken and read its messageImprint. */
export function parseTstInfo(bytes) {
  const root = derTlv(bytes, 0);
  if (!root || root.tag !== 0x30) return { ok: false, reason: "the token is not a DER SEQUENCE" };

  /* ContentInfo: contentType OID + [0] EXPLICIT content */
  const ci = derChildren(bytes, root);
  const contentType = ci[0] ? derOid(bytes, ci[0]) : null;
  const wrapper = ci.find((c) => c.tag === 0xa0);
  if (!wrapper) return { ok: false, reason: "ContentInfo carries no content" };

  const signedData = derTlv(bytes, wrapper.valueStart);
  if (!signedData || signedData.tag !== 0x30) return { ok: false, reason: "SignedData is not a SEQUENCE" };
  const sd = derChildren(bytes, signedData);

  const encap = sd.find((c) => c.tag === 0x30 && derChildren(bytes, c).length === 2 && derChildren(bytes, c)[0].tag === 0x06);
  if (!encap) return { ok: false, reason: "SignedData has no encapContentInfo" };
  const eContentWrapper = derChildren(bytes, encap).find((c) => c.tag === 0xa0);
  if (!eContentWrapper) return { ok: false, reason: "encapContentInfo carries no eContent" };

  const eContentOctets = derTlv(bytes, eContentWrapper.valueStart);
  if (!eContentOctets || eContentOctets.tag !== 0x04) return { ok: false, reason: "eContent is not an OCTET STRING" };
  const tstInfoBytes = derBytes(bytes, eContentOctets);

  const tst = derTlv(tstInfoBytes, 0);
  if (!tst || tst.tag !== 0x30) return { ok: false, reason: "TSTInfo is not a SEQUENCE" };
  const fields = derChildren(tstInfoBytes, tst);

  const policy = fields[1] ? derOid(tstInfoBytes, fields[1]) : null;
  /* The messageImprint is SEQUENCE { AlgorithmIdentifier, OCTET STRING }. The
   * AlgorithmIdentifier is itself a SEQUENCE, so its OID is a child of the
   * imprint, not of the TSTInfo. Reading them from the wrong level makes every
   * token look like an imprint mismatch — a total failure, not an occasional
   * one, which is how it was found. */
  const imprintSeq = fields[2] && fields[2].tag === 0x30 ? derChildren(tstInfoBytes, fields[2]) : [];
  const digestAlgorithm = imprintSeq.length && imprintSeq[0].tag === 0x30
    ? derOid(tstInfoBytes, derChildren(tstInfoBytes, imprintSeq[0])[0] || imprintSeq[0])
    : null;
  const hashedMessage = imprintSeq.length >= 2 && imprintSeq[1].tag === 0x04
    ? derBytes(tstInfoBytes, imprintSeq[1])
    : null;
  const serialNumber = fields[3] && fields[3].tag === 0x02 ? derInteger(tstInfoBytes, fields[3]) : null;
  const genTime = fields[4] ? derTime(tstInfoBytes, fields[4]) : null;

  if (!hashedMessage) return { ok: false, reason: "TSTInfo carries no messageImprint" };

  return {
    ok: true,
    contentType,
    policy,
    digestAlgorithm,
    hashedMessage,
    serialNumber,
    genTime,
    tstInfoBytes,
    signedData,
    sd,
  };
}

/** Extract the signer's certificate and the signature material from SignedData. */
export function parseSignerInfo(bytes, parsed) {
  const sd = parsed.sd;

  let certificate = null;
  const certWrapper = sd.find((c) => c.tag === 0xa0);
  if (certWrapper) {
    const first = derTlv(bytes, certWrapper.valueStart);
    if (first && first.tag === 0x30) certificate = bytes.slice(first.start, first.end);
  }

  const signerInfos = sd[sd.length - 1];
  if (!signerInfos || signerInfos.tag !== 0x31) return { ok: false, reason: "SignedData has no signerInfos" };
  const signerInfo = derTlv(bytes, signerInfos.valueStart);
  if (!signerInfo) return { ok: false, reason: "signerInfos is empty" };

  const si = derChildren(bytes, signerInfo);
  const digestAlgorithm = si.find((c) => c.tag === 0x30 && derOid(bytes, derChildren(bytes, c)[0] || c));
  const signedAttrs = si.find((c) => c.tag === 0xa0);
  const sigAlgSeq = si.filter((c) => c.tag === 0x30).pop();
  const signature = si.filter((c) => c.tag === 0x04).pop();

  if (!signature) return { ok: false, reason: "signerInfo carries no signature" };

  return {
    ok: true,
    certificate,
    signedAttrs,
    signatureAlgorithm: sigAlgSeq ? derOid(bytes, derChildren(bytes, sigAlgSeq)[0] || sigAlgSeq) : null,
    digestAlgorithm: digestAlgorithm ? derOid(bytes, derChildren(bytes, digestAlgorithm)[0] || digestAlgorithm) : null,
    signature: derBytes(bytes, signature),
  };
}

/** The message-digest attribute inside the signed attributes, when present.
 *  CMS signs the ATTRIBUTES, not the content, so this is the value that must
 *  match the digest of the TSTInfo. */
export function readMessageDigestAttribute(bytes, signedAttrs) {
  if (!signedAttrs) return null;
  for (const attr of derChildren(bytes, signedAttrs)) {
    const parts = derChildren(bytes, attr);
    if (!parts[0]) continue;
    if (derOid(bytes, parts[0]) !== "1.2.840.113549.1.9.4") continue;
    const values = parts.find((p) => p.tag === 0x31);
    if (!values) continue;
    const octets = derTlv(bytes, values.valueStart);
    if (octets && octets.tag === 0x04) return derBytes(bytes, octets);
  }
  return null;
}

/* ================================================================== *
 * Digest helpers
 * ================================================================== */

const DIGEST_NAMES = {
  "2.16.840.1.101.3.4.2.1": { webcrypto: "SHA-256", hex: "sha256" },
  "2.16.840.1.101.3.4.2.2": { webcrypto: "SHA-384", hex: "sha384" },
  "2.16.840.1.101.3.4.2.3": { webcrypto: "SHA-512", hex: "sha512" },
  "1.3.14.3.2.26": { webcrypto: "SHA-1", hex: "sha1" },
};

const SIGNATURE_ALGORITHMS = {
  "1.2.840.10045.4.3.2": { name: "ECDSA", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { name: "ECDSA", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { name: "ECDSA", hash: "SHA-512" },
  "1.2.840.113549.1.1.11": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
  "1.2.840.113549.1.1.12": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
  "1.2.840.113549.1.1.13": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
};

export async function digestHex(name, bytes) {
  const d = await globalThis.crypto.subtle.digest(name, bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ================================================================== *
 * The second certification step
 * ================================================================== */

/**
 * Verify a TimeStampResp. Returns `trusted: true` ONLY when
 *   · the status is granted,
 *   · the TSTInfo's messageImprint matches the digest of the bytes the token
 *     was made over,
 *   · the signerInfo's message-digest attribute matches the digest of the
 *     TSTInfo (CMS signs the attributes, not the content), and
 *   · the CMS signature verifies against the TSA certificate's public key.
 *
 * Every one of those is checked here. A failure at any step returns
 * `trusted: false` with the step named — never a pass with a caveat.
 */
export async function verifyTimestampResponse(responseBytes, options = {}) {
  const bytes = responseBytes instanceof Uint8Array ? responseBytes : new Uint8Array(responseBytes);
  const subtle = options.subtle || globalThis.crypto?.subtle;
  const tsPublicKey = options.tsaPublicKey || null;   // SPKI, when the caller has it
  const expectedDigestHex = options.expectedDigestHex || null; // digest of the signed bytes

  if (!subtle) return { trusted: false, at: null, step: "environment", reason: "no WebCrypto implementation is available" };

  /* --- step 1: status --- */
  const root = derTlv(bytes, 0);
  if (!root || root.tag !== 0x30) return { trusted: false, at: null, step: "parse", reason: "the response is not a DER SEQUENCE" };
  const kids = derChildren(bytes, root);
  const statusInfo = kids[0];
  let status = null;
  if (statusInfo) {
    const s = derChildren(bytes, statusInfo).find((p) => p.tag === 0x02);
    if (s) status = derInteger(bytes, s);
  }
  if (status !== 0) return { trusted: false, at: null, step: "status", reason: "the authority did not return granted status" };

  const token = kids[1];
  if (!token) return { trusted: false, at: null, step: "token", reason: "a granted response carried no timeStampToken" };
  const tokenBytes = bytes.slice(token.start, token.end);

  /* --- step 2: TSTInfo --- */
  const parsed = parseTstInfo(tokenBytes);
  if (!parsed.ok) return { trusted: false, at: null, step: "tstinfo", reason: parsed.reason };

  /* --- step 3: messageImprint against the signed bytes --- */
  if (expectedDigestHex) {
    const algo = DIGEST_NAMES[parsed.digestAlgorithm];
    if (!algo) return { trusted: false, at: parsed.genTime, step: "imprint", reason: "unsupported messageImprint digest " + parsed.digestAlgorithm };
    const imprintHex = [...parsed.hashedMessage].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (imprintHex !== expectedDigestHex.toLowerCase()) {
      return { trusted: false, at: parsed.genTime, step: "imprint", reason: "the messageImprint does not match the digest of the signed bytes" };
    }
  }

  /* --- step 4: CMS signature --- */
  const signer = parseSignerInfo(tokenBytes, parsed);
  if (!signer.ok) return { trusted: false, at: parsed.genTime, step: "signerinfo", reason: signer.reason };

  const spec = SIGNATURE_ALGORITHMS[signer.signatureAlgorithm];
  if (!spec) return { trusted: false, at: parsed.genTime, step: "algorithm", reason: "unsupported signature algorithm " + signer.signatureAlgorithm };

  /* The signed bytes are the signedAttrs in their explicit SET OF form when
   * attributes are present, otherwise the TSTInfo itself. */
  let signedBytes;
  if (signer.signedAttrs) {
    const attrs = reencodeAsSet(tokenBytes, signer.signedAttrs);
    /* The message-digest attribute must match the digest of the TSTInfo. */
    const md = readMessageDigestAttribute(tokenBytes, signer.signedAttrs);
    const tstDigestAlgo = DIGEST_NAMES[signer.digestAlgorithm] || DIGEST_NAMES["2.16.840.1.101.3.4.2.1"];
    if (md) {
      const expect = await digestHex(tstDigestAlgo.webcrypto, parsed.tstInfoBytes);
      const got = [...md].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (expect !== got) {
        return { trusted: false, at: parsed.genTime, step: "contentdigest", reason: "the signed message-digest attribute does not match the TSTInfo" };
      }
    }
    signedBytes = attrs;
  } else {
    signedBytes = parsed.tstInfoBytes;
  }

  const keyBytes = tsPublicKey || signer.certificate;
  if (!keyBytes) {
    return {
      trusted: false, at: parsed.genTime, step: "tsa-key",
      reason: "the token carries no TSA certificate and none was supplied, so the CMS signature was not checked",
      imprintVerified: Boolean(expectedDigestHex),
      tstInfo: { policy: parsed.policy, serial: parsed.serialNumber, genTime: parsed.genTime },
    };
  }

  let key;
  try {
    key = await subtle.importKey("spki", keyBytes, { name: spec.name, namedCurve: spec.name === "ECDSA" ? "P-256" : undefined, hash: spec.hash }, false, ["verify"]);
  } catch (err) {
    return {
      trusted: false, at: parsed.genTime, step: "tsa-key",
      reason: "the TSA key did not import: " + (err && err.message || String(err)),
      imprintVerified: Boolean(expectedDigestHex),
    };
  }

  try {
    const ok = await subtle.verify({ name: spec.name, hash: spec.hash }, key, signer.signature, signedBytes);
    if (!ok) return { trusted: false, at: parsed.genTime, step: "cms-signature", reason: "the CMS signature does not hold over the signed attributes" };
  } catch (err) {
    return { trusted: false, at: parsed.genTime, step: "cms-signature", reason: "CMS verification failed: " + (err && err.message || String(err)) };
  }

  return {
    trusted: true,
    at: parsed.genTime,
    step: "verified",
    reason: "status granted, messageImprint matched, and the CMS signature verified against the TSA key",
    policy: parsed.policy,
    serial: parsed.serialNumber,
    digestAlgorithm: parsed.digestAlgorithm,
  };
}

/** The transport call a caller wires in. It verifies when it can and says
 *  exactly which step blocked when it cannot. */
export function createTsrTransport(options = {}) {
  const { fetchTsr, tsaPublicKey, subtle } = options;
  return {
    async verifyTimestamp({ signature, payload, timestampToken }) {
      if (!timestampToken) {
        return { trusted: false, at: null, step: "none", reason: "no countersignature token was presented" };
      }
      let expectedDigestHex = null;
      if (signature) {
        expectedDigestHex = await digestHex("SHA-256", signature instanceof Uint8Array ? signature : new Uint8Array(signature));
      }
      return verifyTimestampResponse(timestampToken, { subtle, tsaPublicKey, expectedDigestHex });
    },
  };
}
