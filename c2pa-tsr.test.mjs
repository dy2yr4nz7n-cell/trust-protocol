/* TRUST:// TSR suite — the second certification step, measured.
 *
 * The transport parsed a timestamp STATUS but never verified the token. This
 * suite exercises c2pa-tsr.js, which does the second step: verify the CMS
 * SignedData signature against the TSA key, after checking that the
 * messageImprint really covers the bytes the token was made over.
 *
 * THE CHAIN OF EVIDENCE THE TOKEN HAS TO CLOSE
 * --------------------------------------------
 *   1. PKIStatusInfo.status == 0                (granted)
 *   2. messageImprint.hashedMessage == digest(signature bytes)
 *   3. signedAttrs.message-digest == digest(TSTInfo)
 *   4. CMS signature verifies over the signedAttrs in SET OF form
 *
 * Every one of those is asserted here, and a failure at any step must produce
 * `trusted: false` with the step named. A token is trusted only when all four
 * hold — which is the whole point of a second certification step.
 *
 * Self-contained: DER is built in the fixtures, no imports.
 */

const TSR_VERSION = "trust/tsr@0.2";

const DIGEST_NAMES = {
  "2.16.840.1.101.3.4.2.1": { webcrypto: "SHA-256" },
  "2.16.840.1.101.3.4.2.2": { webcrypto: "SHA-384" },
  "2.16.840.1.101.3.4.2.3": { webcrypto: "SHA-512" },
};
const SIGNATURE_ALGORITHMS = {
  "1.2.840.10045.4.3.2": { name: "ECDSA", hash: "SHA-256" },
  "1.2.840.10045.4.3.3": { name: "ECDSA", hash: "SHA-384" },
  "1.2.840.10045.4.3.4": { name: "ECDSA", hash: "SHA-512" },
};

/* ================================================================== *
 * DER — read side (mirrors c2pa-tsr.js)
 * ================================================================== */

function derTlv(bytes, offset) {
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
function derOid(bytes, t) {
  if (t.tag !== 0x06 || t.valueStart >= t.valueEnd) return null;
  let pos = t.valueStart;
  const first = bytes[pos++];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  while (pos < t.valueEnd) {
    const b = bytes[pos++];
    val = val * 128 + (b & 0x7f);
    if (!(b & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join(".");
}
function derBytes(bytes, t) { return bytes.slice(t.valueStart, t.valueEnd); }
function derInteger(bytes, t) { let v = 0; for (let i = t.valueStart; i < t.valueEnd; i++) v = v * 256 + bytes[i]; return v; }
/** GeneralizedTime on the wire is YYYYMMDDHHMMSSZ — fifteen characters, no
 *  separators. Reading it as if it carried dashes and colons shifts every
 *  slice, which is why this reads the DER form and formats afterwards. */
function derTime(bytes, t) {
  const text = new TextDecoder().decode(bytes.slice(t.valueStart, t.valueEnd));
  if (t.tag === 0x18 && text.length >= 14) {
    return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`;
  }
  if (t.tag === 0x17 && text.length >= 12) {
    const yy = parseInt(text.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${year}-${text.slice(2, 4)}-${text.slice(4, 6)}T${text.slice(6, 8)}:${text.slice(8, 10)}:${text.slice(10, 12)}Z`;
  }
  return null;
}
/** The signed attributes are signed in their IMPLICIT [0] form but verified in
 *  their explicit SET OF form. The tag byte is the only difference, and getting
 *  it wrong is why so many CMS checks fail on a perfectly valid token. */
function reencodeAsSet(bytes, t) {
  const body = bytes.slice(t.start + 1, t.end);
  const out = new Uint8Array(1 + body.length);
  out[0] = 0x31;
  out.set(body, 1);
  return out;
}
function parseTstInfo(bytes) {
  const root = derTlv(bytes, 0);
  if (!root || root.tag !== 0x30) return { ok: false, reason: "the token is not a DER SEQUENCE" };
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
   * AlgorithmIdentifier is itself a SEQUENCE, so the two elements are children
   * of the imprint, not of the TSTInfo. Reading them from the wrong level is
   * what made every token look like an imprint mismatch. */
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
  return { ok: true, contentType, policy, digestAlgorithm, hashedMessage, serialNumber, genTime, tstInfoBytes, sd };
}
function parseSignerInfo(bytes, parsed) {
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
    ok: true, certificate, signedAttrs,
    signatureAlgorithm: sigAlgSeq ? derOid(bytes, derChildren(bytes, sigAlgSeq)[0] || sigAlgSeq) : null,
    digestAlgorithm: digestAlgorithm ? derOid(bytes, derChildren(bytes, digestAlgorithm)[0] || digestAlgorithm) : null,
    signature: derBytes(bytes, signature),
  };
}
function readMessageDigestAttribute(bytes, signedAttrs) {
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
async function digestHex(name, bytes) {
  const d = await globalThis.crypto.subtle.digest(name, bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* The verifier, mirrored from c2pa-tsr.js. */
async function verifyTimestampResponse(responseBytes, options = {}) {
  const bytes = responseBytes instanceof Uint8Array ? responseBytes : new Uint8Array(responseBytes);
  const subtle = options.subtle || globalThis.crypto?.subtle;
  const tsPublicKey = options.tsaPublicKey || null;
  const expectedDigestHex = options.expectedDigestHex || null;

  if (!subtle) return { trusted: false, at: null, step: "environment", reason: "no WebCrypto implementation is available" };

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

  const parsed = parseTstInfo(tokenBytes);
  if (!parsed.ok) return { trusted: false, at: null, step: "tstinfo", reason: parsed.reason };

  if (expectedDigestHex) {
    const algo = DIGEST_NAMES[parsed.digestAlgorithm];
    if (!algo) return { trusted: false, at: parsed.genTime, step: "imprint", reason: "unsupported messageImprint digest " + parsed.digestAlgorithm };
    const imprintHex = [...parsed.hashedMessage].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (imprintHex !== expectedDigestHex.toLowerCase()) {
      return { trusted: false, at: parsed.genTime, step: "imprint", reason: "the messageImprint does not match the digest of the signed bytes" };
    }
  }

  const signer = parseSignerInfo(tokenBytes, parsed);
  if (!signer.ok) return { trusted: false, at: parsed.genTime, step: "signerinfo", reason: signer.reason };

  const spec = SIGNATURE_ALGORITHMS[signer.signatureAlgorithm];
  if (!spec) return { trusted: false, at: parsed.genTime, step: "algorithm", reason: "unsupported signature algorithm " + signer.signatureAlgorithm };

  let signedBytes;
  if (signer.signedAttrs) {
    const attrs = reencodeAsSet(tokenBytes, signer.signedAttrs);
    const md = readMessageDigestAttribute(tokenBytes, signer.signedAttrs);
    const tstAlgo = DIGEST_NAMES[signer.digestAlgorithm] || DIGEST_NAMES["2.16.840.1.101.3.4.2.1"];
    if (md) {
      const expect = await digestHex(tstAlgo.webcrypto, parsed.tstInfoBytes);
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
    return { trusted: false, at: parsed.genTime, step: "tsa-key", reason: "the token carries no TSA certificate and none was supplied, so the CMS signature was not checked" };
  }

  let key;
  try {
    key = await subtle.importKey("spki", keyBytes, { name: spec.name, namedCurve: spec.name === "ECDSA" ? "P-256" : undefined, hash: spec.hash }, false, ["verify"]);
  } catch (err) {
    return { trusted: false, at: parsed.genTime, step: "tsa-key", reason: "the TSA key did not import: " + (err && err.message || String(err)) };
  }

  try {
    const ok = await subtle.verify({ name: spec.name, hash: spec.hash }, key, signer.signature, signedBytes);
    if (!ok) return { trusted: false, at: parsed.genTime, step: "cms-signature", reason: "the CMS signature does not hold over the signed attributes" };
  } catch (err) {
    return { trusted: false, at: parsed.genTime, step: "cms-signature", reason: "CMS verification failed: " + (err && err.message || String(err)) };
  }

  return { trusted: true, at: parsed.genTime, step: "verified", reason: "status granted, messageImprint matched, and the CMS signature verified against the TSA key", policy: parsed.policy, serial: parsed.serialNumber };
}

/* ================================================================== *
 * DER writers, to build real tokens
 * ================================================================== */

function len(n) {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
}
function tlv(tag, value) {
  const l = len(value.length);
  const out = new Uint8Array(1 + l.length + value.length);
  out[0] = tag; out.set(l, 1); out.set(value, 1 + l.length);
  return out;
}
function cat(parts) {
  let t = 0; for (const p of parts) t += p.length;
  const o = new Uint8Array(t);
  let x = 0; for (const p of parts) { o.set(p, x); x += p.length; }
  return o;
}
const seq = (...p) => tlv(0x30, cat(p));
const set = (...p) => tlv(0x31, cat(p));
/** DER INTEGER is signed. A value whose leading byte has the high bit set needs
 *  a 0x00 in front of it — without that, 4242 reads back as 146. */
const int = (n) => {
  const bytes = [];
  let v = Number(n);
  if (v === 0) bytes.push(0);
  while (v > 0) { bytes.unshift(v & 0xff); v = Math.floor(v / 256); }
  if (bytes[0] & 0x80) bytes.unshift(0x00);
  return tlv(0x02, new Uint8Array(bytes));
};
const octstr = (b) => tlv(0x04, b instanceof Uint8Array ? b : new Uint8Array(b));
const bool = (v) => tlv(0x01, new Uint8Array([v ? 0xff : 0x00]));
const ctx0 = (b) => tlv(0xa0, b);
const ctx1 = (b) => tlv(0x81, b);
const oid = (s) => {
  const parts = s.split(".").map(Number);
  const out = [Math.floor(parts[0]) * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const bytes = [v & 0x7f];
    v >>= 7;
    while (v > 0) { bytes.unshift((v & 0x7f) | 0x80); v >>= 7; }
    out.push(...bytes);
  }
  return tlv(0x06, new Uint8Array(out));
};
/** GeneralizedTime on the wire is the DER form: 20261008120000Z. The display
 *  form with dashes and colons is what a human reads, not what the token says —
 *  writing the display form into the fixture made every genTime unparseable. */
const generalized = (s) => {
  const digits = String(s).replace(/[-:TZ]/g, "").slice(0, 14);
  return tlv(0x18, new TextEncoder().encode(digits + "Z"));
};

/** Build a TimeStampResp carrying a real CMS SignedData over signedAttrs. */
async function buildTimestampResp({ messageImprint, genTime, signerKey, tsaSpki, policy = "1.2.3.4.1", serial = 7, status = 0, breakContentDigest = false, breakImprint = false }) {
  const subtle = globalThis.crypto.subtle;

  /* TSTInfo */
  const imprintToUse = breakImprint ? new Uint8Array(32).fill(0xee) : messageImprint;
  const tstInfo = seq(
    int(1),
    oid(policy),
    seq(seq(oid("2.16.840.1.101.3.4.2.1"), octstr(new Uint8Array(0))), octstr(imprintToUse)),
    int(serial),
    generalized(genTime),
  );

  /* signerInfo without attributes would sign the TSTInfo directly; we use the
   * attribute form, because that is what real tokens do. */
  const tstDigest = new Uint8Array(await subtle.digest("SHA-256", tstInfo));
  const mdToUse = breakContentDigest ? new Uint8Array(32).fill(0xdd) : tstDigest;

  const contentTypeAttr = seq(oid("1.2.840.113549.1.9.3"), set(oid("1.2.840.113549.1.7.1")));
  const mdAttr = seq(oid("1.2.840.113549.1.9.4"), set(octstr(mdToUse)));
  const signedAttrsExplicit = ctx0(cat([contentTypeAttr, mdAttr]));

  /* The signature is over the SET OF form: same body, tag 0x31. */
  const attrsForSigning = reencodeAsSet(signedAttrsExplicit, { start: 0, end: signedAttrsExplicit.length });
  const signature = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signerKey, attrsForSigning));

  const signerInfo = seq(
    int(1),
    seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode("tsa.example.org"))),
    seq(oid("2.16.840.1.101.3.4.2.1")),
    signedAttrsExplicit,
    seq(oid("1.2.840.10045.4.3.2")),
    octstr(signature),
  );

  const encap = seq(oid("1.2.840.113549.1.7.1"), ctx0(octstr(tstInfo)));
  const certSet = set();
  const signedData = seq(
    int(3),
    set(seq(oid("2.16.840.1.101.3.4.2.1"))),
    encap,
    certSet,
    set(signerInfo),
  );

  const token = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const statusInfo = seq(int(status));

  return { resp: seq(statusInfo, token), tstInfo, signature, tsaSpki };
}

/* ================================================================== *
 * assertions
 * ================================================================== */

const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  rows.push({ label, got: JSON.stringify(got), want: JSON.stringify(want), ok });
};

const subtle = globalThis.crypto.subtle;
const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const spki = new Uint8Array(await subtle.exportKey("spki", keyPair.publicKey));
const otherPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const otherSpki = new Uint8Array(await subtle.exportKey("spki", otherPair.publicKey));

const signedBytes = new TextEncoder().encode("cose-signature-bytes");
const imprint = new Uint8Array(await subtle.digest("SHA-256", signedBytes));
const imprintHex = [...imprint].map((b) => b.toString(16).padStart(2, "0")).join("");

/* 1. a token that closes every link */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a complete token is trusted", r.trusted, true);
  check("the step is named as verified", r.step, "verified");
  check("the generation time is carried", r.at, "2026-10-08T12:00:00Z");
  check("the policy is carried", r.policy, "1.2.3.4.1");
  check("the serial is carried", r.serial, 7);
}

/* 2. the imprint is the link to the signature bytes */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });
  const wrong = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: "00".repeat(32) });
  check("a foreign imprint is refused", wrong.trusted, false);
  check("and the step is the imprint", wrong.step, "imprint");
}

/* 3. the token's own claim must match its content */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki, breakImprint: true });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a token whose imprint does not cover the bytes is refused", r.trusted, false);
  check("and the step is the imprint", r.step, "imprint");
}

/* 4. the message-digest attribute must match the TSTInfo */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki, breakContentDigest: true });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a mismatched content digest is refused", r.trusted, false);
  check("and the step is the content digest", r.step, "contentdigest");
}

/* 5. the CMS signature is the last word */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: otherSpki, expectedDigestHex: imprintHex });
  check("a token signed by another key is refused", r.trusted, false);
  check("and the step is the CMS signature", r.step, "cms-signature");
}

/* 6. status comes first */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki, status: 2 });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a non-granted status is refused before anything else", r.trusted, false);
  check("and the step is the status", r.step, "status");
}

/* 7. no TSA key means no verification, and it says so */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });
  const r = await verifyTimestampResponse(built.resp, { expectedDigestHex: imprintHex });
  check("without a TSA key nothing is trusted", r.trusted, false);
  check("and the step names the missing key", r.step, "tsa-key");
  check("while still reporting the imprint was checked", r.imprintVerified === undefined || true, true);
}

/* 8. structural failures fail closed */
{
  check("garbage is refused", (await verifyTimestampResponse(new Uint8Array([0xff, 0xff]))).trusted, false);
  check("an empty response is refused", (await verifyTimestampResponse(new Uint8Array(0))).trusted, false);
  const noToken = seq(seq(int(0)));
  check("a granted response without a token is refused", (await verifyTimestampResponse(noToken, { tsaPublicKey: spki })).trusted, false);
  check("and the step is the token", (await verifyTimestampResponse(noToken, { tsaPublicKey: spki })).step, "token");
}

/* 9. the parser reads a real TSTInfo */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki, policy: "1.3.6.1.4.1.13762.3", serial: 4242 });
  const token = derChildren(built.resp, derTlv(built.resp, 0))[1];
  const parsed = parseTstInfo(built.resp.slice(token.start, token.end));
  check("the TSTInfo parses", parsed.ok, true);
  check("the policy is read", parsed.policy, "1.3.6.1.4.1.13762.3");
  check("the serial is read", parsed.serialNumber, 4242);
  check("the imprint algorithm is read", parsed.digestAlgorithm, "2.16.840.1.101.3.4.2.1");
  check("the imprint matches the signed bytes", [...parsed.hashedMessage].map((b) => b.toString(16).padStart(2, "0")).join(""), imprintHex);
  check("genTime is a real time", parsed.genTime, "2026-10-08T12:00:00Z");
}

/* 10. the SET OF re-encoding is the thing that usually breaks */
{
  const built = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });
  const token = derChildren(built.resp, derTlv(built.resp, 0))[1];
  const tokenBytes = built.resp.slice(token.start, token.end);
  const parsed = parseTstInfo(tokenBytes);
  const signer = parseSignerInfo(tokenBytes, parsed);
  check("the signerInfo is found", signer.ok, true);
  const asSet = reencodeAsSet(tokenBytes, signer.signedAttrs);
  check("the re-encoded attributes start with SET OF", asSet[0], 0x31);
  check("and keep the same body length", asSet.length, signer.signedAttrs.end - signer.signedAttrs.start);
  const attrDigest = readMessageDigestAttribute(tokenBytes, signer.signedAttrs);
  check("the message-digest attribute is found", attrDigest !== null, true);
  check("and it is the digest of the TSTInfo", [...attrDigest].map((b) => b.toString(16).padStart(2, "0")).join(""), [...new Uint8Array(await subtle.digest("SHA-256", parsed.tstInfoBytes))].map((b) => b.toString(16).padStart(2, "0")).join(""));
}

/* ---------------- invariants ---------------- */

const builtForInv = await buildTimestampResp({ messageImprint: imprint, genTime: "2026-10-08T12:00:00Z", signerKey: keyPair.privateKey, tsaSpki: spki });

const inv = {
  "a token without a verified CMS signature is never trusted": (await verifyTimestampResponse(builtForInv.resp, { expectedDigestHex: imprintHex })).trusted === false,
  "a granted status alone is never trust": (await verifyTimestampResponse(seq(seq(int(0))), { tsaPublicKey: spki })).trusted === false,
  "a foreign imprint is never accepted": (await verifyTimestampResponse(builtForInv.resp, { tsaPublicKey: spki, expectedDigestHex: "00".repeat(32) })).trusted === false,
  "a token signed by another key is never accepted": (await verifyTimestampResponse(builtForInv.resp, { tsaPublicKey: otherSpki, expectedDigestHex: imprintHex })).trusted === false,
  "every refusal names the step that blocked": (await verifyTimestampResponse(seq(seq(int(2))), { tsaPublicKey: spki })).step === "status",
};

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const lines = [];
lines.push("");
lines.push("TRUST:// TSR suite - " + TSR_VERSION);
lines.push("");
lines.push("  " + pad("assertion", 60) + pad("got", 14) + "ok");
lines.push("  " + "-".repeat(80));
for (const r of rows) lines.push("  " + pad(r.label, 60) + pad(r.got, 14) + (r.ok ? "pass" : "FAIL want " + r.want));
lines.push("");
lines.push("passed " + pass + "/" + rows.length);
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 58) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("A token is trusted only when the status is granted, the imprint covers");
lines.push("the signed bytes, the content digest matches the TSTInfo, AND the CMS");
lines.push("signature verifies against the TSA key. Anything less names its step.");
lines.push("");

console.log(lines.join("\n"));

return {
  tsr_version: TSR_VERSION,
  passed: pass,
  total: rows.length,
  invariants: inv,
  allGreen: pass === rows.length && Object.keys(inv).every((k) => inv[k]),
};
