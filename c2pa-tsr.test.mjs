/* TRUST:// TSR suite — the second certification step, measured.
 *
 * WHAT THIS SUITE DOES
 * --------------------
 * It drives the SHIPPED c2pa-tsr.js. Until this revision it carried a copy of
 * the verifier inside itself, which meant it could stay green while the
 * product drifted — and it did: the two fail-open paths fixed in c2pa-tsr.js
 * (a token without a digest reported as trusted, an embedded certificate
 * allowed to vouch for its own token) were present in the copy and invisible
 * here. The verifier is now imported, not mirrored.
 *
 * The fixtures stay: they carry the three lessons of the build — DER INTEGER is
 * signed, GeneralizedTime on the wire has no separators, and signed attributes
 * are signed in IMPLICIT [0] form but verified in SET OF form.
 *
 * Run: node c2pa-tsr.test.mjs   (Node 20+, global WebCrypto)
 */

import { verifyTimestampResponse, parseTstInfo, parseSignerInfo, readMessageDigestAttribute } from "./c2pa-tsr.js";

const TSR_VERSION = "trust/tsr@0.3";

/* ================================================================== *
 * DER writers, for the fixtures only
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
const ctx0 = (b) => tlv(0xa0, b);
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
 *  form with dashes and colons is what a human reads, not what the token says. */
const generalized = (s) => {
  const digits = String(s).replace(/[-:TZ]/g, "").slice(0, 14);
  return tlv(0x18, new TextEncoder().encode(digits + "Z"));
};
const bitstr = (b) => tlv(0x03, cat([new Uint8Array([0x00]), b]));
const utc = (s) => tlv(0x17, new TextEncoder().encode(s));
const nameOf = (cn) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));
/** A structurally real certificate wrapping a real SPKI, so the embedded-
 *  certificate case can be exercised: it must never vouch for its own token. */
const makeCert = (spkiDer) => seq(
  seq(ctx0(int(2)), int(1), seq(oid("1.2.840.10045.4.3.2")), nameOf("Test TSA"),
      seq(utc("260101000000Z"), utc("270101000000Z")), nameOf("Test TSA"), spkiDer),
  seq(oid("1.2.840.10045.4.3.2")), bitstr(new Uint8Array([0])));

/** Build a TimeStampResp carrying a real CMS SignedData over signedAttrs. */
async function buildTimestampResp({ messageImprint, genTime, signerKey, policy = "1.2.3.4.1", serial = 7, status = 0, breakContentDigest = false, breakImprint = false, certDer = null }) {
  const subtle = globalThis.crypto.subtle;

  const imprintToUse = breakImprint ? new Uint8Array(32).fill(0xee) : messageImprint;
  const tstInfo = seq(
    int(1),
    oid(policy),
    seq(seq(oid("2.16.840.1.101.3.4.2.1"), octstr(new Uint8Array(0))), octstr(imprintToUse)),
    int(serial),
    generalized(genTime),
  );

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
  const certSet = certDer ? ctx0(certDer) : set();
  const signedData = seq(
    int(3),
    set(seq(oid("2.16.840.1.101.3.4.2.1"))),
    encap,
    certSet,
    set(signerInfo),
  );

  const token = seq(oid("1.2.840.113549.1.7.2"), ctx0(signedData));
  const statusInfo = seq(int(status));

  return { resp: seq(statusInfo, token), tstInfo, signature };
}

function reencodeAsSet(bytes, t) { const body = bytes.slice(t.start + 1, t.end); const out = new Uint8Array(1 + body.length); out[0] = 0x31; out.set(body, 1); return out; }
function derTlv(bytes, offset) {
  if (offset + 2 > bytes.length) return null;
  let pos = offset;
  const tag = bytes[pos++];
  let n = bytes[pos++];
  if (n & 0x80) { const k = n & 0x7f; if (k === 0 || k > 4) return null; n = 0; for (let i = 0; i < k; i++) n = n * 256 + bytes[pos++]; }
  if (pos + n > bytes.length) return null;
  return { tag, start: offset, valueStart: pos, valueEnd: pos + n, end: pos + n };
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
const make = (extra = {}) => buildTimestampResp({
  messageImprint: imprint, genTime: "2026-10-08T12:00:00Z",
  signerKey: keyPair.privateKey, ...extra,
});

/* 1. a token that closes every link */
{
  const built = await make();
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a complete token is trusted", r.trusted, true);
  check("the step is named as verified", r.step, "verified");
  check("the generation time is carried", r.at, "2026-10-08T12:00:00Z");
  check("the policy is carried", r.policy, "1.2.3.4.1");
  check("the serial is carried", r.serial, 7);
}

/* 2. the imprint is the link to the signature bytes */
{
  const built = await make();
  const wrong = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: "00".repeat(32) });
  check("a foreign imprint is refused", wrong.trusted, false);
  check("and the step is the imprint", wrong.step, "imprint");
}

/* 3. the token's own claim must match its content */
{
  const built = await make({ breakImprint: true });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a token whose imprint does not cover the bytes is refused", r.trusted, false);
  check("and the step is the imprint", r.step, "imprint");
}

/* 4. the message-digest attribute must match the TSTInfo */
{
  const built = await make({ breakContentDigest: true });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a mismatched content digest is refused", r.trusted, false);
  check("and the step is the content digest", r.step, "contentdigest");
}

/* 5. the CMS signature is the last word */
{
  const built = await make();
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: otherSpki, expectedDigestHex: imprintHex });
  check("a token signed by another key is refused", r.trusted, false);
  check("and the step is the CMS signature", r.step, "cms-signature");
}

/* 6. status comes first */
{
  const built = await make({ status: 2 });
  const r = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("a non-granted status is refused before anything else", r.trusted, false);
  check("and the step is the status", r.step, "status");
}

/* 7. no TSA key means no verification, and it says so */
{
  const built = await make();
  const r = await verifyTimestampResponse(built.resp, { expectedDigestHex: imprintHex });
  check("without a TSA key nothing is trusted", r.trusted, false);
  check("and the step names the missing key", r.step, "tsa-key");
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
  const built = await make({ policy: "1.3.6.1.4.1.13762.3", serial: 4242 });
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
  const built = await make();
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

/* 11. the two fail-open paths the integration suite found — held together here */
{
  const built = await make();
  const noDigest = await verifyTimestampResponse(built.resp, { tsaPublicKey: spki });
  check("a token without a digest to bind to is refused", noDigest.trusted, false);
  check("at the imprint", noDigest.step, "imprint");

  const cert = makeCert(spki);
  const carried = await make({ certDer: cert });
  const embedded = await verifyTimestampResponse(carried.resp, { expectedDigestHex: imprintHex });
  check("an embedded certificate never vouches for its own token", embedded.trusted, false);
  check("and the step names the missing trusted key", embedded.step, "tsa-key");
}

/* ---------------- invariants ---------------- */

const builtForInv = await make();

const inv = {
  "a token without a verified CMS signature is never trusted": (await verifyTimestampResponse(builtForInv.resp, { expectedDigestHex: imprintHex })).trusted === false,
  "a granted status alone is never trust": (await verifyTimestampResponse(seq(seq(int(0))), { tsaPublicKey: spki })).trusted === false,
  "a foreign imprint is never accepted": (await verifyTimestampResponse(builtForInv.resp, { tsaPublicKey: spki, expectedDigestHex: "00".repeat(32) })).trusted === false,
  "a token signed by another key is never accepted": (await verifyTimestampResponse(builtForInv.resp, { tsaPublicKey: otherSpki, expectedDigestHex: imprintHex })).trusted === false,
  "every refusal names the step that blocked": (await verifyTimestampResponse(seq(seq(int(2))), { tsaPublicKey: spki })).step === "status",
  "a token is never trusted without a digest to bind it to": (await verifyTimestampResponse(builtForInv.resp, { tsaPublicKey: spki })).trusted === false,
  "an embedded certificate never vouches for its own token": (await verifyTimestampResponse((await make({ certDer: makeCert(spki) })).resp, { expectedDigestHex: imprintHex })).trusted === false,
};

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const lines = [];
lines.push("");
lines.push("TRUST:// TSR suite - " + TSR_VERSION);
lines.push("  drives the shipped c2pa-tsr.js (imported, not mirrored)");
lines.push("");
lines.push("  " + pad("assertion", 62) + pad("got", 16) + "ok");
lines.push("  " + "-".repeat(84));
for (const r of rows) lines.push("  " + pad(r.label, 62) + pad(r.got, 16) + (r.ok ? "pass" : "FAIL want " + r.want));
lines.push("");
lines.push("passed " + pass + "/" + rows.length);
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 60) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("A token is trusted only when the status is granted, the imprint covers");
lines.push("the signed bytes, the content digest matches the TSTInfo, AND the CMS");
lines.push("signature verifies against a key the CALLER supplied. Anything less");
lines.push("names the step that blocked.");
lines.push("");

console.log(lines.join("\n"));

/* Exit code, not a top-level return: a `return` outside a function is a
 * SyntaxError under node, which is why this file could not be started at all
 * before this revision. */
const allGreen = pass === rows.length && Object.keys(inv).every((k) => inv[k]);
process.exitCode = allGreen ? 0 : 1;
