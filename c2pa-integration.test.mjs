/* TRUST:// integration suite — drives the SHIPPED c2pa-tsr.js and c2pa-transport.js.
 *
 * The other suites re-implement the code they test. This one does not: it imports
 * the real modules and feeds them real, signed tokens. Run: node c2pa-integration.test.mjs
 * Needs Node 20 or newer (global WebCrypto).
 *
 * WHAT IT CAUGHT (see STATUS.md): createVerifiedTransport never verified
 * anything (step "parse" every time), a token without a digest was reported as
 * trusted, and an embedded certificate was allowed to vouch for its own token.
 */
import { verifyTimestampResponse, spkiFromCertificate } from "./c2pa-tsr.js";
import { createTransport, createVerifiedTransport } from "./c2pa-transport.js";

function reencodeAsSet(bytes, t) { const body = bytes.slice(t.start + 1, t.end); const out = new Uint8Array(1 + body.length); out[0] = 0x31; out.set(body, 1); return out; }
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
async function buildTimestampResp({ messageImprint, genTime, signerKey, tsaSpki, policy = "1.2.3.4.1", serial = 7, status = 0, breakContentDigest = false, breakImprint = false, certDer = null }) {
  const subtle = globalThis.crypto.subtle;

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

  return { resp: seq(statusInfo, token), tstInfo, signature, tsaSpki };
}

const subtle = globalThis.crypto.subtle;
const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  rows.push({ label, got: JSON.stringify(got), want: JSON.stringify(want), ok });
};
async function section(name, fn) {
  try { await fn(); }
  catch (err) { rows.push({ label: name + " (threw: " + (err && err.message || err) + ")", got: "threw", want: "ok", ok: false }); }
}

const bitstr = (b) => tlv(0x03, cat([new Uint8Array([0x00]), b]));
const utc = (s) => tlv(0x17, new TextEncoder().encode(s));
const nameOf = (cn) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));
/* A structurally real X.509 certificate that wraps a real SubjectPublicKeyInfo. */
const makeCert = (spkiDer) => seq(
  seq(ctx0(int(2)), int(1), seq(oid("1.2.840.10045.4.3.2")), nameOf("Test TSA"),
      seq(utc("260101000000Z"), utc("270101000000Z")), nameOf("Test TSA"), spkiDer),
  seq(oid("1.2.840.10045.4.3.2")), bitstr(new Uint8Array([0])));

const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const spki = new Uint8Array(await subtle.exportKey("spki", keyPair.publicKey));
const otherPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const otherSpki = new Uint8Array(await subtle.exportKey("spki", otherPair.publicKey));

const signature = new TextEncoder().encode("cose-signature-bytes");
const imprint = new Uint8Array(await subtle.digest("SHA-256", signature));
const imprintHex = [...imprint].map((b) => b.toString(16).padStart(2, "0")).join("");
const make = (extra = {}) => buildTimestampResp({
  messageImprint: imprint, genTime: "2026-10-08T12:00:00Z",
  signerKey: keyPair.privateKey, tsaSpki: spki, ...extra,
});
const good = await make();

await section("A. the verifier module directly", async () => {
  const r = await verifyTimestampResponse(good.resp, { tsaPublicKey: spki, expectedDigestHex: imprintHex });
  check("A1 the shipped verifier trusts a complete token", r.trusted, true);
  check("A2 and names the step", r.step, "verified");
  const nb = await verifyTimestampResponse(good.resp, { tsaPublicKey: spki });
  check("A3 without a digest to bind to, nothing is trusted", nb.trusted, false);
  check("A4 and the step is the imprint", nb.step, "imprint");
});

await section("B. the shipped verified transport, end to end", async () => {
  const t = createVerifiedTransport({ tsaPublicKey: spki });
  const r = await t.verifyTimestamp({ signature, timestampToken: good.resp });
  check("B1 the verified transport really verifies", r.trusted, true);
  check("B2 and reports the step it established", r.step, "verified");
  const foreign = await t.verifyTimestamp({ signature: new TextEncoder().encode("another signature"), timestampToken: good.resp });
  check("B3 a foreign signature is refused", foreign.trusted, false);
  check("B4 at the imprint", foreign.step, "imprint");
  const unbound = await t.verifyTimestamp({ timestampToken: good.resp });
  check("B5 no signature to bind to is refused", unbound.trusted, false);
  const other = await createVerifiedTransport({ tsaPublicKey: otherSpki }).verifyTimestamp({ signature, timestampToken: good.resp });
  check("B6 a token checked against another key is refused", other.trusted, false);
  check("B7 at the CMS signature", other.step, "cms-signature");
  const nokey = await createVerifiedTransport({}).verifyTimestamp({ signature, timestampToken: good.resp });
  check("B8 without a TSA key nothing is trusted", nokey.trusted, false);
  check("B9 and the step names the missing key", nokey.step, "tsa-key");
});

await section("C. the plain transport without an injected verifier", async () => {
  const r = await createTransport({}).verifyTimestamp({ signature, timestampToken: good.resp });
  check("C1 stays untrusted", r.trusted, false);
  check("C2 and names the step that did not happen", r.step, "tsa-signature");
  const none = await createTransport({}).verifyTimestamp({ signature });
  check("C3 no token is named as such", none.step, "none");
});

await section("D. a certificate inside the token cannot vouch for itself", async () => {
  const cert = makeCert(spki);
  const carried = await make({ certDer: cert });
  const r = await createVerifiedTransport({}).verifyTimestamp({ signature, timestampToken: carried.resp });
  check("D1 an embedded certificate alone never produces trust", r.trusted, false);
  check("D2 the step names the missing trusted key", r.step, "tsa-key");

  /* The attack this closes: anyone can mint a keypair, sign a token and embed
   * the matching certificate. Verifying a token against its own certificate
   * proves nothing about WHO the timestamp authority is. */
  const attackerPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const attackerSpki = new Uint8Array(await subtle.exportKey("spki", attackerPair.publicKey));
  const forged = await buildTimestampResp({
    messageImprint: imprint, genTime: "2026-10-08T12:00:00Z",
    signerKey: attackerPair.privateKey, tsaSpki: attackerSpki, certDer: makeCert(attackerSpki),
  });
  const f = await createVerifiedTransport({}).verifyTimestamp({ signature, timestampToken: forged.resp });
  check("D3 a self-made token with its own certificate is not trusted", f.trusted, false);
  const pinned = await createVerifiedTransport({ tsaPublicKey: spki }).verifyTimestamp({ signature, timestampToken: forged.resp });
  check("D4 and fails against the key the caller actually trusts", pinned.trusted, false);

  const extracted = spkiFromCertificate(cert);
  check("D5 the key can be taken from a certificate the CALLER trusts", extracted ? Array.from(extracted) : null, Array.from(spki));
  const viaCert = await createVerifiedTransport({ tsaPublicKey: extracted }).verifyTimestamp({ signature, timestampToken: carried.resp });
  check("D6 and verifies against that pinned key", viaCert.trusted, true);
  check("D7 a non-certificate yields no key", spkiFromCertificate(new Uint8Array([1, 2, 3])), null);
});

await section("E. refusals from the injected verifier survive the transport", async () => {
  const refusing = createTransport({ verifyToken: async () => ({ trusted: false, step: "contentdigest", reason: "injected" }) });
  const r = await refusing.verifyTimestamp({ signature, timestampToken: good.resp });
  check("E1 a refusal is not turned into trust", r.trusted, false);
  check("E2 and its step survives", r.step, "contentdigest");
});

const vt = createVerifiedTransport({ tsaPublicKey: spki });
const inv = {
  "the shipped verified transport is not a pass-through stub": (await vt.verifyTimestamp({ signature, timestampToken: good.resp })).trusted === true,
  "a foreign signature is never trusted through the shipped transport": (await vt.verifyTimestamp({ signature: new TextEncoder().encode("x"), timestampToken: good.resp })).trusted === false,
  "a token is never trusted without a signature to bind it to": (await vt.verifyTimestamp({ timestampToken: good.resp })).trusted === false,
  "an embedded certificate never vouches for its own token": (await createVerifiedTransport({}).verifyTimestamp({ signature, timestampToken: (await make({ certDer: makeCert(spki) })).resp })).trusted === false,
  "without an injected verifier the plain transport never trusts": (await createTransport({}).verifyTimestamp({ signature, timestampToken: good.resp })).trusted === false,
};

const pad = (s, n) => { s = String(s); while (s.length < n) s += " "; return s; };
const lines = ["", "TRUST:// integration suite - shipped modules", ""];
for (const r of rows) lines.push("  " + pad(r.label, 72) + (r.ok ? "pass" : "FAIL got " + r.got + " want " + r.want));
lines.push("", "passed " + pass + "/" + rows.length, "");
for (const k of Object.keys(inv)) lines.push("inv  " + pad(k, 66) + (inv[k] ? "holds" : "VIOLATED"));
lines.push("");
console.log(lines.join("\n"));
process.exitCode = pass === rows.length && Object.values(inv).every(Boolean) ? 0 : 1;
