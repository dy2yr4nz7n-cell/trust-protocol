/* TRUST:// transport suite — DER parsing, chain building, signature
 * verification, CRL lookup.
 *
 * WHAT CHANGED IN THIS REVISION (Phase 05)
 * ----------------------------------------
 * The fixtures in this suite used to be structurally hollow: `certificate()`
 * wrote `bitstr(new Uint8Array([0x00, 0x01]))` as the signature — two arbitrary
 * bytes with no key pair behind them. That was enough while buildChain() only
 * ordered the chain by name and never checked a signature, which is exactly the
 * gap STATUS.md recorded as "no certificate signature verification".
 *
 * Now that buildChain() PROVES the order, the fixtures must be real. Every
 * certificate here is minted with WebCrypto and signed by its issuer's private
 * key, so a chain that orders also verifies — and a chain that does not verify
 * is refused, which the suite asserts directly.
 *
 * The certificate COUNT and the assertion count both change; the old 37 is not
 * comparable with this revision.
 *
 * Run: node c2pa-transport.test.mjs   (Node 20+)
 */

import { parseCertificate, buildChain, checkCrl, createTransport } from "./c2pa-transport.js";

const subtle = globalThis.crypto.subtle;

/* ---------------- DER writers ---------------- */

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
const seq = (...parts) => tlv(0x30, cat(parts));
const set = (...parts) => tlv(0x31, cat(parts));
const int = (n) => tlv(0x02, new Uint8Array([n]));
const octstr = (b) => tlv(0x04, b instanceof Uint8Array ? b : new Uint8Array(b));
const bitstr = (b) => tlv(0x03, cat([new Uint8Array([0x00]), b instanceof Uint8Array ? b : new Uint8Array(b)]));
const bool = (v) => tlv(0x01, new Uint8Array([v ? 0xff : 0x00]));
const oid = (str) => {
  const parts = str.split(".").map(Number);
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
const utc = (s) => tlv(0x17, new TextEncoder().encode(s));
const name = (cn) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));

/* P-256, because that is the curve the COSE profile uses. */
const EC_ALG = () => seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.1"));
const ECDSA_SHA256 = () => seq(oid("1.2.840.10045.4.3.2"));

/** Convert a WebCrypto IEEE P1363 signature into the DER SEQUENCE X.509 uses. */
function ecdsaDer(raw) {
  const half = raw.length / 2;
  const part = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = cat([new Uint8Array([0]), v]);
    return tlv(0x02, v);
  };
  return seq(part(raw.slice(0, half)), part(raw.slice(half)));
}

/**
 * Mint a real certificate. `issuerKeyPair` signs it; without one it is
 * self-signed. Returns the DER and the key pair, so a chain can be built.
 */
async function mintCertificate({ serial, issuerCn, subjectCn, notBefore, notAfter, ski, aki, isCa, keyPair, issuerKeyPair }) {
  const kp = keyPair || (await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]));
  const signer = issuerKeyPair || kp;
  const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));

  const extensions = [];
  if (ski) extensions.push(seq(oid("2.5.29.14"), octstr(tlv(0x04, ski))));
  if (aki) extensions.push(seq(oid("2.5.29.35"), octstr(seq(tlv(0x80, aki)))));
  if (isCa !== undefined) extensions.push(seq(oid("2.5.29.19"), octstr(seq(bool(isCa)))));
  const extWrapper = extensions.length ? tlv(0xa3, seq(...extensions)) : new Uint8Array(0);

  const tbs = seq(
    tlv(0xa0, int(2)),
    tlv(0x02, new Uint8Array([serial & 0xff])),
    ECDSA_SHA256(),
    name(issuerCn),
    seq(utc(notBefore), utc(notAfter)),
    name(subjectCn),
    spki,
    extWrapper,
  );

  const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, signer.privateKey, tbs));
  return { der: seq(tbs, ECDSA_SHA256(), bitstr(ecdsaDer(raw))), keyPair: kp, tbs };
}

/* ---------------- fixtures ---------------- */

/* Everything from the fixtures onward lives in an async main(), because the
 * certificates must be minted before any assertion can run. */
async function main() {

const now = "2026-10-08T12:00:00Z";

const rootKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const interKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const strangerKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);

const root = (await mintCertificate({
  serial: 0x33, issuerCn: "Example Root CA", subjectCn: "Example Root CA",
  notBefore: "200001000000Z", notAfter: "350101000000Z",
  ski: new Uint8Array([3, 3, 3, 3]), isCa: true, keyPair: rootKp,
})).der;

const intermediate = (await mintCertificate({
  serial: 0x22, issuerCn: "Example Root CA", subjectCn: "Example Intermediate",
  notBefore: "250101000000Z", notAfter: "280101000000Z",
  ski: new Uint8Array([2, 2, 2, 2]), aki: new Uint8Array([3, 3, 3, 3]), isCa: true,
  keyPair: interKp, issuerKeyPair: rootKp,
})).der;

const leaf = (await mintCertificate({
  serial: 0x11, issuerCn: "Example Intermediate", subjectCn: "did:web:example.org",
  notBefore: "250101000000Z", notAfter: "270101000000Z",
  ski: new Uint8Array([1, 1, 1, 1]), aki: new Uint8Array([2, 2, 2, 2]), isCa: false,
  issuerKeyPair: interKp,
})).der;

const strangerRoot = (await mintCertificate({
  serial: 0x44, issuerCn: "Rogue Root", subjectCn: "Rogue Root",
  notBefore: "200001000000Z", notAfter: "350101000000Z",
  ski: new Uint8Array([4, 4, 4, 4]), isCa: true, keyPair: strangerKp,
})).der;

const expiredLeaf = (await mintCertificate({
  serial: 0x55, issuerCn: "Example Intermediate", subjectCn: "old.example.org",
  notBefore: "200101000000Z", notAfter: "210101000000Z",
  ski: new Uint8Array([5, 5, 5, 5]), aki: new Uint8Array([2, 2, 2, 2]), isCa: false,
  issuerKeyPair: interKp,
})).der;

/* The impostor: same names as the honest intermediate, different key. A chain
 * built on it orders perfectly and must still be refused. */
const impostorKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const impostorIntermediate = (await mintCertificate({
  serial: 0x22, issuerCn: "Example Root CA", subjectCn: "Example Intermediate",
  notBefore: "250101000000Z", notAfter: "280101000000Z",
  isCa: true, keyPair: impostorKp, issuerKeyPair: rootKp,
})).der;

function crl(serials) {
  const entries = serials.map((s) => seq(tlv(0x02, new Uint8Array([s])), utc("260101000000Z")));
  const revokedList = entries.length ? seq(...entries) : new Uint8Array(0);
  return seq(
    seq(int(0), ECDSA_SHA256(), name("Example Intermediate"), utc("260101000000Z"), utc("270101000000Z"), revokedList),
    ECDSA_SHA256(),
    bitstr(new Uint8Array([0x00, 0x01])),
  );
}
const crlWithLeaf = crl([0x11]);
const crlWithoutLeaf = crl([0x99]);

/* ---------------- assertions ---------------- */

const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  rows.push({ label, got: JSON.stringify(got), want: JSON.stringify(want), ok });
};

/* 1 — certificate parsing */
{
  const p = parseCertificate(leaf);
  check("a leaf parses", p.ok, true);
  check("the serial is read", p.serial, "11");
  check("notAfter is read as a time", p.notAfter, "2027-01-01T00:00:00Z");
  check("the certificate reports it is not a CA", p.isCa, false);
  check("a root reports it is a CA", parseCertificate(root).isCa, true);
  check("SKI and AKI are read", [p.ski !== null, p.aki !== null], [true, true]);
  check("garbage is refused", parseCertificate(new Uint8Array([1, 2, 3])).ok, false);
  /* New in this revision: the material verification needs. */
  check("the TBS TLV is retained for verification", p.tbsBytes[0], 0x30);
  check("the signature is retained", p.signature.length > 0, true);
  check("the signature algorithm is read", p.signatureAlgorithm, "1.2.840.10045.4.3.2");
  check("the full SPKI is retained", p.spki[0], 0x30);
}

/* 2 — chain building, now proven by signature */
{
  const c1 = await buildChain([leaf, intermediate, root], ["Example Root CA"], now);
  check("a chain is ordered to its root", c1.ok, true);
  check("the anchor is named", c1.anchor, "Example Root CA");
  check("the chain is not expired", c1.expired, false);
  check("the chain length is reported", c1.chainLength, 3);
  check("order of presentation does not matter", (await buildChain([root, leaf, intermediate], ["Example Root CA"], now)).ok, true);

  const off = await buildChain([leaf, intermediate, strangerRoot], ["Example Root CA"], now);
  check("a root off the list is refused", off.ok, false);
  check("and the reason names the list", off.reason.indexOf("trust list") >= 0, true);

  const noList = await buildChain([leaf, intermediate, root], [], now);
  check("no trust list means no anchor claim", [noList.ok, noList.anchor], [true, null]);

  const exp = await buildChain([expiredLeaf, intermediate, root], ["Example Root CA"], now);
  check("an expired chain still verifies", exp.ok, true);
  check("and is flagged as expired", exp.expired, true);

  /* THE FIX. Same names as the honest intermediate, a different key: the order
   * is found, and the signature check is what refuses it. */
  const forged = await buildChain([leaf, impostorIntermediate, root], ["Example Root CA"], now);
  check("an impostor with matching names is refused", forged.ok, false);
  check("and the reason names the signature", forged.reason.indexOf("does not verify against its issuer") >= 0, true);
}

/* 3 — CRL, by value */
{
  check("a revoked serial is found in the CRL", checkCrl(crlWithLeaf, "11").revoked, true);
  check("an absent serial is not reported as revoked", checkCrl(crlWithoutLeaf, "11").revoked, false);
  check("leading zeros do not defeat the match", checkCrl(crlWithLeaf, "0011").revoked, true);
  check("a CRL that does not parse says so", checkCrl(new Uint8Array([1, 2, 3]), "11").reason.indexOf("did not parse") >= 0, true);
}

/* 4 — the http path */
{
  const issuer = parseCertificate(leaf).issuer;
  const crlUrls = { [issuer]: "http://crl.example/ca.crl" };

  const t = createTransport({ http: async () => ({ status: 200, headers: {}, body: crlWithLeaf }), crlUrls });
  check("a fetched CRL revoking the leaf is reported", (await t.revocationStatus([leaf])).revoked, true);

  const t2 = createTransport({ http: async () => ({ status: 200, headers: {}, body: crlWithoutLeaf }), crlUrls });
  const r2 = await t2.revocationStatus([leaf]);
  check("a clean CRL is reported as clean", [r2.revoked, r2.checked], [false, 1]);

  const t3 = createTransport({ crlUrls });
  const r3 = await t3.revocationStatus([leaf]);
  check("no http function means no CRL was fetched", r3.reason.indexOf("no http function") >= 0, true);

  const t4 = createTransport({ http: async () => { throw new Error("network down"); }, crlUrls });
  const r4 = await t4.revocationStatus([leaf]);
  check("a failed fetch is never reported as revoked", r4.revoked, false);
  check("and the failure is named", r4.reason.indexOf("network down") >= 0, true);
}

/* 5 — the transport's buildPath is the proven path */
{
  const t = createTransport({ trustAnchors: ["Example Root CA"], referenceTime: now });
  const path = await t.buildPath([leaf, intermediate, root]);
  check("buildPath proves the chain", path.ok, true);
  check("and names the anchor", path.anchor, "Example Root CA");

  const bad = await createTransport({ trustAnchors: ["Example Root CA"], referenceTime: now }).buildPath([leaf, impostorIntermediate, root]);
  check("buildPath refuses an impostor chain", bad.ok, false);
}

/* 6 — timestamps WITHOUT an injected verifier: the honest no, step named */
{
  const t = createTransport({});
  const none = await t.verifyTimestamp({ signature: new Uint8Array([1]) });
  check("no token means nothing is trusted", none.trusted, false);
  check("and the step says no token was presented", none.step, "none");

  const granted = seq(seq(int(0)), seq(int(0)));
  const g = await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: granted });
  check("a granted response is not trusted without the proof", g.trusted, false);
  check("and the step names the unverified TSA signature", g.step, "tsa-signature");

  const r = await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: seq(seq(int(2))) });
  check("a non-granted status is refused", r.trusted, false);
  check("and the step names the status", r.step, "status");
}

/* 7 — timestamps WITH an injected verifier */
{
  let received = null;
  const t = createTransport({
    verifyToken: async (args) => { received = args; return { trusted: true, at: "2026-10-08T12:00:00Z", step: "verified", reason: "injected" }; },
    tsaPublicKey: new Uint8Array([9, 9, 9]),
  });
  const token = seq(seq(int(0)), seq(int(0)));
  const out = await t.verifyTimestamp({ signature: new Uint8Array([1, 2, 3]), payload: new Uint8Array([7]), timestampToken: token });
  check("the injected verifier is consulted", received !== null, true);
  check("it receives the signature", received && Array.from(received.signature), [1, 2, 3]);
  check("it receives the token", received && received.timestampToken.length > 0, true);
  check("it receives the TSA key", received && Array.from(received.tsaPublicKey), [9, 9, 9]);
  check("its result is passed through unchanged", out.trusted, true);
  check("including the step it established", out.step, "verified");

  const refusing = createTransport({ verifyToken: async () => ({ trusted: false, step: "contentdigest", reason: "injected refusal" }) });
  const no = await refusing.verifyTimestamp({ signature: new Uint8Array([1, 2, 3]), timestampToken: token });
  check("an injected refusal is not turned into trust", no.trusted, false);
  check("and its step survives", no.step, "contentdigest");
}

/* ---------------- invariants ---------------- */

const t = createTransport({});
const inv = {
  "a root off the trust list is never accepted": (await buildChain([leaf, intermediate, strangerRoot], ["Example Root CA"], now)).ok === false,
  "a chain that orders but does not verify is refused": (await buildChain([leaf, impostorIntermediate, root], ["Example Root CA"], now)).ok === false,
  "an expired chain is flagged, not silently passed": (await buildChain([expiredLeaf, intermediate, root], ["Example Root CA"], now)).expired === true,
  "a CRL match is by value, not by position": checkCrl(crlWithLeaf, "0011").revoked === true && checkCrl(crlWithoutLeaf, "11").revoked === false,
  "no http function means no revocation was checked": (await createTransport({}).revocationStatus([leaf])).checked === 0,
  "a timestamp is never trusted without verifying the TSA signature": (await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: seq(seq(int(0))) })).trusted === false,
  "every refusal names the step that blocked": (await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: seq(seq(int(2))) })).step === "status",
};

/* ---------------- report ---------------- */

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const lines = ["", "TRUST:// C2PA transport suite - trust/transport@0.4", "  drives the shipped c2pa-transport.js (imported, not mirrored)", "  fixtures are real: every certificate is signed by its issuer", ""];
lines.push("  " + pad("assertion", 66) + pad("got", 16) + "ok", "  " + "-".repeat(90));
for (const r of rows) lines.push("  " + pad(r.label, 66) + pad(r.got, 16) + (r.ok ? "pass" : "FAIL want " + r.want));
lines.push("", "passed " + pass + "/" + rows.length, "");
for (const k of Object.keys(inv)) lines.push("inv  " + pad(k, 64) + (inv[k] ? "holds" : "VIOLATED"));
lines.push("");
console.log(lines.join("\n"));

process.exitCode = pass === rows.length && Object.values(inv).every(Boolean) ? 0 : 1;
}

main().catch((err) => {
  console.error("suite threw: " + (err && err.message ? err.message : String(err)));
  process.exitCode = 1;
});
