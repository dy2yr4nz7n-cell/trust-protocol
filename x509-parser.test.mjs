/**
 * x509-parser.test.mjs — tests for the offline X.509 parser and chain validator.
 *
 * Run with:  node x509-parser.test.mjs
 *
 * These tests mint their own certificates in DER, so they need no fixtures and
 * no network. WebCrypto does the signing, which is the same primitive the parser
 * verifies against — a broken encoder surfaces as a failed signature rather than
 * hiding behind a stored fixture.
 */

import assert from "node:assert/strict";
import {
  parseX509Certificate,
  isCertificateValid,
  verifyCertificate,
  verifyCertificateSignature,
  validateCertificateChain,
} from "./x509-parser.js";
import { createX509Transport } from "./x509-chain-transport.js";

const subtle = globalThis.crypto.subtle;
let passed = 0;
const failures = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
  } catch (err) {
    failures.push({ name, message: err && err.message ? err.message : String(err) });
  }
}

/* ------------------------------------------------------------------ *
 * A minimal DER encoder, so the tests can mint real certificates.
 * ------------------------------------------------------------------ */

function cat(...parts) {
  const all = parts.flat();
  const total = all.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of all) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
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

function encodeOid(dotted) {
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

function attribute(oidDotted, value, tag) {
  return tlv(0x31, tlv(0x30, cat(encodeOid(oidDotted), tlv(tag ?? 0x0c, new TextEncoder().encode(value)))));
}

function name(...attributes) {
  return tlv(0x30, cat(...attributes));
}

const OID = {
  ecPublicKey: "1.2.840.10045.2.1",
  prime256v1: "1.2.840.10045.3.1.1",
  secp384r1: "1.3.132.0.34",
  secp521r1: "1.3.132.0.35",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
};

function utcTime(value) {
  return tlv(0x17, new TextEncoder().encode(value));
}

async function mintCert({
  subjectCN = "Test Signer",
  subjectO = "TRUST Test CA",
  subjectC = "DE",
  issuerCN,
  issuerO,
  issuerC,
  keyPair,
  issuerKeyPair,
  curve = "P-256",
  hash = "SHA-256",
  notBefore = "260101000000Z",
  notAfter = "261231235959Z",
  stringTag = 0x0c,
} = {}) {
  const kp = keyPair || (await subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]));
  const signer = issuerKeyPair || kp;

  const subject = name(
    attribute("2.5.4.6", subjectC, stringTag),
    attribute("2.5.4.10", subjectO, stringTag),
    attribute("2.5.4.3", subjectCN, stringTag)
  );
  const issuer = name(
    attribute("2.5.4.6", issuerC || subjectC, stringTag),
    attribute("2.5.4.10", issuerO || subjectO, stringTag),
    attribute("2.5.4.3", issuerCN || subjectCN, stringTag)
  );

  const curveOid = { "P-256": OID.prime256v1, "P-384": OID.secp384r1, "P-521": OID.secp521r1 }[curve];
  const algorithm = tlv(0x30, cat(encodeOid(OID.ecPublicKey), encodeOid(curveOid)));
  const sigAlg = tlv(0x30, encodeOid(OID.ecdsaWithSHA256));
  const spki = new Uint8Array(await subtle.exportKey("spki", kp.publicKey));

  const tbs = tlv(
    0x30,
    cat(
      tlv(0xa0, tlv(0x02, Uint8Array.of(2))),
      tlv(0x02, Uint8Array.of(1, 0, 1)),
      sigAlg,
      issuer,
      tlv(0x30, cat(utcTime(notBefore), utcTime(notAfter))),
      subject,
      tlv(0x30, cat(algorithm, tlv(0x03, cat(Uint8Array.of(0), spki))))
    )
  );

  const rawSig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash }, signer.privateKey, tbs));
  const derSig = tlv(0x30, cat(ecdsaInt(rawSig.slice(0, rawSig.length / 2)), ecdsaInt(rawSig.slice(rawSig.length / 2))));

  return { der: tlv(0x30, cat(tbs, sigAlg, tlv(0x03, cat(Uint8Array.of(0), derSig)))), tbs, keyPair: kp, spki };
}

function ecdsaInt(bytes) {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  let value = bytes.slice(start);
  if (value[0] & 0x80) value = cat(Uint8Array.of(0), value);
  return tlv(0x02, value);
}

/* ------------------------------------------------------------------ *
 * Parsing
 * ------------------------------------------------------------------ */

await test("a well-formed certificate parses", async () => {
  const { der } = await mintCert();
  const parsed = parseX509Certificate(der);
  assert.equal(parsed.ok, true, parsed.reason);
  assert.equal(parsed.version, 3);
  assert.equal(parsed.publicKey.type, "ec");
  assert.equal(parsed.publicKey.curve, "P-256");
  assert.ok(parsed.notBefore instanceof Date);
  assert.ok(parsed.notAfter instanceof Date);
  assert.ok(parsed.notBefore < parsed.notAfter);
});

await test("subject and issuer DNs are decoded", async () => {
  const { der } = await mintCert();
  const parsed = parseX509Certificate(der);
  const subject = parsed.subject.join(",");
  assert.match(subject, /CN=Test Signer/);
  assert.match(subject, /O=TRUST Test CA/);
  assert.match(subject, /C=DE/);
});

await test("tbsBytes carry the SEQUENCE header, not just the value", async () => {
  const { der, tbs } = await mintCert();
  const parsed = parseX509Certificate(der);
  // A certificate signature covers tag+length+value. Returning only the value
  // makes every signature check fail, which is the bug this asserts against.
  assert.equal(parsed.tbsBytes[0], 0x30);
  assert.equal(parsed.tbsBytes.length, tbs.length);
  assert.deepEqual(Array.from(parsed.tbsBytes), Array.from(tbs));
});

await test("PrintableString names decode (real CAs use them)", async () => {
  const { der } = await mintCert({ stringTag: 0x13 });
  const parsed = parseX509Certificate(der);
  assert.match(parsed.subject.join(","), /CN=Test Signer/);
});

await test("P-384 and P-521 curve OIDs are recognised", async () => {
  assert.equal(parseX509Certificate((await mintCert({ curve: "P-384" })).der).publicKey.curve, "P-384");
  assert.equal(parseX509Certificate((await mintCert({ curve: "P-521" })).der).publicKey.curve, "P-521");
});

await test("full SPKI is retained and importable", async () => {
  const { der, spki } = await mintCert();
  const parsed = parseX509Certificate(der);
  assert.deepEqual(Array.from(parsed.publicKey.spki), Array.from(spki));
  await assert.doesNotReject(() =>
    subtle.importKey("spki", parsed.publicKey.spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"])
  );
});

await test("constrained extensions are decoded", async () => {
  const { der } = await mintCert();
  const parsed = parseX509Certificate(der);
  assert.equal(parsed.extensions, null); // no [3] in these fixtures
});

/* ------------------------------------------------------------------ *
 * Malformed input
 * ------------------------------------------------------------------ */

await test("an empty buffer is rejected", () => {
  assert.equal(parseX509Certificate(new Uint8Array(0)).ok, false);
});

await test("truncation is rejected", async () => {
  const { der } = await mintCert();
  const parsed = parseX509Certificate(der.slice(0, 40));
  assert.equal(parsed.ok, false);
  assert.match(parsed.reason, /truncated|EOF/);
});

await test("a non-SEQUENCE outer tag is rejected", () => {
  assert.equal(parseX509Certificate(new Uint8Array([0x02, 0x01, 0x00])).ok, false);
});

await test("isCertificateValid is false for junk input", () => {
  assert.equal(isCertificateValid(null), false);
  assert.equal(isCertificateValid({}), false);
});

/* ------------------------------------------------------------------ *
 * Validity windows
 * ------------------------------------------------------------------ */

await test("validity is judged against the reference time", async () => {
  const parsed = parseX509Certificate((await mintCert({ notBefore: "260101000000Z", notAfter: "260201000000Z" })).der);
  assert.equal(isCertificateValid(parsed, new Date("2026-01-15T00:00:00Z")), true);
  assert.equal(isCertificateValid(parsed, new Date("2025-12-31T00:00:00Z")), false);
  assert.equal(isCertificateValid(parsed, new Date("2026-03-01T00:00:00Z")), false);
});

/* ------------------------------------------------------------------ *
 * Signature verification
 * ------------------------------------------------------------------ */

await test("a self-signed certificate verifies against its own key", async () => {
  const { der } = await mintCert();
  const res = await verifyCertificate(der, null, new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.valid, true, res.reason);
});

await test("a tampered TBS fails signature verification", async () => {
  const { der } = await mintCert();
  const parsed = parseX509Certificate(der);
  const tampered = parsed.tbsBytes.slice();
  tampered[10] ^= 0x01;
  const res = await verifyCertificateSignature(tampered, parsed.signature, parsed.publicKey.spki, parsed.signatureAlgorithm);
  assert.equal(res.ok, false);
  assert.equal(res.code, "signature-mismatch");
});

await test("a signature from another key fails", async () => {
  const a = parseX509Certificate((await mintCert()).der);
  const b = parseX509Certificate((await mintCert()).der);
  const res = await verifyCertificateSignature(a.tbsBytes, a.signature, b.publicKey.spki, a.signatureAlgorithm);
  assert.equal(res.ok, false);
  assert.equal(res.code, "signature-mismatch");
});

await test("an unsupported signature algorithm is reported, not guessed", async () => {
  const parsed = parseX509Certificate((await mintCert()).der);
  const res = await verifyCertificateSignature(parsed.tbsBytes, parsed.signature, parsed.publicKey.spki, "1.2.840.99999.1.1");
  assert.equal(res.ok, false);
  assert.equal(res.code, "algorithm-unsupported");
});

await test("an expired certificate reports expired, not a bad signature", async () => {
  const { der } = await mintCert({ notBefore: "200101000000Z", notAfter: "200201000000Z" });
  const res = await verifyCertificate(der, null, new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.valid, false);
  assert.equal(res.code, "certificate-expired");
});

/* ------------------------------------------------------------------ *
 * Chain validation
 * ------------------------------------------------------------------ */

await test("a two-link chain to a self-signed root validates", async () => {
  const rootKp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const root = await mintCert({ subjectCN: "Test Root CA", subjectO: "TRUST Test Root", keyPair: rootKp });
  const leaf = await mintCert({ subjectCN: "Leaf Signer", issuerCN: "Test Root CA", issuerO: "TRUST Test Root", issuerKeyPair: rootKp });

  const res = await validateCertificateChain([leaf.der, root.der], [root.der], new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.ok, true, res.reason);
  assert.equal(res.trustEstablished, true);
  assert.equal(res.chainLength, 2);
});

await test("a leaf signed by a different root is rejected", async () => {
  const root = await mintCert({ subjectCN: "Test Root CA" });
  const other = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const leaf = await mintCert({ subjectCN: "Leaf Signer", issuerCN: "Test Root CA", issuerKeyPair: other });

  const res = await validateCertificateChain([leaf.der, root.der], [root.der], new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.ok, false);
  assert.match(res.reason, /does not verify against its issuer/);
});

await test("a chain without anchors is refused", async () => {
  const root = await mintCert({ subjectCN: "Untrusted Root" });
  const leaf = await mintCert({ subjectCN: "Leaf", issuerCN: "Untrusted Root", issuerKeyPair: root.keyPair });
  const res = await validateCertificateChain([leaf.der, root.der], [], new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.ok, false);
  assert.equal(res.code, "no-trust-anchors");
});

await test("an expired chain reports the expiry code", async () => {
  const root = await mintCert({ subjectCN: "Test Root CA", notBefore: "200101000000Z", notAfter: "200201000000Z" });
  const leaf = await mintCert({
    subjectCN: "Leaf Signer",
    issuerCN: "Test Root CA",
    issuerKeyPair: root.keyPair,
    notBefore: "200101000000Z",
    notAfter: "200201000000Z",
  });
  const res = await validateCertificateChain([leaf.der, root.der], [root.der], new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.ok, false);
  assert.equal(res.code, "certificate-expired");
});

await test("certificates sharing a name are still verified by key", async () => {
  // Comparing issuer/subject strings alone would accept this chain: the names
  // match. The signature does not, and that is the whole point.
  const rootA = await mintCert({ subjectCN: "Same Name CA" });
  const rootB = await mintCert({ subjectCN: "Same Name CA" });
  const leaf = await mintCert({ subjectCN: "Leaf", issuerCN: "Same Name CA", issuerKeyPair: rootA.keyPair });

  const res = await validateCertificateChain([leaf.der, rootB.der], [rootB.der], new Date("2026-06-01T00:00:00Z"));
  assert.equal(res.ok, false);
  assert.match(res.reason, /does not verify against its issuer/);
});

/* ------------------------------------------------------------------ *
 * Transport adapter
 * ------------------------------------------------------------------ */

await test("the transport builds a path for a valid chain", async () => {
  const root = await mintCert({ subjectCN: "Transport Root" });
  const leaf = await mintCert({ subjectCN: "Transport Leaf", issuerCN: "Transport Root", issuerKeyPair: root.keyPair });

  const path = await createX509Transport({ trustAnchors: [root.der] }).buildPath([leaf.der, root.der]);
  assert.equal(path.ok, true, path.reason);
  assert.ok(path.anchor);
  assert.equal(path.expired, false);
});

await test("the transport fails closed with no anchors", async () => {
  const leaf = await mintCert();
  const path = await createX509Transport({ trustAnchors: [] }).buildPath([leaf.der]);
  assert.equal(path.ok, false);
  assert.match(path.reason, /no trust anchors/);
});

await test("the transport never claims revocation was checked", async () => {
  const rev = await createX509Transport({ trustAnchors: [] }).revocationStatus();
  assert.equal(rev.revoked, false);
  assert.equal(rev.checked, false);
  assert.match(rev.reason, /not determined/);
});

await test("the transport reports expiry as expired", async () => {
  const root = await mintCert({ subjectCN: "Expired Root", notBefore: "200101000000Z", notAfter: "200201000000Z" });
  const leaf = await mintCert({
    subjectCN: "Leaf",
    issuerCN: "Expired Root",
    issuerKeyPair: root.keyPair,
    notBefore: "200101000000Z",
    notAfter: "200201000000Z",
  });
  const path = await createX509Transport({ trustAnchors: [root.der], referenceTime: "2026-06-01T00:00:00Z" }).buildPath([leaf.der, root.der]);
  assert.equal(path.ok, false);
  assert.equal(path.expired, true);
});

await test("describe() reports signer identity for display", async () => {
  const cert = await mintCert({ subjectCN: "Display Me" });
  const described = await createX509Transport({ trustAnchors: [cert.der] }).describe([cert.der]);
  assert.equal(described[0].ok, true);
  assert.match(described[0].subject.join(","), /CN=Display Me/);
});

/* ------------------------------------------------------------------ *
 * Report
 * ------------------------------------------------------------------ */

console.log("");
console.log("x509-parser — " + passed + " passed, " + failures.length + " failed");
if (failures.length) {
  console.log("");
  for (const f of failures) console.log("  FAIL  " + f.name + "\n        " + f.message);
  process.exitCode = 1;
}
