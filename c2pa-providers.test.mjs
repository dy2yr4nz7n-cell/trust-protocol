/* TRUST:// C2PA providers suite — the network layers, and the boundary.
 *
 * WHAT CHANGED IN THIS REVISION
 * -----------------------------
 * This suite used to carry a COPY of c2pa-providers.js inside itself and test
 * that. A mirror proves the logic, not the file that ships — and it can stay
 * green while the product drifts. The providers are now IMPORTED from
 * ./c2pa-providers.js, and the suite ends with process.exitCode instead of a
 * top-level `return` (which is a SyntaxError under node).
 *
 * WHAT THIS PROVES — the SHAPE of the network half:
 *
 *   · the Sig_structure is built correctly (the thing people get wrong)
 *   · a real ES256 signature verifies through WebCrypto
 *   · a tampered payload fails, and a wrong key fails
 *   · an absent transport yields `unknown`, never `verified`
 *   · a revoked certificate fails the chain even when the path builds
 *   · a required revocation check with no source is a failure, not a pass
 *   · an untrusted countersignature is never trusted
 *
 * WebCrypto only. Run: node c2pa-providers.test.mjs   (Node 20+)
 */

import {
  buildSigStructure,
  createCryptoProvider,
  createChainProvider,
  createTimestampProvider,
  createNullTransport,
} from "./c2pa-providers.js";

const PROVIDER_VERSION = "trust/c2pa-providers@0.3";

/* ---------------- assertions ---------------- */

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
const keyPair2 = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
const spki2 = new Uint8Array(await subtle.exportKey("spki", keyPair2.publicKey));

const protectedBytes = new Uint8Array([0xa2, 0x01, 0x26, 0x18, 0x21, 0x81, 0x58, 0x40]);
const payload = new TextEncoder().encode("asset-pixels");
const sigStructure = buildSigStructure(protectedBytes, payload, new Uint8Array(0));
const goodSig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keyPair.privateKey, sigStructure));
const crypto = createCryptoProvider({});

/* 1 — the Sig_structure, which is what COSE actually signs */
{
  const s = buildSigStructure(protectedBytes, payload, new Uint8Array(0));
  check("Sig_structure starts with array(4)", s[0], 0x84);
  check("first element is the text Signature1", new TextDecoder().decode(s.slice(2, 12)), "Signature1");
  const emptySig = buildSigStructure(new Uint8Array(0), new Uint8Array(0), new Uint8Array(0));
  check("an empty protected header encodes as array(4)", emptySig[0], 0x84);
  const aad = buildSigStructure(protectedBytes, payload, new Uint8Array([1, 2]));
  check("an external_aad is included", aad.length > s.length, true);
}

/* 2 — a real signature verifies */
{
  const r = await crypto({ protectedBytes, payload, signature: goodSig, alg: -7, certificates: [spki] });
  check("a valid ES256 signature verifies", r.ok, true);
  check("the reason names the Sig_structure", r.reason.indexOf("Sig_structure") >= 0, true);
}

/* 3 — tampering fails */
{
  const other = new TextEncoder().encode("different-pixels");
  const r = await crypto({ protectedBytes, payload: other, signature: goodSig, alg: -7, certificates: [spki] });
  check("a tampered payload fails", r.ok, false);
}

{
  const otherProt = new Uint8Array([0xa2, 0x01, 0x26, 0x18, 0x21, 0x81, 0x58, 0x41]);
  const r = await crypto({ protectedBytes: otherProt, payload, signature: goodSig, alg: -7, certificates: [spki] });
  check("a tampered protected header fails", r.ok, false);
}

{
  const r = await crypto({ protectedBytes, payload, signature: goodSig, alg: -7, certificates: [spki2] });
  check("the wrong public key fails", r.ok, false);
}

/* 4 — absent inputs fail closed */
{
  const noSig = await crypto({ protectedBytes, payload, signature: new Uint8Array(0), alg: -7, certificates: [spki] });
  check("an empty signature fails", noSig.ok, false);
  const noCert = await crypto({ protectedBytes, payload, signature: goodSig, alg: -7, certificates: [] });
  check("no certificate fails", noCert.ok, false);
  const badAlg = await crypto({ protectedBytes, payload, signature: goodSig, alg: -999, certificates: [spki] });
  check("an unsupported algorithm fails", badAlg.ok, false);
  const notSpki = await crypto({ protectedBytes, payload, signature: goodSig, alg: -7, certificates: [new Uint8Array([0x30, 0x82, 0x01, 0x00])] });
  check("an unimportable certificate fails rather than passing", notSpki.ok, false);
  check("and it says why", notSpki.reason.length > 0, true);
}

/* 5 — the chain provider */
{
  const good = createChainProvider({ transport: {
    async buildPath() { return { ok: true, anchor: "Example Root CA", expired: false }; },
    async revocationStatus() { return { revoked: false }; },
  } });
  const r1 = await good({ certificates: [spki] });
  check("a built path passes", r1.ok, true);
  check("the anchor is reported", r1.anchor, "Example Root CA");

  const expired = createChainProvider({ transport: {
    async buildPath() { return { ok: true, anchor: "Example Root CA", expired: true }; },
    async revocationStatus() { return { revoked: false }; },
  } });
  const r2 = await expired({ certificates: [spki] });
  check("an expired path passes the provider but flags it", r2.ok && r2.expired, true);

  const revoked = createChainProvider({ transport: {
    async buildPath() { return { ok: true, anchor: "Example Root CA", expired: false }; },
    async revocationStatus() { return { revoked: true }; },
  } });
  const r3 = await revoked({ certificates: [spki] });
  check("a revoked certificate fails the chain", r3.ok, false);
  check("and it names revocation", r3.reason.indexOf("revoked") >= 0, true);

  const noPath = createChainProvider({ transport: { async buildPath() { return { ok: false, reason: "unknown anchor" }; } } });
  const r4 = await noPath({ certificates: [spki] });
  check("an unbuildable path fails", r4.ok, false);
  check("and it names the anchor", r4.reason.indexOf("unknown anchor") >= 0, true);

  const throwing = createChainProvider({ transport: { async buildPath() { throw new Error("dns down"); } } });
  const r5 = await throwing({ certificates: [spki] });
  check("a throwing path builder fails", r5.ok, false);
  check("and it carries the error", r5.reason.indexOf("dns down") >= 0, true);

  const absent = createChainProvider({});
  const r6 = await absent({ certificates: [spki] });
  check("no transport is a failure, never a pass", r6.ok, false);

  const strict = createChainProvider({ transport: { async buildPath() { return { ok: true, anchor: "A", expired: false }; } }, requireRevocationCheck: true });
  const r7 = await strict({ certificates: [spki] });
  check("a required revocation check with no source fails", r7.ok, false);
  check("and it says policy required it", r7.reason.indexOf("revocation") >= 0, true);
}

/* 6 — the timestamp provider */
{
  const trusted = createTimestampProvider({ transport: { async verifyTimestamp() { return { trusted: true, at: "2026-10-08T12:00:00Z" }; } } });
  const t1 = await trusted({ signature: goodSig, payload });
  check("a trusted countersignature passes", t1.trusted, true);
  check("and carries the time", t1.at, "2026-10-08T12:00:00Z");

  const untrusted = createTimestampProvider({ transport: { async verifyTimestamp() { return { trusted: false, reason: "unknown TSA" }; } } });
  const t2 = await untrusted({ signature: goodSig, payload });
  check("an untrusted countersignature is not trusted", t2.trusted, false);

  const absentT = createTimestampProvider({});
  const t3 = await absentT({ signature: goodSig, payload });
  check("no timestamp transport means not trusted", t3.trusted, false);
  check("and it says so", t3.reason.indexOf("no timestamp authority") >= 0, true);

  const throwingT = createTimestampProvider({ transport: { async verifyTimestamp() { throw new Error("tsa unreachable"); } } });
  const t4 = await throwingT({ signature: goodSig, payload });
  check("a throwing TSA is not trusted", t4.trusted, false);
  check("and it carries the error", t4.reason.indexOf("tsa unreachable") >= 0, true);
}

/* 7 — the null transport, which must never invent an answer */
{
  const nullT = createNullTransport();
  const n1 = await nullT.buildPath([]);
  const n2 = await nullT.revocationStatus([]);
  const n3 = await nullT.verifyTimestamp({});
  check("the null transport builds no path", n1.ok, false);
  check("the null transport claims no revocation", n2.revoked, false);
  check("the null transport trusts no timestamp", n3.trusted, false);
}

/* ---------------- invariants ---------------- */

const inv = {
  "no provider passes without a transport that answered": (await createChainProvider({})({ certificates: [] })).ok === false,
  "a throwing transport never passes": (await createChainProvider({ transport: { async buildPath() { throw new Error("x"); } } })({ certificates: [] })).ok === false,
  "a signature failure is never a pass": (await crypto({ protectedBytes, payload: new TextEncoder().encode("x"), signature: goodSig, alg: -7, certificates: [spki] })).ok === false,
  "a required revocation check is never skipped": (await createChainProvider({ transport: { async buildPath() { return { ok: true }; } }, requireRevocationCheck: true })({ certificates: [] })).ok === false,
  "an untrusted timestamp is never trusted": (await createTimestampProvider({})({ signature: new Uint8Array(0), payload: new Uint8Array(0) })).trusted === false,
};

/* ---------------- report ---------------- */

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const lines = [];
lines.push("");
lines.push("TRUST:// C2PA providers suite - " + PROVIDER_VERSION);
lines.push("  drives the shipped c2pa-providers.js (imported, not mirrored)");
lines.push("");
lines.push("  " + pad("assertion", 60) + pad("got", 12) + "ok");
lines.push("  " + "-".repeat(78));
for (const r of rows) lines.push("  " + pad(r.label, 60) + pad(r.got, 12) + (r.ok ? "pass" : "FAIL want " + r.want));
lines.push("");
lines.push("passed " + pass + "/" + rows.length);
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 58) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("The network layers are providers: absent or throwing means unknown,");
lines.push("never verified. The Sig_structure is what COSE actually signs.");
lines.push("");

console.log(lines.join("\n"));

/* Exit code, not a top-level return: a `return` outside a function is a
 * SyntaxError under node, which is why this file could not be started. */
process.exitCode = pass === rows.length && Object.keys(inv).every((k) => inv[k]) ? 0 : 1;
