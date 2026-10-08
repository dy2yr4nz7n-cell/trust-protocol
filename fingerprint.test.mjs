/* TRUST:// fingerprint check test suite — the grid must stay untouched.
 *
 * Proves two things at once:
 *
 *   1. The grid is UNCHANGED. Six statuses, the same mapping, the same
 *      behaviour as before the fingerprint existed.
 *
 *   2. The fingerprint check is reported ALONGSIDE the status, and can never
 *      lift it. An unconfirmed signature over bytes that are not the bytes
 *      declared produces status CLAIMED with fingerprint "mismatch" — the
 *      finding is visible without distorting the status.
 *
 * Self-contained: SHA-256 via WebCrypto, no imports. Runs in Node 18+, in a
 * browser, or as a script body in any JS runner.
 */

const SPEC_VERSION = "TRUST-Record/0.2";
const FINGERPRINT_RESULTS = ["match", "mismatch", "multiple", "none"];

async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ---------------- the grid, unchanged ---------------- */

const GRID = {
  "verified|intact": "VERIFIED", "verified|modified": "MODIFIED", "verified|broken": "INVALID",
  "claimed|intact": "CLAIMED", "claimed|modified": "CLAIMED", "claimed|broken": "INVALID",
  "none|intact": "UNKNOWN", "none|modified": "UNKNOWN", "none|broken": "UNKNOWN",
};

function deriveOriginAxes(evidence) {
  const att = evidence.filter((e) => e && e.kind === "attestation");
  const asr = evidence.filter((e) => e && e.kind === "assertion");
  const clm = evidence.filter((e) => e && e.kind === "generation_claim");
  return att.some((a) => a.state === "valid") ? "verified"
    : (att.length || asr.length || clm.length ? "claimed" : "none");
}

function deriveIntegrityAxis(evidence, computedHash) {
  const withHash = evidence
    .filter((e) => e && e.kind === "attestation")
    .filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64);
  if (withHash.length === 0 || !computedHash) return "intact";

  const matches = withHash.filter((a) => a.content_hash.toLowerCase() === computedHash.toLowerCase());
  const others = withHash.filter((a) => a.content_hash.toLowerCase() !== computedHash.toLowerCase());
  if (matches.length && others.length) return "broken";
  if (matches.length) return "intact";
  return "modified";
}

/* ---------------- the fingerprint check, added ---------------- */

function checkFingerprint(evidence, contentHash) {
  const att = (Array.isArray(evidence) ? evidence : []).filter((e) => e && e.kind === "attestation");
  const declared = att
    .filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64)
    .map((a) => ({ id: a.id ?? null, hash: a.content_hash.toLowerCase() }));
  const unique = Array.from(new Set(declared.map((d) => d.hash)));

  if (!contentHash) return { result: "none", declared: unique, detail: "no bytes were presented, so there is nothing to compare" };
  if (declared.length === 0) return { result: "none", declared: [], detail: "no evidence declared a fingerprint, so nothing can be compared" };
  if (unique.length > 1) return { result: "multiple", declared: unique, detail: "the evidence declares " + unique.length + " different fingerprints" };

  const match = unique[0] === contentHash.toLowerCase();
  return {
    result: match ? "match" : "mismatch",
    declared: unique,
    computed: contentHash.toLowerCase(),
    detail: match ? "the declared fingerprint is the fingerprint of these bytes" : "the declared fingerprint belongs to different bytes",
  };
}

function checkDerivation(subject, store) {
  const parents = Array.isArray(subject?.derived_from) ? subject.derived_from : [];
  if (parents.length === 0) return { linked: false, resolved: [], signed_parent: false, detail: "no derivation recorded" };
  const resolved = parents.map((hash) => {
    const rec = (store && typeof store.get === "function" ? store.get(hash) : null) ?? null;
    return { hash, known: Boolean(rec), fingerprint: rec?.fingerprint?.result ?? null, origin: rec?.origin ?? null };
  });
  const proven = resolved.filter((r) => r.known && r.origin === "verified" && r.fingerprint === "match");
  return {
    linked: true, resolved, signed_parent: proven.length > 0,
    detail: proven.length > 0 ? "links to a source whose fingerprint matched and whose origin was proven" : "links to a source with no proven-origin, fingerprint-matching record",
  };
}

function deriveRecord(input, store) {
  const evidence = Array.isArray(input.evidence) ? input.evidence : [];
  const bytesHash = input.content_hash ?? null;

  const origin = deriveOriginAxes(evidence);
  const integrity = deriveIntegrityAxis(evidence, bytesHash);
  const authenticated = evidence.some(
    (e) => e && e.kind === "attestation" && e.state === "valid" && (e.identity_proof === true || e.identity_proof === "verified")
  );

  let verdict = GRID[origin + "|" + integrity] || "UNKNOWN";
  if (authenticated && verdict === "VERIFIED") verdict = "AUTHENTICATED";

  return {
    origin, integrity, authenticated, verdict,
    fingerprint: checkFingerprint(evidence, bytesHash),
    derivation: checkDerivation(input.subject, store),
  };
}

/* ---------------- the case under test ---------------- */

const att = (o) => ({ kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", ...o });
const enc = (s) => new TextEncoder().encode(s);

const H = await sha256Hex(enc("the-bytes-in-hand"));
const OTHER = "f".repeat(64);
const SECOND = "b".repeat(64);

const store = new Map();
store.set(H, { content_hash: H, origin: "verified", fingerprint: { result: "match" } });

const cases = [
  { label: "signiert, Fingerabdruck stimmt", evidence: [att({ content_hash: H })], hash: H, wantVerdict: "VERIFIED", wantFp: "match" },
  { label: "signiert, andere Bytes", evidence: [att({ content_hash: OTHER })], hash: H, wantVerdict: "MODIFIED", wantFp: "mismatch" },
  { label: "kein Verifier, Fingerabdruck stimmt", evidence: [{ kind: "attestation", id: "urn:c2pa:x", content_hash: H, state: "unknown" }], hash: H, wantVerdict: "CLAIMED", wantFp: "match" },
  { label: "kein Verifier, andere Bytes", evidence: [{ kind: "attestation", id: "urn:c2pa:x", content_hash: OTHER, state: "unknown" }], hash: H, wantVerdict: "CLAIMED", wantFp: "mismatch" },
  { label: "zwei Fingerabdrueche widersprechen sich", evidence: [att({ content_hash: H }), att({ id: "urn:c2pa:2", content_hash: SECOND })], hash: H, wantVerdict: "INVALID", wantFp: "multiple" },
  { label: "kein Fingerabdruck deklariert", evidence: [{ kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "detector" }], hash: H, wantVerdict: "CLAIMED", wantFp: "none" },
  { label: "Ableitung auf geprueften Ursprung", evidence: [att({ content_hash: H })], hash: H, subject: { kind: "card", id: "card:x", derived_from: [H] }, wantVerdict: "VERIFIED", wantFp: "match", wantLink: true },
  { label: "Ableitung auf unbekannte Quelle", evidence: [att({ content_hash: H })], hash: H, subject: { kind: "card", id: "card:x", derived_from: [SECOND] }, wantVerdict: "VERIFIED", wantFp: "match", wantLink: false },
  { label: "keine Belege, kein Fingerabdruck", evidence: [], hash: H, wantVerdict: "UNKNOWN", wantFp: "none" },
];

const rows = [];
let pass = 0;
const check = (label, got, want) => { const ok = got === want; if (ok) pass++; rows.push({ label, got, want, ok }); };

for (const c of cases) {
  const subject = c.subject ?? { kind: "url", id: "https://example.org/x" };
  const r = deriveRecord({ subject, evidence: c.evidence, content_hash: c.hash }, store);
  check(c.label + " | status", r.verdict, c.wantVerdict);
  check(c.label + " | fingerprint", r.fingerprint.result, c.wantFp);
  if (c.wantLink !== undefined) check(c.label + " | link", r.derivation.signed_parent, c.wantLink);
}

/* ---------------- the invariants ---------------- */

const mismatchUnconfirmed = deriveRecord({ subject: { kind: "url", id: "x" }, evidence: [{ kind: "attestation", id: "x", content_hash: OTHER, state: "unknown" }], content_hash: H }, store);
const matchUnconfirmed = deriveRecord({ subject: { kind: "url", id: "x" }, evidence: [{ kind: "attestation", id: "x", content_hash: H, state: "unknown" }], content_hash: H }, store);
const contradiction = deriveRecord({ subject: { kind: "url", id: "x" }, evidence: [att({ content_hash: H }), att({ id: "y", content_hash: SECOND })], content_hash: H }, store);

const inv = {
  "the grid is unchanged: nine mappings, same statuses": Object.keys(GRID).length === 9 && matchUnconfirmed.verdict === "CLAIMED",
  "the fingerprint is reported when the status hides the difference": mismatchUnconfirmed.verdict === "CLAIMED" && mismatchUnconfirmed.fingerprint.result === "mismatch",
  "the two fingerprints differ without the statuses differing": mismatchUnconfirmed.verdict === matchUnconfirmed.verdict && mismatchUnconfirmed.fingerprint.result !== matchUnconfirmed.fingerprint.result,
  "the fingerprint never lifts a status": mismatchUnconfirmed.verdict !== "VERIFIED" && mismatchUnconfirmed.verdict !== "MODIFIED",
  "contradicting declarations are broken on the unchanged integrity axis": contradiction.integrity === "broken" && contradiction.verdict === "INVALID",
  "every fingerprint result is one of the four": FINGERPRINT_RESULTS.indexOf(mismatchUnconfirmed.fingerprint.result) >= 0,
};

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }

const lines = [];
lines.push("");
lines.push("TRUST:// fingerprint suite - Record Format 0.2 (grid unchanged)");
lines.push("");
lines.push(pad("case", 42) + pad("status", 12) + pad("fingerprint", 12) + "ok");
lines.push("-".repeat(74));
for (const c of cases) {
  const subject = c.subject ?? { kind: "url", id: "https://example.org/x" };
  const r = deriveRecord({ subject, evidence: c.evidence, content_hash: c.hash }, store);
  const ok = r.verdict === c.wantVerdict && r.fingerprint.result === c.wantFp && (c.wantLink === undefined || r.derivation.signed_parent === c.wantLink);
  lines.push(pad(c.label, 42) + pad(r.verdict, 12) + pad(r.fingerprint.result, 12) + (ok ? "pass" : "FAIL"));
}
lines.push("-".repeat(74));
lines.push("passed " + pass + "/" + rows.length + " assertions");
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 62) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("The grid says what state the record is in.");
lines.push("The fingerprint says whether the content is the content it claims to be.");
lines.push("Different questions. Different lifetimes. Both reported.");
lines.push("");

console.log(lines.join("\n"));

const results = {
  spec_version: SPEC_VERSION,
  pass: pass,
  total: rows.length,
  invariants: inv,
  allGreen: pass === rows.length && Object.keys(inv).every((k) => inv[k]),
};
if (typeof globalThis.__report === "function") globalThis.__report(results);

return results;
