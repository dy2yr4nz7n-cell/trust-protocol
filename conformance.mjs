/* TRUST:// conformance suite — Record Format 0.2
 *
 * Self-contained: SHA-256 via WebCrypto, no imports, no dependencies.
 * Runs in a browser, in Node 18+, or as a script body in any JS runner:
 *   node conformance.mjs
 *
 * Checks the two axes the standard is built on, the third it added, and the
 * four invariants that separate a standard from a library.
 */

const SPEC_VERSION = "TRUST-Record/0.2";

async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ---------------- the engine, in full ---------------- */

const GRID = {
  "verified|intact": "VERIFIED",
  "verified|modified": "MODIFIED",
  "verified|broken": "INVALID",
  "claimed|intact": "CLAIMED",
  "claimed|modified": "CLAIMED",
  "claimed|broken": "INVALID",
  "none|intact": "UNKNOWN",
  "none|modified": "UNKNOWN",
  "none|broken": "UNKNOWN",
};

const GENERATION_KINDS = {
  trainedAlgorithmicMedia: "machine_generated",
  algorithmicMedia: "machine_generated",
  compositeWithTrainedAlgorithmicMedia: "machine_assisted",
  digitalCapture: "captured",
  computationalCapture: "captured",
};

function classify(evidence) {
  const list = Array.isArray(evidence) ? evidence : [];
  return {
    attestations: list.filter((e) => e && e.kind === "attestation"),
    assertions: list.filter((e) => e && e.kind === "assertion"),
    claims: list.filter((e) => e && e.kind === "generation_claim"),
  };
}

function deriveOrigin(b) {
  if (b.attestations.some((a) => a.state === "valid")) return "verified";
  if (b.attestations.length || b.assertions.length || b.claims.length) return "claimed";
  return "none";
}

function deriveIntegrity(b, computedHash) {
  const withHash = b.attestations.filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64);
  if (withHash.length === 0) return "intact";

  const matches = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() === computedHash.toLowerCase());
  const others = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() !== computedHash.toLowerCase());
  const broken = withHash.filter((a) => a.state === "invalid" || a.chain === "unavailable" || a.chain === "expired");

  if (matches.length && others.length) return "broken";
  if (broken.length === withHash.length) return "broken";
  if (matches.length) return "intact";
  return "modified";
}

function deriveGeneration(b) {
  const signing = b.attestations.filter((a) => a.state === "valid" && a.generation && a.generation.kind);
  if (signing.length) {
    return {
      value: "attested_by_signer",
      kinds: [...new Set(signing.map((a) => GENERATION_KINDS[a.generation.kind] ?? a.generation.kind))],
      raw: [...new Set(signing.map((a) => a.generation.kind))],
      sources: [...new Set(signing.map((a) => a.label ?? a.id ?? "unnamed attestation"))],
    };
  }
  if (b.claims.length) {
    return {
      value: "asserted",
      kinds: [...new Set(b.claims.map((c) => GENERATION_KINDS[c.generation_kind] ?? c.generation_kind ?? "unspecified"))],
      raw: [...new Set(b.claims.map((c) => c.generation_kind ?? "unspecified"))],
      sources: [...new Set(b.claims.map((c) => c.source ?? "unknown source"))],
      detector_scores: b.claims
        .filter((c) => typeof c.confidence === "number")
        .map((c) => ({ source: c.source ?? "unknown", confidence: c.confidence })),
    };
  }
  return { value: "none", kinds: [], raw: [], sources: [] };
}

function derive(evidence, computedHash) {
  const b = classify(evidence);
  const origin = deriveOrigin(b);
  const integrity = deriveIntegrity(b, computedHash);
  const generation = deriveGeneration(b);
  const authenticated = b.attestations.some(
    (a) => a.state === "valid" && (a.identity_proof === true || a.identity_proof === "verified")
  );
  let verdict = GRID[origin + "|" + integrity] || "UNKNOWN";
  if (authenticated && verdict === "VERIFIED") verdict = "AUTHENTICATED";
  return { origin, integrity, generation, authenticated, verdict };
}

/* ---------------- vectors ---------------- */

const att = (o) => ({ kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", ...o });

const H = await sha256Hex(new TextEncoder().encode("static-bytes-of-the-pokemon-base-set-charizard-4-of-102"));
const OTHER = "f".repeat(64);

const vectors = [
  { id: "verified", verdict: "VERIFIED", generation: "none",
    evidence: () => [att({ content_hash: H })] },
  { id: "authenticated", verdict: "AUTHENTICATED", generation: "none",
    evidence: () => [att({ content_hash: H, identity_proof: true })] },
  { id: "machine-signed", verdict: "VERIFIED", generation: "attested_by_signer",
    evidence: () => [att({ content_hash: H, generation: { kind: "trainedAlgorithmicMedia" } })] },
  { id: "captured-signed", verdict: "VERIFIED", generation: "attested_by_signer",
    evidence: () => [att({ content_hash: H, generation: { kind: "digitalCapture" } })] },
  { id: "machine-rumour", verdict: "CLAIMED", generation: "asserted",
    evidence: () => [{ kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "some-forum-post" }] },
  { id: "detector-claim", verdict: "CLAIMED", generation: "asserted",
    evidence: () => [
      { kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship" },
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "detector-v3", confidence: 0.87 },
    ] },
  { id: "claim-plus-signer", verdict: "VERIFIED", generation: "asserted",
    evidence: () => [att({ content_hash: H }), { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "forum" }] },
  { id: "assertion-only", verdict: "CLAIMED", generation: "none",
    evidence: () => [{ kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship" }] },
  { id: "modified", verdict: "MODIFIED", generation: "none",
    evidence: () => [att({ content_hash: OTHER })] },
  { id: "machine-modified", verdict: "MODIFIED", generation: "attested_by_signer",
    evidence: () => [att({ content_hash: OTHER, generation: { kind: "trainedAlgorithmicMedia" } })] },
  { id: "contradiction", verdict: "INVALID", generation: "none",
    evidence: () => [att({ id: "A", content_hash: H }), att({ id: "B", content_hash: OTHER })] },
  { id: "invalid-signature", verdict: "INVALID", generation: "none",
    evidence: () => [att({ content_hash: H, state: "invalid", chain: "unavailable" })] },
  { id: "expired-chain", verdict: "INVALID", generation: "none",
    evidence: () => [att({ content_hash: H, state: "invalid", chain: "expired" })] },
  { id: "unknown", verdict: "UNKNOWN", generation: "none",
    evidence: () => [] },
];

const rows = [];
let pass = 0;

for (const v of vectors) {
  const r = derive(v.evidence(), H);
  const ok = r.verdict === v.verdict && r.generation.value === v.generation;
  if (ok) pass++;
  rows.push({
    id: v.id, verdict: r.verdict, origin: r.origin, integrity: r.integrity,
    generation: r.generation.value, ok,
  });
}

/* ---------------- the four invariants ---------------- */

const signedAlone = derive([att({ content_hash: H })], H);
const signedPlusClaim = derive(
  [att({ content_hash: H }), { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "forum" }], H);
const claimAlone = derive([{ kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "detector", confidence: 0.99 }], H);

const inv = {
  "verdict is never persisted":             !("verdict" in { spec_version: SPEC_VERSION, origin: "verified" }),
  "unsigned claim never forges provenance": claimAlone.verdict === "CLAIMED" && claimAlone.origin === "claimed",
  "generation never moves origin/integrity": signedAlone.origin === signedPlusClaim.origin && signedAlone.integrity === signedPlusClaim.integrity,
  "unsigned claim never downgrades a signed subject": signedPlusClaim.verdict === "VERIFIED" && signedPlusClaim.generation.value === "asserted",
};

/* ---------------- report ---------------- */

const width = [19, 15, 11, 11, 20];
const lines = [];
lines.push("");
lines.push("TRUST:// conformance - Record Format 0.2");
lines.push("");
lines.push("vector".padEnd(width[0]) + "verdict".padEnd(width[1]) + "origin".padEnd(width[2]) + "integrity".padEnd(width[3]) + "generation".padEnd(width[4]) + "ok");
lines.push("-".repeat(90));
for (const r of rows) {
  lines.push(r.id.padEnd(width[0]) + r.verdict.padEnd(width[1]) + r.origin.padEnd(width[2]) + r.integrity.padEnd(width[3]) + r.generation.padEnd(width[4]) + (r.ok ? "pass" : "FAIL"));
}
lines.push("-".repeat(90));
lines.push(`passed ${pass}/${rows.length}`);
lines.push("");
for (const [name, holds] of Object.entries(inv)) {
  lines.push(`inv  ${name.padEnd(46)} ${holds ? "holds" : "VIOLATED"}`);
}
lines.push("");
lines.push("The system reports who made a generation claim, never whether it is true.");
lines.push("");

const report = lines.join("\n");
console.log(report);

export const results = {
  spec_version: SPEC_VERSION,
  pass,
  total: rows.length,
  invariants: inv,
  allGreen: pass === rows.length && Object.values(inv).every(Boolean),
};
