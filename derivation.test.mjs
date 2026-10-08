/* TRUST:// derivation test suite — the scanner scenario, end to end.
 *
 * Four steps:
 *   1. a camera capture, signed at the source
 *   2. the scanner app straightening, cropping and colour-correcting it
 *   3. an unrelated edit that merely ASSERTS the same ancestry
 *   4. an edit with no derivation link at all
 *
 * Step 3 is the attack the rule exists to stop; step 4 is the case that must
 * not be silently described as "derived".
 *
 * Self-contained: SHA-256 via WebCrypto, no imports. Runs in Node 18+, in a
 * browser, or as a script body in any JS runner.
 */

const SPEC_VERSION = "TRUST-Record/0.2";

async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

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

/* ---- the module, inlined so the suite is a single self-contained file ---- */

function classify(evidence) {
  const list = Array.isArray(evidence) ? evidence : [];
  return {
    attestations: list.filter((e) => e && e.kind === "attestation"),
    assertions: list.filter((e) => e && e.kind === "assertion"),
    claims: list.filter((e) => e && e.kind === "generation_claim"),
  };
}

function createTrustStore() {
  const records = new Map();
  return {
    store(record) {
      if (!record.content_hash) throw new Error("a record needs a content_hash to be resolvable");
      records.set(record.content_hash, record);
      return record;
    },
    get(hash) { return records.get(hash) ?? null; },
    has(hash) { return records.has(hash); },
    size() { return records.size; },
  };
}

function resolveDerivation(subject, store) {
  const parents = Array.isArray(subject?.derived_from) ? subject.derived_from : [];
  if (parents.length === 0) return { linked: false, parents: [], signed_parent: false, note: "no derivation recorded" };
  const resolved = parents.map((hash) => {
    const rec = store?.get(hash) ?? null;
    return { hash, known: Boolean(rec), origin: rec?.origin ?? null, integrity: rec?.integrity ?? null };
  });
  const proven = resolved.filter((r) => r.known && r.origin === "verified");
  return {
    linked: true,
    parents: resolved,
    signed_parent: proven.length > 0,
    note: proven.length > 0 ? "links to a source whose origin was proven" : "links to a source with no proven origin",
  };
}

function pipeline(input, store) {
  const b = classify(input.evidence);
  const origin = b.attestations.some((a) => a.state === "valid")
    ? "verified"
    : (b.attestations.length || b.assertions.length || b.claims.length ? "claimed" : "none");

  const derivation = resolveDerivation(input.subject, store);
  const withHash = b.attestations.filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64);
  const computedHash = input.content_hash ?? null;

  let integrity = "intact";
  let reason = "no content hash attested, so nothing can contradict";
  let resolvable = null;
  if (withHash.length) {
    const matches = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() === computedHash.toLowerCase());
    const others = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() !== computedHash.toLowerCase());
    const broken = withHash.filter((a) => a.state === "invalid" || a.chain === "unavailable" || a.chain === "expired");
    if (matches.length && others.length) { integrity = "broken"; reason = "attestations contradict each other"; resolvable = false; }
    else if (broken.length === withHash.length) { integrity = "broken"; reason = "no attestation resolved to a verified chain"; resolvable = false; }
    else if (matches.length) { integrity = "intact"; reason = "hash matches the attested value"; resolvable = null; }
    else if (derivation.linked) {
      integrity = "modified"; resolvable = true;
      reason = derivation.signed_parent
        ? "bytes differ from the signed source, but a recorded derivation link to a proven-origin source resolves"
        : "bytes differ from the signed source; a derivation link is recorded but its source has no proven origin";
    } else {
      integrity = "modified"; resolvable = false; reason = "hash differs and no derivation is recorded";
    }
  }

  const signing = b.attestations.filter((a) => a.state === "valid" && a.generation && a.generation.kind);
  const generation = signing.length
    ? { value: "attested_by_signer", kinds: [...new Set(signing.map((a) => GENERATION_KINDS[a.generation.kind] ?? a.generation.kind))] }
    : (b.claims.length
      ? { value: "asserted", kinds: [...new Set(b.claims.map((c) => GENERATION_KINDS[c.generation_kind] ?? c.generation_kind ?? "unspecified"))] }
      : { value: "none", kinds: [] });

  const authenticated = b.attestations.some((a) => a.state === "valid" && (a.identity_proof === true || a.identity_proof === "verified"));
  let verdict = GRID[origin + "|" + integrity] || "UNKNOWN";
  if (authenticated && verdict === "VERIFIED") verdict = "AUTHENTICATED";

  return { origin, integrity, generation: generation.value, authenticated, verdict, derivation, reason, resolvable };
}

/* ---- the scenario ---- */

const att = (o) => ({ kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", ...o });
const enc = (s) => new TextEncoder().encode(s);

const H_ORIG = await sha256Hex(enc("original-camera-jpeg-of-charizard-4-102"));
const H_EDIT = await sha256Hex(enc("straightened-cropped-colour-corrected-charizard-4-102"));
const H_ALIEN = await sha256Hex(enc("unrelated-edited-image-with-a-borrowed-marker"));

const store = createTrustStore();
const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (ok) pass++;
  rows.push({ label, got, want, ok });
};

/* 1 — capture: signed at the source. */
const capture = pipeline({
  subject: { kind: "card", id: "card:pokemon:base-set:4/102" },
  evidence: [att({ content_hash: H_ORIG, generation: { kind: "digitalCapture" } })],
  content_hash: H_ORIG,
  issuer: "did:web:example.org",
  checked_at: "2026-10-08T09:00:00Z",
}, store);
store.store({ ...capture, content_hash: H_ORIG });
check("1 capture  origin", capture.origin, "verified");
check("1 capture  integrity", capture.integrity, "intact");
check("1 capture  verdict", capture.verdict, "VERIFIED");
check("1 capture  generation", capture.generation, "attested_by_signer");

/* 2 — the scanner straightens, crops and colour-corrects. New bytes; the old
 * signature no longer covers them; the derivation link resolves. */
const edited = pipeline({
  subject: { kind: "card", id: "card:pokemon:base-set:4/102", derived_from: [H_ORIG] },
  evidence: [att({ content_hash: H_ORIG, generation: { kind: "digitalCapture" } })],
  content_hash: H_EDIT,
  issuer: "did:web:example.org",
  checked_at: "2026-10-08T09:02:00Z",
}, store);
store.store({ ...edited, content_hash: H_EDIT });
check("2 edited   origin unchanged", edited.origin, "verified");
check("2 edited   integrity", edited.integrity, "modified");
check("2 edited   verdict", edited.verdict, "MODIFIED");
check("2 edited   link resolves", edited.derivation.linked, true);
check("2 edited   links to proven source", edited.derivation.signed_parent, true);
check("2 edited   marked resolvable", edited.resolvable, true);

/* 3 — an unrelated edit ASSERTING the same ancestry. Must inherit nothing. */
const borrowed = pipeline({
  subject: { kind: "card", id: "card:pokemon:base-set:4/102", derived_from: [H_ORIG] },
  evidence: [],
  content_hash: H_ALIEN,
  issuer: null,
  checked_at: "2026-10-08T09:05:00Z",
}, store);
check("3 borrowed origin", borrowed.origin, "none");
check("3 borrowed integrity", borrowed.integrity, "intact");
check("3 borrowed verdict", borrowed.verdict, "UNKNOWN");
check("3 borrowed inherits nothing", borrowed.origin === "none", true);

/* 4 — an edit with no link at all stays unresolvable. */
const orphan = pipeline({
  subject: { kind: "card", id: "card:x" },
  evidence: [att({ content_hash: H_ORIG })],
  content_hash: H_EDIT,
  checked_at: "2026-10-08T09:07:00Z",
}, store);
check("4 orphan   no link recorded", orphan.derivation.linked, false);
check("4 orphan   not resolvable", orphan.resolvable, false);

const inv = {
  "derivation moves only integrity": capture.origin === edited.origin,
  "derivation never grants origin": borrowed.origin === "none",
  "unresolvable edit stays MODIFIED": orphan.integrity === "modified" && orphan.resolvable === false,
};

const width = [34, 18, 18];
const lines = [];
lines.push("");
lines.push("TRUST:// derivation suite - Record Format 0.2");
lines.push("");
lines.push("check".padEnd(width[0]) + "got".padEnd(width[1]) + "want".padEnd(width[2]) + "ok");
lines.push("-".repeat(74));
for (const r of rows) {
  lines.push(String(r.label).padEnd(width[0]) + String(r.got).padEnd(width[1]) + String(r.want).padEnd(width[2]) + (r.ok ? "pass" : "FAIL"));
}
lines.push("-".repeat(74));
lines.push(`passed ${pass}/${rows.length}`);
lines.push("");
for (const [name, holds] of Object.entries(inv)) lines.push(`inv  ${name.padEnd(46)} ${holds ? "holds" : "VIOLATED"}`);
lines.push("");
lines.push("A derivation record moves integrity, never origin.");
lines.push("You cannot inherit a provenance you cannot prove.");
lines.push("");

const report = lines.join("\n");
console.log(report);

const results = {
  spec_version: SPEC_VERSION,
  pass,
  total: rows.length,
  invariants: inv,
  allGreen: pass === rows.length && Object.values(inv).every(Boolean),
};
if (typeof globalThis.__report === "function") globalThis.__report(results);
