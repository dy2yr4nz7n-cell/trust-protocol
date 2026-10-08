/* TRUST:// reference engine — Record Format 0.2
 * Browser-safe ES module. No Node APIs, no dependencies.
 *
 * DESIGN RULES THAT CARRY THE STANDARD:
 *   1. verdict is DERIVED from origin + integrity at read time and is NEVER
 *      a member of a serialised record.
 *   2. A generation claim NEVER touches origin or integrity. It lives on its
 *      own axis and reports who made it, never whether it is true.
 */

export const SPEC_VERSION = "TRUST-Record/0.2";

/* ------------------------------------------------------------------ *
 * Canonicalisation — the only place a subject identity may be created
 * ------------------------------------------------------------------ */

/** Lowercase scheme+host, strip default port, drop fragment, sort query. */
export function canonicalSubjectUrl(raw) {
  const u = new URL(raw);
  u.hash = "";
  if ((u.protocol === "https:" && u.port === "443") || (u.protocol === "http:" && u.port === "80")) u.port = "";
  const pairs = [...u.searchParams.entries()].sort((a, b) =>
    a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : (a[0] < b[0] ? -1 : 1));
  u.search = "";
  for (const [k, v] of pairs) u.searchParams.append(k, v);
  let out = u.toString();
  if (out.endsWith("?")) out = out.slice(0, -1);
  return out;
}

export async function hashBytes(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function hashString(str) {
  return hashBytes(new TextEncoder().encode(str));
}

/* ------------------------------------------------------------------ *
 * Evidence kinds (0.2)
 * ------------------------------------------------------------------ *
 * attestation       a signature binding subject_id to content_hash.
 *                     state:  invalid | valid | unknown
 *                     chain:  intact | expired | unavailable
 *                     generation (optional): { kind } — a generation claim
 *                     carried INSIDE the signed payload. This is what makes
 *                     it attested_by_signer rather than asserted.
 *
 * assertion         a provenance claim with no cryptographic binding.
 * generation_claim  an authorship claim with no cryptographic binding.
 *                     generation_kind: a C2PA digitalSourceType string
 *                     source: who says so
 *                     confidence: optional detector score — reported, never
 *                     promoted to a measurement.
 * absence           no evidence was submitted at all.
 */

const GENERATION_KINDS = {
  trainedAlgorithmicMedia: "machine_generated",
  algorithmicMedia: "machine_generated",
  compositeWithTrainedAlgorithmicMedia: "machine_assisted",
  digitalCapture: "captured",
  computationalCapture: "captured",
};

function classifyEvidence(evidence) {
  const list = Array.isArray(evidence) ? evidence : [];
  return {
    list,
    attestations: list.filter((e) => e && e.kind === "attestation"),
    assertions: list.filter((e) => e && e.kind === "assertion"),
    claims: list.filter((e) => e && e.kind === "generation_claim"),
    absences: list.filter((e) => e && e.kind === "absence"),
  };
}

/* ------------------------------------------------------------------ *
 * Axis 1 — origin: can the binding be proven at all?
 * ------------------------------------------------------------------ */

function deriveOrigin(ev) {
  const valid = ev.attestations.filter((a) => a.state === "valid");
  if (valid.length > 0) return { value: "verified", basis: valid.map((a) => a.label ?? a.id ?? "attestation") };
  if (ev.attestations.length > 0 || ev.assertions.length > 0 || ev.claims.length > 0)
    return { value: "claimed", basis: ["a claim was presented, but nothing proves it"] };
  return { value: "none", basis: ["no evidence submitted"] };
}

/* ------------------------------------------------------------------ *
 * Axis 2 — integrity: do the bytes still match what was signed?
 * ------------------------------------------------------------------ */

function deriveIntegrity(ev, computedHash) {
  const withHash = ev.attestations.filter((a) => typeof a.content_hash === "string" && a.content_hash.length > 0);
  if (withHash.length === 0)
    return { value: "intact", basis: ["no content hash was attested, so nothing can contradict"] };

  const matches = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() === computedHash.toLowerCase());
  const others = withHash.filter((a) => !computedHash || a.content_hash.toLowerCase() !== computedHash.toLowerCase());
  const broken = withHash.filter((a) => a.state === "invalid" || a.chain === "unavailable" || a.chain === "expired");

  if (matches.length > 0 && others.length > 0)
    return { value: "broken", basis: ["attestations contradict each other about the same subject"] };
  if (broken.length === withHash.length)
    return { value: "broken", basis: ["every attestation failed to resolve to a verified chain"] };
  if (matches.length > 0)
    return { value: "intact", basis: ["attested hash matches the bytes presented"] };
  return { value: "modified", basis: ["attested hash does not match the bytes presented"] };
}

/* ------------------------------------------------------------------ *
 * Axis 3 (0.2) — generation: what was claimed about how it was made?
 * ------------------------------------------------------------------ *
 * attested_by_signer  the claim sat inside a valid attestation. Signed and
 *                     non-repudiable — but still a claim about authorship.
 * asserted            the claim stands alone. Anyone can add one.
 * none                nothing was claimed. NOT "made by a human".
 */

export function deriveGeneration(evidence) {
  const ev = classifyEvidence(evidence);
  const signing = ev.attestations.filter((a) => a.state === "valid" && a.generation && a.generation.kind);
  const declared = signing.map((a) => a.generation);

  if (declared.length > 0) {
    return {
      value: "attested_by_signer",
      kinds: [...new Set(declared.map((g) => GENERATION_KINDS[g.kind] ?? g.kind))],
      raw: [...new Set(declared.map((g) => g.kind))],
      sources: [...new Set(signing.map((a) => a.label ?? a.id ?? "unnamed attestation"))],
      provenance: "Declared inside a valid attestation. Signed and non-repudiable, but still a claim about authorship.",
    };
  }

  if (ev.claims.length > 0) {
    return {
      value: "asserted",
      kinds: [...new Set(ev.claims.map((c) => GENERATION_KINDS[c.generation_kind] ?? c.generation_kind ?? "unspecified"))],
      raw: [...new Set(ev.claims.map((c) => c.generation_kind ?? "unspecified"))],
      sources: [...new Set(ev.claims.map((c) => c.source ?? "unknown source"))],
      detector_scores: ev.claims
        .filter((c) => typeof c.confidence === "number")
        .map((c) => ({ source: c.source ?? "unknown", confidence: c.confidence })),
      provenance: "Unsigned claim. Anyone can add one, so it weighs no more than the source it names.",
    };
  }

  return {
    value: "none",
    kinds: [], raw: [], sources: [],
    provenance: "Nothing was claimed. This does NOT mean the content is human-made.",
  };
}

/* ------------------------------------------------------------------ *
 * verdict — DERIVED, never serialised
 * ------------------------------------------------------------------ *
 *              verified          claimed        none
 *   intact     VERIFIED          CLAIMED        UNKNOWN
 *   modified   MODIFIED          CLAIMED        UNKNOWN
 *   broken     INVALID           INVALID        UNKNOWN
 *
 * MODIFIED is reported as a STATE, not a warning: a legitimate edit after
 * signing produces exactly this record.
 * AUTHENTICATED is VERIFIED plus a separate identity proof — identity is
 * orthogonal to the grid, so it is a flag, not a fifth origin value.
 */

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

const WHY = {
  VERIFIED: "A valid cryptographic binding was presented and the content is unchanged.",
  AUTHENTICATED: "A valid binding was presented and the identity behind it was independently confirmed.",
  CLAIMED: "A provenance claim was presented, but nothing proves it.",
  MODIFIED: "The origin is proven, but the content changed after it was signed.",
  INVALID: "The signature, the hash or the chain is broken.",
  UNKNOWN: "No verifiable origin was found. This is a measurement, not a suspicion.",
};

export function isAuthenticated(evidence) {
  return (Array.isArray(evidence) ? evidence : []).some(
    (e) => e && e.kind === "attestation" && e.state === "valid" &&
      (e.identity_proof === true || e.identity_proof === "verified")
  );
}

export function deriveRecord(input) {
  const ev = classifyEvidence(input.evidence);
  const computedHash = input.content_hash ?? null;
  const origin = deriveOrigin(ev);
  const integrity = deriveIntegrity(ev, computedHash);
  const generation = deriveGeneration(input.evidence);
  const authenticated = isAuthenticated(input.evidence);

  let status = GRID[`${origin.value}|${integrity.value}`] ?? "UNKNOWN";
  if (authenticated && status === "VERIFIED") status = "AUTHENTICATED";

  const record = {
    spec_version: SPEC_VERSION,
    subject: {
      kind: input.subject?.kind ?? "url",
      id: input.subject?.id ?? "",
    },
    origin: origin.value,
    integrity: integrity.value,
    authenticated,
    generation: generation.value,
    evidence: ev.list.map((e) => {
      const out = { kind: e.kind };
      if (e.id) out.id = e.id;
      if (e.label) out.label = e.label;
      if (e.kind === "attestation") {
        out.state = e.state ?? "unknown";
        out.chain = e.chain ?? "unavailable";
        if (e.content_hash) out.content_hash = e.content_hash;
        if (e.generation) out.generation = e.generation;
      }
      if (e.kind === "generation_claim") {
        if (e.generation_kind) out.generation_kind = e.generation_kind;
        if (e.source) out.source = e.source;
        if (typeof e.confidence === "number") out.confidence = e.confidence;
      }
      if (e.issued_at) out.issued_at = e.issued_at;
      return out;
    }),
    issuer: input.issuer ?? null,
    checked_at: input.checked_at ?? new Date().toISOString(),
  };
  if (computedHash) record.content_hash = computedHash;

  return {
    record,
    derivation: {
      status,
      why: WHY[status],
      origin_basis: origin.basis,
      integrity_basis: integrity.basis,
      generation_basis: generation.provenance,
      generation_detail: generation,
      authenticated_basis: authenticated
        ? "an identity proof accompanied a valid attestation"
        : "no separate identity proof",
      provenance: `verdict=${status} derived from origin=${origin.value} + integrity=${integrity.value}` +
        `${authenticated ? " + authenticated" : ""}. generation=${generation.value} is reported alongside and never affects the verdict.`,
    },
  };
}

/* ------------------------------------------------------------------ *
 * Front door — the only export an application needs
 * ------------------------------------------------------------------ */

export async function check(input) {
  const out = deriveRecord(input);
  out.record.verdict = { status: out.derivation.status, spec_version: SPEC_VERSION };
  return out;
}

/* Serialisation MUST drop verdict — it is a view, not a fact. */
export function recordJson(record) {
  const { verdict, ...persisted } = record;
  return JSON.stringify(persisted, null, 2);
}

/* ------------------------------------------------------------------ *
 * Structural C2PA reader — box structure only.
 * Signature and certificate-chain verification needs a trust list, chain
 * building and a timestamp authority, i.e. a network. Out of scope here.
 * ------------------------------------------------------------------ */

const JUMBF_PREFIX = [0x4a, 0x55, 0x4d, 0x42, 0x46]; // "JUMBF"

function readBoxAt(bytes, off, end) {
  if (off + 8 > end) return null;
  let len = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
  const type = String.fromCharCode(bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]);
  let header = 8;
  if (len === 1) {
    if (off + 16 > end) return null;
    len = 0;
    for (let i = 0; i < 8; i++) len = len * 256 + bytes[off + 8 + i];
    header = 16;
  } else if (len === 0) {
    len = end - off;
  }
  if (len < header) return null;
  return { type, len, header, start: off, end: Math.min(off + len, end), body: off + header };
}

export function readManifestStructure(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!(u8[0] === 0xff && u8[1] === 0xd8)) return { found: false, reason: "not a JPEG container", boxes: [] };

  let off = 2;
  let jumbfStart = -1;
  while (off + 4 < u8.length) {
    if (u8[off] !== 0xff) { off++; continue; }
    const marker = u8[off + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { off += 2; continue; }
    if (marker === 0xda) break;
    const segLen = (u8[off + 2] << 8) | u8[off + 3];
    if (marker === 0xeb && segLen > 8) {
      const p = off + 4;
      let match = true;
      for (let i = 0; i < JUMBF_PREFIX.length; i++) if (u8[p + i] !== JUMBF_PREFIX[i]) { match = false; break; }
      if (match) { jumbfStart = p; break; }
    }
    off += 2 + segLen;
  }
  if (jumbfStart < 0) return { found: false, reason: "no APP11/JUMBF segment found", boxes: [] };

  const limit = Math.min(u8.length, jumbfStart + 4 * 1024 * 1024);
  const boxes = [];
  const walk = (start, end, depth) => {
    let o = start;
    let guard = 0;
    while (o + 8 <= end && guard++ < 4096) {
      const box = readBoxAt(u8, o, end);
      if (!box || box.end <= o) break;
      boxes.push({ depth, type: box.type, size: box.end - o });
      if (box.type === "jumb") walk(box.body, box.end, depth + 1);
      o = box.end;
    }
  };
  const root = readBoxAt(u8, jumbfStart, limit);
  if (root && root.type === "jumbf") walk(jumbfStart, root.end, 0);

  return {
    found: true,
    container: "JPEG/APP11",
    root_type: root?.type ?? null,
    boxes,
    note: "Structure only. Signature and chain verification need a trust list and are out of scope for this prototype.",
  };
}

export function bytesFromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ *
 * Test vectors — one per status, plus the generation axis
 * ------------------------------------------------------------------ */

export const PRESETS = {
  verified: {
    label: "Signierte Datei, unveraendert — VERIFIED",
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", issued_at: "2026-09-30T08:12:00Z" },
    ],
  },
  authenticated: {
    label: "Zusaetzlicher Identitaetsnachweis — AUTHENTICATED",
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", identity_proof: true, issued_at: "2026-09-30T08:12:00Z" },
    ],
  },
  machineSigned: {
    label: "Erzeugung signiert ausgewiesen — VERIFIED, attested_by_signer",
    subject: { kind: "url", id: "https://example.org/gallery/hero-image-77" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:aa10", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", generation: { kind: "trainedAlgorithmicMedia" }, issued_at: "2026-10-02T09:00:00Z" },
    ],
  },
  capturedSigned: {
    label: "Kamera-Aufnahme signiert — VERIFIED, attested_by_signer",
    subject: { kind: "url", id: "https://example.org/press/photo-1180" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:bb21", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", generation: { kind: "digitalCapture" }, issued_at: "2026-10-02T09:00:00Z" },
    ],
  },
  machineRumour: {
    label: "Lose KI-Behauptung ohne Signatur — CLAIMED, asserted",
    subject: { kind: "url", id: "https://example.org/feed/post-9001" },
    issuer: null,
    evidence: [
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "some-forum-post", issued_at: "2026-10-05T14:22:00Z" },
    ],
  },
  detectorClaim: {
    label: "Detektor-Ergebnis als Behauptung — CLAIMED, asserted",
    subject: { kind: "url", id: "https://example.org/news/photo-4711" },
    issuer: null,
    evidence: [
      { kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship", issued_at: "2026-10-01T10:00:00Z" },
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "detector-v3", confidence: 0.87, issued_at: "2026-10-06T08:00:00Z" },
    ],
  },
  claimed: {
    label: "Behauptete Herkunft ohne Bindung — CLAIMED",
    subject: { kind: "url", id: "https://example.org/news/photo-4711" },
    issuer: null,
    evidence: [
      { kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship", issued_at: "2026-10-01T10:00:00Z" },
    ],
  },
  modified: {
    label: "Inhalt nach Signatur veraendert — MODIFIED",
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<ANDERER HASH>", issued_at: "2026-09-30T08:12:00Z" },
    ],
  },
  invalid: {
    label: "Gebrochene Signatur oder Kette — INVALID",
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:unknown.example",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:b0a1", label: "C2PA manifest", state: "invalid", chain: "unavailable", content_hash: "<BERECHNET>", issued_at: "2026-09-28T19:44:00Z" },
    ],
  },
  contradiction: {
    label: "Zwei widersprechende Belege — INVALID",
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest A", state: "valid", chain: "intact", content_hash: "<BERECHNET>", issued_at: "2026-09-30T08:12:00Z" },
      { kind: "attestation", id: "urn:c2pa:aa11", label: "C2PA manifest B", state: "valid", chain: "intact", content_hash: "<ANDERER HASH>", issued_at: "2026-09-29T11:03:00Z" },
    ],
  },
  unknown: {
    label: "Kein Beleg vorgelegt — UNKNOWN",
    subject: { kind: "url", id: "https://example.org/unknown/asset-99" },
    issuer: null,
    evidence: [],
  },
};
