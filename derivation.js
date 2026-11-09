/* TRUST:// derivation pipeline — Record Format 0.2
 *
 * The idea pulled in from the card-scanner project (Grade-Check Vault):
 *
 *   A scanned card image is not the photograph. Between capture and display sit
 *   straightening, cropping, colour correction and rescaling. Most records in
 *   the real world are like this — the thing being checked is an EDITED
 *   derivative of something that was signed.
 *
 *   A naive verifier reads that as a problem and shows MODIFIED, which is true
 *   about the bytes and useless as an answer: it describes a transform as if it
 *   were a tampering.
 *
 * TRUST:// handles it with one extra field on the subject:
 *
 *   subject.derived_from : [ "<sha256 hex>", ... ]
 *
 * A record may sit at integrity `modified` while a derivation link ties the
 * current hash back to the signed source. That link is what turns MODIFIED from
 * a dead end into a resolvable state.
 *
 * THE INVARIANT THAT KEEPS IT HONEST: a derivation record moves ONLY
 * `integrity`. It can NEVER move `origin`. You cannot inherit a provenance you
 * cannot prove — deriving from a signed image does not make YOU the signer.
 *
 * Self-contained: SHA-256 via WebCrypto. Runs in Node 18+, in a browser, or as
 * a script body in any JS runner.
 */

export const SPEC_VERSION = "TRUST-Record/0.2";

export const MAX_DERIVATION_DEPTH = 32;

export async function sha256Hex(bytes) {
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

/* ------------------------------------------------------------------ *
 * Trust store — a verifier's own memory of records it has emitted.
 * In production this is a database; here a Map is enough to prove the
 * linking works and to keep the module free of dependencies.
 * ------------------------------------------------------------------ */
export function createTrustStore() {
  const records = new Map();
  return {
    store(record) {
      if (!record.content_hash) throw new Error("a record needs a content_hash to be resolvable");
      records.set(record.content_hash, record);
      return record;
    },
    get(hash) {
      return records.get(hash) ?? null;
    },
    has(hash) {
      return records.has(hash);
    },
    size() {
      return records.size;
    },
  };
}

function isSha256Hex(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/i.test(value);
}

/* Resolve `subject.derived_from` against a verifier's own records.
 *
 * A parent counts as proven only when its stored record has origin
 * "verified". The traversal is bounded and acyclic: a hash may occur only
 * once on a lineage path, and a chain may not exceed MAX_DERIVATION_DEPTH
 * records. A cycle or excessive depth is a validation failure, not a
 * provenance inheritance.
 */
export function resolveDerivation(subject, store, options = {}) {
  const maxDepth = Number.isInteger(options.maxDepth) && options.maxDepth > 0
    ? options.maxDepth
    : MAX_DERIVATION_DEPTH;

  const rawParents = Array.isArray(subject?.derived_from) ? subject.derived_from : [];
  if (rawParents.length === 0) {
    return {
      linked: false,
      parents: [],
      signed_parent: false,
      cyclic: false,
      tooDeep: false,
      resolvable: null,
      note: "no derivation recorded",
    };
  }

  const rootHash = typeof subject?.content_hash === "string" ? subject.content_hash.toLowerCase() : null;
  const visited = new Set();
  if (rootHash) visited.add(rootHash);

  const parents = [];
  let cyclic = false;
  let tooDeep = false;

  const visit = (hash, depth) => {
    if (!isSha256Hex(hash)) {
      parents.push({ hash, known: false, origin: null, integrity: null, verdict: null, cycle: false, depth });
      return;
    }

    const key = hash.toLowerCase();
    if (visited.has(key)) {
      cyclic = true;
      parents.push({ hash: key, known: false, origin: null, integrity: null, verdict: null, cycle: true, depth });
      return;
    }

    if (depth > maxDepth) {
      tooDeep = true;
      parents.push({ hash: key, known: false, origin: null, integrity: null, verdict: null, cycle: false, depth });
      return;
    }

    visited.add(key);
    const record = store?.get(key) ?? null;
    parents.push({
      hash: key,
      known: Boolean(record),
      origin: record?.origin ?? null,
      integrity: record?.integrity ?? null,
      verdict: record?.verdict ?? null,
      cycle: false,
      depth,
    });

    const nextParents = Array.isArray(record?.subject?.derived_from) ? record.subject.derived_from : [];
    for (const parent of nextParents) visit(parent, depth + 1);
  };

  for (const parent of rawParents) visit(parent, 1);

  const validParents = parents.filter((parent) => isSha256Hex(parent.hash) && !parent.cycle);
  const proven = validParents.filter((parent) => parent.known && parent.origin === "verified");
  const resolvable = !cyclic && !tooDeep && proven.length > 0;

  let note;
  if (cyclic) note = "derivation chain contains a cycle";
  else if (tooDeep) note = `derivation chain exceeds the maximum depth of ${maxDepth}`;
  else if (proven.length > 0) note = "links to a source whose origin was proven";
  else note = "links to a source with no proven origin";

  return {
    linked: true,
    parents,
    signed_parent: proven.length > 0,
    cyclic,
    tooDeep,
    resolvable,
    note,
  };
}

/* ------------------------------------------------------------------ *
 * Axes 1 and 2 — origin and integrity, with derivation resolution
 * ------------------------------------------------------------------ */
function classify(evidence) {
  const list = Array.isArray(evidence) ? evidence : [];
  return {
    attestations: list.filter((e) => e && e.kind === "attestation"),
    assertions: list.filter((e) => e && e.kind === "assertion"),
    claims: list.filter((e) => e && e.kind === "generation_claim"),
  };
}

export function deriveOriginAxes(evidence) {
  const b = classify(evidence);
  if (b.attestations.some((a) => a.state === "valid")) return "verified";
  if (b.attestations.length || b.assertions.length || b.claims.length) return "claimed";
  return "none";
}

export function deriveIntegrityAxis(evidence, computedHash, subject, store) {
  const b = classify(evidence);
  const derivation = resolveDerivation(subject, store);
  const withHash = b.attestations.filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64);

  if (withHash.length === 0) {
    return {
      value: "intact",
      derivation,
      reason: "no content hash attested, so nothing can contradict",
      resolvable: null,
    };
  }

  const matches = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() === computedHash.toLowerCase());
  const others = withHash.filter((a) => computedHash && a.content_hash.toLowerCase() !== computedHash.toLowerCase());
  const broken = withHash.filter((a) => a.state === "invalid" || a.chain === "unavailable" || a.chain === "expired");

  if (matches.length && others.length) {
    return {
      value: "broken",
      derivation,
      reason: "attestations contradict each other",
      resolvable: false,
    };
  }

  if (broken.length === withHash.length) {
    return {
      value: "broken",
      derivation,
      reason: "no attestation resolved to a verified chain",
      resolvable: false,
    };
  }

  if (matches.length) {
    return {
      value: "intact",
      derivation,
      reason: "hash matches the attested value",
      resolvable: null,
    };
  }

  /* The hash does not match. Only now does derivation matter: a declared,
   * acyclic and bounded lineage is what separates a derived asset from an
   * unexplained modification. */
  if (derivation.cyclic) {
    return {
      value: "modified",
      derivation,
      resolvable: false,
      reason: "derivation chain contains a cycle and cannot establish a lineage",
    };
  }

  if (derivation.tooDeep) {
    return {
      value: "modified",
      derivation,
      resolvable: false,
      reason: `derivation chain exceeds the maximum depth of ${MAX_DERIVATION_DEPTH}`,
    };
  }

  if (derivation.linked) {
    return {
      value: "modified",
      derivation,
      resolvable: derivation.resolvable,
      reason: derivation.signed_parent
        ? "bytes differ from the signed source, but a recorded derivation link to a proven-origin source resolves"
        : "bytes differ from the signed source; a derivation link is recorded but its source has no proven origin",
    };
  }

  return {
    value: "modified",
    derivation,
    resolvable: false,
    reason: "hash differs and no derivation is recorded",
  };
}

/* ------------------------------------------------------------------ *
 * Axis 3 — generation (0.2)
 * ------------------------------------------------------------------ */
const GENERATION_KINDS = {
  trainedAlgorithmicMedia: "machine_generated",
  algorithmicMedia: "machine_generated",
  compositeWithTrainedAlgorithmicMedia: "machine_assisted",
  digitalCapture: "captured",
  computationalCapture: "captured",
};

export function deriveGenerationAxis(evidence) {
  const b = classify(evidence);
  const signing = b.attestations.filter((a) => a.state === "valid" && a.generation && a.generation.kind);
  if (signing.length) {
    return {
      value: "attested_by_signer",
      kinds: [...new Set(signing.map((a) => GENERATION_KINDS[a.generation.kind] ?? a.generation.kind))],
      sources: [...new Set(signing.map((a) => a.label ?? a.id ?? "unnamed attestation"))],
    };
  }

  if (b.claims.length) {
    return {
      value: "asserted",
      kinds: [...new Set(b.claims.map((c) => GENERATION_KINDS[c.generation_kind] ?? c.generation_kind ?? "unspecified"))],
      sources: [...new Set(b.claims.map((c) => c.source ?? "unknown source"))],
      detector_scores: b.claims
        .filter((c) => typeof c.confidence === "number")
        .map((c) => ({ source: c.source ?? "unknown", confidence: c.confidence })),
    };
  }

  return { value: "none", kinds: [], sources: [] };
}

/* ------------------------------------------------------------------ *
 * Front door
 * ------------------------------------------------------------------ */
export function pipeline(input, store) {
  const b = classify(input.evidence);
  const origin = deriveOriginAxes(input.evidence);
  const integ = deriveIntegrityAxis(input.evidence, input.content_hash ?? null, input.subject, store);
  const generation = deriveGenerationAxis(input.evidence);
  const authenticated = b.attestations.some(
    (a) => a.state === "valid" && (a.identity_proof === true || a.identity_proof === "verified")
  );

  let verdict = GRID[origin + "|" + integ.value] || "UNKNOWN";
  if (authenticated && verdict === "VERIFIED") verdict = "AUTHENTICATED";

  const record = {
    spec_version: SPEC_VERSION,
    subject: {
      kind: input.subject?.kind ?? "file",
      id: input.subject?.id ?? "",
      ...(Array.isArray(input.subject?.derived_from) && input.subject.derived_from.length
        ? { derived_from: input.subject.derived_from }
        : {}),
    },
    origin,
    integrity: integ.value,
    authenticated,
    generation: generation.value,
    evidence: b.attestations.concat(b.assertions, b.claims),
    issuer: input.issuer ?? null,
    checked_at: input.checked_at ?? new Date().toISOString(),
  };
  if (input.content_hash) record.content_hash = input.content_hash;

  return {
    record,
    derivation: integ.derivation,
    reason: integ.reason,
    resolvable: integ.resolvable,
    verdict,
  };
}

/* Derive AND remember — the scanner's normal path, since a scanned image is
 * usually the parent of something downstream. */
export function pipelineAndStore(input, store) {
  const out = pipeline(input, store);
  if (out.record.content_hash) store.store({ ...out.record, verdict: out.verdict });
  return out;
}
