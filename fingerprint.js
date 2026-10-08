/* TRUST:// fingerprint check — an ADDITION to the record, not a change to the grid.
 * Record Format 0.2
 *
 * THE GRID IS UNCHANGED. Six statuses, two axes, the same mapping since 0.1.
 * Nothing in this file rewrites it.
 *
 * WHAT IS ADDED
 * -------------
 * A separate, independent check that has nothing to do with the status:
 *
 *   FINGERPRINT CHECK
 *   -----------------
 *   A hash is not a verifier's opinion about content — it is a property of the
 *   content itself. So this check needs no verifier, no trust list, no network.
 *   It compares the fingerprints the evidence declares against the fingerprint
 *   of the bytes in hand:
 *
 *       match      the declared fingerprint is the fingerprint of these bytes
 *       mismatch   the declared fingerprint belongs to DIFFERENT bytes
 *       multiple   the evidence declares more than one fingerprint
 *       none       nothing was declared, so nothing can be compared
 *
 *   DERIVATION LINK
 *   ---------------
 *   Does the subject tie these bytes to a source whose fingerprint was itself
 *   proven and whose origin resolved?
 *
 * WHY THEY STAY SEPARATE
 * ----------------------
 * The grid answers "what is the state of this record". The fingerprint answers
 * "is the content the content it claims to be". Different questions, and
 * different lifetimes:
 *
 *   the status changes as new evidence arrives — CLAIMED can become VERIFIED
 *   the fingerprint merely is; it was computed over bytes and stays the same
 *   fact in a hundred years
 *
 * Folding the fingerprint into the status would hide the case that matters
 * most: an unconfirmed signature over bytes that are NOT the bytes declared.
 * Kept alongside, the status stays comparable between systems while the
 * fingerprint stays checkable by anyone, with no verifier at all.
 */

export const SPEC_VERSION = "TRUST-Record/0.2";
export const FINGERPRINT_RESULTS = ["match", "mismatch", "multiple", "none"];

/* ------------------------------------------------------------------ *
 * The fingerprint check
 * ------------------------------------------------------------------ */

/** Compares declared fingerprints against the bytes in hand.
 *  No verifier, no trust list, no policy — a fingerprint is a property of the
 *  content, so this needs no second opinion. */
export function checkFingerprint(evidence, contentHash) {
  const att = (Array.isArray(evidence) ? evidence : []).filter((e) => e && e.kind === "attestation");
  const declared = att
    .filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64)
    .map((a) => ({ id: a.id ?? null, hash: a.content_hash.toLowerCase() }));
  const unique = Array.from(new Set(declared.map((d) => d.hash)));

  if (!contentHash) {
    return {
      result: "none",
      declared: unique,
      detail: "no bytes were presented, so there is nothing to compare",
    };
  }
  if (declared.length === 0) {
    return {
      result: "none",
      declared: [],
      detail: "no evidence declared a fingerprint, so nothing can be compared",
    };
  }
  if (unique.length > 1) {
    return {
      result: "multiple",
      declared: unique,
      detail: "the evidence declares " + unique.length + " different fingerprints — they cannot all describe the content",
    };
  }
  const match = unique[0] === contentHash.toLowerCase();
  return {
    result: match ? "match" : "mismatch",
    declared: unique,
    computed: contentHash.toLowerCase(),
    detail: match
      ? "the declared fingerprint is the fingerprint of these bytes"
      : "the declared fingerprint belongs to different bytes",
  };
}

/* ------------------------------------------------------------------ *
 * The derivation link
 * ------------------------------------------------------------------ */

/** Resolve `subject.derived_from` against a verifier's own records. A parent
 *  counts as proven only when its stored record has origin "verified" AND its
 *  own fingerprint check matched. */
export function checkDerivation(subject, store) {
  const parents = Array.isArray(subject?.derived_from) ? subject.derived_from : [];
  if (parents.length === 0) {
    return { linked: false, resolved: [], signed_parent: false, detail: "no derivation recorded" };
  }

  const resolved = parents.map((hash) => {
    const rec = (typeof store?.get === "function" ? store.get(hash) : null) ?? null;
    return {
      hash,
      known: Boolean(rec),
      fingerprint: rec?.fingerprint?.result ?? null,
      origin: rec?.origin ?? null,
    };
  });

  const proven = resolved.filter((r) => r.known && r.origin === "verified" && r.fingerprint === "match");
  return {
    linked: true,
    resolved,
    signed_parent: proven.length > 0,
    detail: proven.length > 0
      ? "links to a source whose fingerprint matched and whose origin was proven"
      : "links to a source with no proven-origin, fingerprint-matching record",
  };
}

/* ------------------------------------------------------------------ *
 * Attaching both to a derived record
 * ------------------------------------------------------------------ */

/** Takes the output of `deriveRecord()` (grid unchanged) plus the input it was
 *  derived from, and returns the same record with the two checks added.
 *  It NEVER touches origin, integrity, authenticated or verdict. */
export function attachChecks(record, input, store) {
  const evidence = Array.isArray(input?.evidence) ? input.evidence : [];
  const fingerprint = checkFingerprint(evidence, input?.content_hash ?? null);
  const derivation = checkDerivation(input?.subject, store);

  return {
    ...record,
    fingerprint,
    derivation,
  };
}

/** Serialisable form. `verdict` still never appears — it remains a view. */
export function checksJson(record) {
  const { verdict, ...persisted } = record;
  return JSON.stringify(persisted, null, 2);
}
