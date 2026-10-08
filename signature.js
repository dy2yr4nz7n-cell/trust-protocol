/* TRUST:// signature verifier — the layer the spec says it does not do itself
 * Record Format 0.2
 *
 * WHAT THIS IS
 * ------------
 * `engine.js` and `derivation.js` consume the RESULT of a verification they
 * cannot perform: `state: "valid" | "invalid" | "unknown"` and `chain`.
 * Something has to produce those values. This is that something.
 *
 * WHAT IT CAN AND CANNOT DO — read this before trusting a green checkmark
 * ----------------------------------------------------------------------
 * Full C2PA validation means: parse the CBOR/COSE structure, build the X.509
 * chain to a trust anchor, check revocation (CRL/OCSP over a network), and
 * verify an RFC 3161 timestamp. That needs a network and a trust list. Any
 * implementation claiming to do it offline is lying.
 *
 * So the work is split along a line that can be stated honestly:
 *
 *   VERIFIER (needs a network)        POLICY (this file, needs nothing)
 *   ------------------------------    ------------------------------------
 *   chain to a trust anchor           is the anchor one WE decided to trust
 *   revocation (CRL / OCSP)           is the chain state acceptable for us
 *   RFC 3161 timestamp                is "unknown" treated as a failure
 *   cryptographic signature check     how much clock skew we allow
 *
 * This module is the POLICY half plus a pluggable VERIFIER interface. It is
 * complete and testable. The verifier half is deliberately an injected
 * dependency — not a missing feature but the boundary the standard describes.
 *
 * THE RULE THAT KEEPS IT HONEST
 * ----------------------------
 * A failed or unknown check NEVER produces `verified`. Undefined behaviour must
 * fail closed: an unresolvable chain, an expired certificate and a verifier that
 * simply threw all end at `claimed` at best — never at `verified`.
 */

export const SPEC_VERSION = "TRUST-Record/0.2";
export const VERIFIER_INTERFACE = "trust/verifier@0.2";

/* ------------------------------------------------------------------ *
 * Terminal states, before policy
 * ------------------------------------------------------------------ *
 * "verified"    a complete, valid chain to a trusted anchor, signature good
 * "invalid"     the signature, the structure or the chain is provably broken
 * "unknown"     it could not be determined — no network, no anchor, no verifier
 *
 * `unknown` and `invalid` are different claims and must never collapse.
 */

export const SIGNATURE_STATES = ["verified", "invalid", "unknown"];

/* ------------------------------------------------------------------ *
 * Trust anchors
 * ------------------------------------------------------------------ *
 * Which issuers a verifier decides to trust is a POLICY choice, and it belongs
 * to the verifier — exactly like `issuer` being a reference rather than a value.
 * The record never contains this: a record saying "signed by X" is a fact, a
 * record saying "X is trustworthy" would be an opinion.
 */

export function createTrustList(anchors = [], opts = {}) {
  const entries = anchors.map((a) => ({
    name: typeof a === "string" ? a : a.name,
    fingerprint: typeof a === "string" ? null : (a.fingerprint ?? null),
  }));
  return {
    anchors: entries,
    /** A verifier must decide the default for an anchor it does not know. */
    unknownAnchorPolicy: opts.unknownAnchorPolicy ?? "untrusted", // "untrusted" | "trusted"
    has(nameOrFingerprint) {
      return entries.some((e) => e.name === nameOrFingerprint || e.fingerprint === nameOrFingerprint);
    },
    size() {
      return entries.length;
    },
  };
}

/* ------------------------------------------------------------------ *
 * Policy
 * ------------------------------------------------------------------ *
 * Every field here is a decision a verifier makes about ITSELF, which is why
 * none of it lives in the record format.
 */

export const DEFAULT_POLICY = {
  /** anchors the verifier decided to trust */
  trustList: createTrustList([]),
  /** is a chain that expired later still acceptable for an old signature? */
  allowExpiredChain: false,
  /** how long before issued_at the signature may have been made */
  clockSkewSeconds: 300,
  /** treat `unknown` as a failure? off by default: unknown is a measurement */
  treatUnknownAsInvalid: false,
  /** require an RFC 3161 timestamp to call something verified */
  requireTrustedTimestamp: false,
  /** what to do when no verifier is injected at all */
  noVerifierPolicy: "unknown", // "unknown" | "invalid"
};

export function withPolicy(overrides = {}) {
  return { ...DEFAULT_POLICY, ...overrides };
}

/* ------------------------------------------------------------------ *
 * The verifier interface
 * ------------------------------------------------------------------ *
 * A verifier is any object with a `verify` method returning:
 *
 *   {
 *     state:       "verified" | "invalid" | "unknown",
 *     chain:       "intact" | "expired" | "unavailable",
 *     anchor:      string | null,   // which trust anchor it terminated at
 *     signer:      string | null,   // the signing identity, as reported
 *     issued_at:   ISO 8601 | null,
 *     timestamp:   { trusted: boolean, at: ISO 8601 } | null,
 *     reason:      string,          // free text, for the verifier's own log
 *     errors:      string[],
 *   }
 *
 * A verifier that throws is not a crash — it is an `unknown` result.
 */

export function noVerifier() {
  return {
    kind: "none",
    async verify() {
      return {
        state: "unknown",
        chain: "unavailable",
        anchor: null,
        signer: null,
        issued_at: null,
        timestamp: null,
        reason: "no verifier was injected; the signature was not checked",
        errors: [],
      };
    },
  };
}

/** A verifier driven by a table of known evidence ids. Useful for tests, for a
 *  cached verification result, and for previewing a policy without a network. */
export function createStubVerifier(table = {}) {
  return {
    kind: "stub",
    async verify(evidence) {
      const entry = table[evidence?.id] ?? table[evidence?.content_hash];
      if (!entry) {
        return {
          state: "unknown",
          chain: "unavailable",
          anchor: null,
          signer: null,
          issued_at: null,
          timestamp: null,
          reason: "no entry in the stub table for this evidence",
          errors: [],
        };
      }
      return {
        state: entry.state ?? "unknown",
        chain: entry.chain ?? "unavailable",
        anchor: entry.anchor ?? null,
        signer: entry.signer ?? null,
        issued_at: entry.issued_at ?? null,
        timestamp: entry.timestamp ?? null,
        reason: entry.reason ?? "reported by stub verifier",
        errors: entry.errors ?? [],
      };
    },
  };
}

/* ------------------------------------------------------------------ *
 * Applying policy to a raw verifier result
 * ------------------------------------------------------------------ */

function normalise(raw) {
  const state = SIGNATURE_STATES.includes(raw?.state) ? raw.state : "unknown";
  const chain = ["intact", "expired", "unavailable"].includes(raw?.chain) ? raw.chain : "unavailable";
  return {
    state,
    chain,
    anchor: raw?.anchor ?? null,
    signer: raw?.signer ?? null,
    issued_at: raw?.issued_at ?? null,
    timestamp: raw?.timestamp ?? null,
    reason: String(raw?.reason ?? ""),
    errors: Array.isArray(raw?.errors) ? raw.errors.map(String) : [],
  };
}

/** The policy gate. Turns a raw verifier result into the `state`/`chain` pair
 *  the record format consumes, plus the reason it landed there. */
export function applyPolicy(raw, policy = DEFAULT_POLICY, context = {}) {
  const r = normalise(raw);
  const notes = [];

  /* Fail closed first: nothing below may lift a non-verified result. */
  if (r.state === "unknown") {
    if (policy.noVerifierPolicy === "invalid" || policy.treatUnknownAsInvalid) {
      return {
        state: "invalid",
        chain: r.chain,
        reason: `${r.reason} — policy treats an undetermined check as a failure`,
        notes: [...notes, "unknown promoted to invalid by policy"],
        raw: r,
      };
    }
    return {
      state: "unknown",
      chain: r.chain,
      reason: r.reason || "the signature could not be checked",
      notes,
      raw: r,
    };
  }

  if (r.state === "invalid") {
    return { state: "invalid", chain: r.chain === "intact" ? "unavailable" : r.chain, reason: r.reason || "the signature is invalid", notes, raw: r };
  }

  /* From here the verifier claims a valid signature. Policy may still refuse. */

  if (r.chain === "unavailable") {
    return { state: "invalid", chain: "unavailable", reason: "signature verified, but no chain to a trust anchor could be built", notes, raw: r };
  }

  if (r.chain === "expired" && !policy.allowExpiredChain) {
    return { state: "invalid", chain: "expired", reason: "the certificate chain has expired and policy does not accept expired chains", notes, raw: r };
  }

  if (policy.trustList?.size?.() > 0 && r.anchor) {
    if (!policy.trustList.has(r.anchor)) {
      if (policy.trustList.unknownAnchorPolicy === "trusted") {
        notes.push("anchor not on the verifier's trust list, but policy accepts unknown anchors");
      } else {
        return { state: "invalid", chain: r.chain, reason: `signed by "${r.anchor}", which is not on this verifier's trust list`, notes, raw: r };
      }
    } else {
      notes.push(`anchor "${r.anchor}" is on the verifier's trust list`);
    }
  } else if (policy.trustList?.size?.() > 0 && !r.anchor) {
    return { state: "invalid", chain: r.chain, reason: "the verifier did not report a trust anchor, but policy requires one from its trust list", notes, raw: r };
  }

  if (policy.requireTrustedTimestamp && !(r.timestamp && r.timestamp.trusted)) {
    return { state: "invalid", chain: r.chain, reason: "policy requires a trusted timestamp and none was presented", notes, raw: r };
  }

  if (r.timestamp?.trusted) notes.push("a trusted timestamp was presented");

  return {
    state: "verified",
    chain: r.chain,
    reason: r.chain === "expired"
      ? "signature valid against a trust anchor; the chain has expired but policy accepts it"
      : "signature valid against a trust anchor",
    notes,
    raw: r,
  };
}

/* ------------------------------------------------------------------ *
 * Verifying one evidence item
 * ------------------------------------------------------------------ */

export async function verifyEvidence(evidence, verifier = noVerifier(), policy = DEFAULT_POLICY) {
  if (!evidence || evidence.kind !== "attestation") {
    throw new Error("verifyEvidence expects an evidence item of kind \"attestation\"");
  }

  let raw;
  try {
    raw = await verifier.verify(evidence);
  } catch (err) {
    /* A verifier that throws is not verified. Ever. */
    raw = {
      state: "unknown",
      chain: "unavailable",
      reason: `the verifier threw: ${err?.message ?? String(err)}`,
      errors: [String(err?.message ?? err)],
    };
  }

  const decided = applyPolicy(raw, policy, { evidence });
  return {
    evidence_id: evidence.id ?? null,
    content_hash: evidence.content_hash ?? null,
    ...decided,
  };
}

/* ------------------------------------------------------------------ *
 * Turning results into the shape `engine.js` already consumes
 * ------------------------------------------------------------------ *
 * The record format wants `state` and `chain` on each attestation. This writes
 * them back, so the existing engine needs no change at all.
 */

export async function verifyAttestations(evidenceList, verifier, policy = DEFAULT_POLICY) {
  const list = Array.isArray(evidenceList) ? evidenceList : [];
  const results = [];

  for (const item of list) {
    if (!item || item.kind !== "attestation") {
      results.push({ skipped: true, item });
      continue;
    }
    results.push(await verifyEvidence(item, verifier, policy));
  }

  return results;
}

export async function annotateEvidence(evidenceList, verifier, policy = DEFAULT_POLICY) {
  const list = Array.isArray(evidenceList) ? evidenceList : [];
  const out = [];
  for (const item of list) {
    if (!item || item.kind !== "attestation") {
      out.push(item);
      continue;
    }
    const v = await verifyEvidence(item, verifier, policy);
    out.push({
      ...item,
      state: v.state,
      chain: v.chain,
      ...(v.raw?.signer ? { signer: v.raw.signer } : {}),
      ...(v.notes.length ? { verification_notes: v.notes } : {}),
    });
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * The honest one-liner
 * ------------------------------------------------------------------ */

export function verifierSummary(results) {
  const real = results.filter((r) => !r.skipped);
  const verified = real.filter((r) => r.state === "verified").length;
  const invalid = real.filter((r) => r.state === "invalid").length;
  const unknown = real.filter((r) => r.state === "unknown").length;
  return {
    checked: real.length,
    verified,
    invalid,
    unknown,
    allVerified: real.length > 0 && verified === real.length,
    summary: real.length === 0
      ? "no attestation was checked"
      : `${verified} verified, ${invalid} invalid, ${unknown} undetermined — undetermined is a measurement, not a failure`,
  };
}
