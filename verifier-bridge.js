/* TRUST:// verifier bridge — connects signature.js policy to the record engine.
 *
 * `engine.js` and `derivation.js` consume `state` and `chain` on each
 * attestation, as if something had produced them. This module is that
 * something's output side: it takes raw evidence, runs it through a verifier
 * plus a policy, and hands back evidence the engine can read.
 *
 * The three modules form one chain, and each one owns exactly one question:
 *
 *   engine.js      — given verified facts, what is the record?
 *   derivation.js  — is a changed byte a transform or a tampering?
 *   signature.js   — may we call this attestation verified at all?
 *
 * Self-contained: mirrors the policy in signature.js so the bridge runs as a
 * plain script without module wiring. Keep the two in step.
 */

const SIGNATURE_STATES = ["verified", "invalid", "unknown"];

export function createTrustList(anchors = [], opts = {}) {
  const entries = (anchors || []).map((a) => ({
    name: typeof a === "string" ? a : a.name,
    fingerprint: typeof a === "string" ? null : (a.fingerprint ?? null),
  }));
  return {
    anchors: entries,
    unknownAnchorPolicy: opts.unknownAnchorPolicy ?? "untrusted",
    has(k) { return entries.some((e) => e.name === k || e.fingerprint === k); },
    size() { return entries.length; },
  };
}

export const DEFAULT_POLICY = {
  trustList: createTrustList([]),
  allowExpiredChain: false,
  clockSkewSeconds: 300,
  treatUnknownAsInvalid: false,
  requireTrustedTimestamp: false,
  noVerifierPolicy: "unknown",
};

export function withPolicy(overrides = {}) {
  return { ...DEFAULT_POLICY, ...overrides };
}

function normalise(raw) {
  return {
    state: SIGNATURE_STATES.includes(raw?.state) ? raw.state : "unknown",
    chain: ["intact", "expired", "unavailable"].includes(raw?.chain) ? raw.chain : "unavailable",
    anchor: raw?.anchor ?? null,
    signer: raw?.signer ?? null,
    issued_at: raw?.issued_at ?? null,
    timestamp: raw?.timestamp ?? null,
    reason: String(raw?.reason ?? ""),
    errors: Array.isArray(raw?.errors) ? raw.errors.map(String) : [],
  };
}

export function applyPolicy(raw, policy = DEFAULT_POLICY) {
  const r = normalise(raw);
  const notes = [];

  if (r.state === "unknown") {
    if (policy.noVerifierPolicy === "invalid" || policy.treatUnknownAsInvalid) {
      return { state: "invalid", chain: r.chain, reason: `${r.reason} — policy treats an undetermined check as a failure`, notes: [...notes, "unknown promoted to invalid by policy"], raw: r };
    }
    return { state: "unknown", chain: r.chain, reason: r.reason || "the signature could not be checked", notes, raw: r };
  }
  if (r.state === "invalid") {
    return { state: "invalid", chain: r.chain === "intact" ? "unavailable" : r.chain, reason: r.reason || "the signature is invalid", notes, raw: r };
  }

  if (r.chain === "unavailable") return { state: "invalid", chain: "unavailable", reason: "signature verified, but no chain to a trust anchor could be built", notes, raw: r };
  if (r.chain === "expired" && !policy.allowExpiredChain) return { state: "invalid", chain: "expired", reason: "the certificate chain has expired and policy does not accept expired chains", notes, raw: r };

  if (policy.trustList?.size?.() > 0 && r.anchor) {
    if (!policy.trustList.has(r.anchor)) {
      if (policy.trustList.unknownAnchorPolicy === "trusted") notes.push("anchor not on the verifier's trust list, but policy accepts unknown anchors");
      else return { state: "invalid", chain: r.chain, reason: `signed by "${r.anchor}", which is not on this verifier's trust list`, notes, raw: r };
    } else notes.push(`anchor "${r.anchor}" is on the verifier's trust list`);
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
    reason: r.chain === "expired" ? "signature valid against a trust anchor; the chain has expired but policy accepts it" : "signature valid against a trust anchor",
    notes, raw: r,
  };
}

export function noVerifier() {
  return {
    kind: "none",
    async verify() {
      return { state: "unknown", chain: "unavailable", anchor: null, signer: null, issued_at: null, timestamp: null, reason: "no verifier was injected; the signature was not checked", errors: [] };
    },
  };
}

export function createStubVerifier(table = {}) {
  return {
    kind: "stub",
    async verify(evidence) {
      const entry = table[evidence?.id] ?? table[evidence?.content_hash];
      if (!entry) return { state: "unknown", chain: "unavailable", anchor: null, signer: null, issued_at: null, timestamp: null, reason: "no entry in the stub table for this evidence", errors: [] };
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

export async function verifyEvidence(evidence, verifier = noVerifier(), policy = DEFAULT_POLICY) {
  let raw;
  try {
    raw = await verifier.verify(evidence);
  } catch (err) {
    raw = { state: "unknown", chain: "unavailable", reason: `the verifier threw: ${err?.message ?? String(err)}`, errors: [String(err?.message ?? err)] };
  }
  const decided = applyPolicy(raw, policy);
  return { evidence_id: evidence?.id ?? null, content_hash: evidence?.content_hash ?? null, ...decided };
}

/** Rewrite an evidence list so engine.js / derivation.js can consume it.
 *  Attestation state and chain are REPLACED by what the verifier determined —
 *  a caller cannot smuggle in `state: "valid"` of its own. */
export async function annotateEvidence(evidenceList, verifier = noVerifier(), policy = DEFAULT_POLICY) {
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
      state: v.state === "verified" ? "valid" : v.state === "invalid" ? "invalid" : "unknown",
      chain: v.chain,
      ...(v.raw?.signer ? { signer: v.raw.signer } : {}),
      ...(v.raw?.anchor ? { anchor: v.raw.anchor } : {}),
      ...(v.notes.length ? { verification_notes: v.notes } : {}),
      verification_reason: v.reason,
    });
  }
  return out;
}

export function verifierSummary(results) {
  const real = results.filter((r) => !r.skipped);
  const verified = real.filter((r) => r.state === "verified").length;
  const invalid = real.filter((r) => r.state === "invalid").length;
  const unknown = real.filter((r) => r.state === "unknown").length;
  return {
    checked: real.length,
    verified, invalid, unknown,
    allVerified: real.length > 0 && verified === real.length,
    summary: real.length === 0
      ? "no attestation was checked"
      : `${verified} verified, ${invalid} invalid, ${unknown} undetermined — undetermined is a measurement, not a failure`,
  };
}
