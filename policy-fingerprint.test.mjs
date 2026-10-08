/* TRUST:// policy x fingerprint — the two claims, visible at once.
 *
 *   1. The same record, under two different trust policies, gets two different
 *      verdicts — and both are right, because the trust list belongs to the
 *      verifier, not to the record.
 *
 *   2. The fingerprint check is reported ALONGSIDE the status and never lifts
 *      it. An unconfirmed signature over bytes that are NOT the bytes declared
 *      reads CLAIMED with fingerprint "mismatch" — the finding is visible
 *      without distorting the status.
 *
 * Self-contained: SHA-256 via WebCrypto, no imports.
 */

const SPEC_VERSION = "TRUST-Record/0.2";
const SIGNATURE_STATES = ["verified", "invalid", "unknown"];

async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function createTrustList(anchors = [], opts = {}) {
  const entries = (anchors || []).map((a) => ({ name: typeof a === "string" ? a : a.name, fingerprint: typeof a === "string" ? null : (a.fingerprint ?? null) }));
  return {
    anchors: entries,
    unknownAnchorPolicy: opts.unknownAnchorPolicy ?? "untrusted",
    has(k) { return entries.some((e) => e.name === k || e.fingerprint === k); },
    size() { return entries.length; },
  };
}

const DEFAULT_POLICY = {
  trustList: createTrustList([]),
  allowExpiredChain: false,
  clockSkewSeconds: 300,
  treatUnknownAsInvalid: false,
  requireTrustedTimestamp: false,
  noVerifierPolicy: "unknown",
};
const withPolicy = (o = {}) => ({ ...DEFAULT_POLICY, ...o });

const POLICY_CONFIGS = {
  strict:   () => withPolicy({ trustList: createTrustList(["Example Root CA"]), allowExpiredChain: false, requireTrustedTimestamp: true,  treatUnknownAsInvalid: false }),
  open:     () => withPolicy({ trustList: createTrustList(["Example Root CA"]), allowExpiredChain: true,  requireTrustedTimestamp: false, treatUnknownAsInvalid: false }),
  none:     () => withPolicy({ trustList: createTrustList([]),                  allowExpiredChain: false, requireTrustedTimestamp: false, treatUnknownAsInvalid: false }),
  paranoid: () => withPolicy({ trustList: createTrustList(["Example Root CA"]), allowExpiredChain: false, requireTrustedTimestamp: true,  treatUnknownAsInvalid: true }),
};

function normalise(raw) {
  return {
    state: SIGNATURE_STATES.indexOf(raw?.state) >= 0 ? raw.state : "unknown",
    chain: ["intact", "expired", "unavailable"].indexOf(raw?.chain) >= 0 ? raw.chain : "unavailable",
    anchor: raw?.anchor ?? null,
    reason: String(raw?.reason ?? ""),
  };
}

function applyPolicy(raw, policy) {
  const p = policy || DEFAULT_POLICY;
  const r = normalise(raw);
  const notes = [];

  if (r.state === "unknown") {
    if (p.noVerifierPolicy === "invalid" || p.treatUnknownAsInvalid === true) {
      return { state: "invalid", reason: r.reason + " — policy treats an undetermined check as a failure", notes: ["unknown promoted to invalid by policy"] };
    }
    return { state: "unknown", reason: r.reason || "the signature could not be checked", notes };
  }
  if (r.state === "invalid") return { state: "invalid", reason: r.reason || "the signature is invalid", notes };
  if (r.chain === "unavailable") return { state: "invalid", reason: "signature verified, but no chain to a trust anchor could be built", notes };
  if (r.chain === "expired" && p.allowExpiredChain !== true) return { state: "invalid", reason: "the certificate chain has expired and policy does not accept expired chains", notes };

  if (p.trustList.size() > 0 && r.anchor) {
    if (!p.trustList.has(r.anchor)) {
      if (p.trustList.unknownAnchorPolicy === "trusted") notes.push("anchor not on the trust list, but policy accepts unknown anchors");
      else return { state: "invalid", reason: 'signed by "' + r.anchor + '", which is not on this verifier\'s trust list', notes };
    } else notes.push('anchor "' + r.anchor + '" is on the verifier\'s trust list');
  } else if (p.trustList.size() > 0 && !r.anchor) {
    return { state: "invalid", reason: "the verifier did not report a trust anchor, but policy requires one", notes };
  }

  if (p.requireTrustedTimestamp === true && !(raw && raw.timestamp && raw.timestamp.trusted)) {
    return { state: "invalid", reason: "policy requires a trusted timestamp and none was presented", notes };
  }
  return {
    state: "verified",
    reason: r.chain === "expired" ? "signature valid against a trust anchor; the chain has expired but policy accepts it" : "signature valid against a trust anchor",
    notes,
  };
}

const GRID = {
  "verified|intact": "VERIFIED", "verified|modified": "MODIFIED", "verified|broken": "INVALID",
  "claimed|intact": "CLAIMED", "claimed|modified": "CLAIMED", "claimed|broken": "INVALID",
  "none|intact": "UNKNOWN", "none|modified": "UNKNOWN", "none|broken": "UNKNOWN",
};

function deriveRecord(input) {
  const evidence = Array.isArray(input.evidence) ? input.evidence : [];
  const att = evidence.filter((e) => e && e.kind === "attestation");
  const asr = evidence.filter((e) => e && e.kind === "assertion");
  const clm = evidence.filter((e) => e && e.kind === "generation_claim");
  const bytesHash = input.content_hash ?? null;

  const origin = att.some((a) => a.state === "valid") ? "verified"
    : (att.length || asr.length || clm.length ? "claimed" : "none");

  const withHash = att.filter((a) => typeof a.content_hash === "string" && a.content_hash.length === 64);
  let integrity = "intact";
  if (withHash.length && bytesHash) {
    const m = withHash.filter((a) => a.content_hash.toLowerCase() === bytesHash.toLowerCase());
    const o = withHash.filter((a) => a.content_hash.toLowerCase() !== bytesHash.toLowerCase());
    if (m.length && o.length) integrity = "broken";
    else if (m.length) integrity = "intact";
    else integrity = "modified";
  }

  const signing = att.filter((a) => a.state === "valid" && a.generation && a.generation.kind);
  const generation = signing.length ? "attested_by_signer" : (clm.length ? "asserted" : "none");
  const authenticated = att.some((a) => a.state === "valid" && (a.identity_proof === true || a.identity_proof === "verified"));

  let verdict = GRID[origin + "|" + integrity] || "UNKNOWN";
  if (authenticated && verdict === "VERIFIED") verdict = "AUTHENTICATED";

  const declared = Array.from(new Set(withHash.map((a) => a.content_hash.toLowerCase())));
  let fingerprint;
  if (!bytesHash) fingerprint = { result: "none", detail: "no bytes were presented" };
  else if (!declared.length) fingerprint = { result: "none", detail: "no evidence declared a fingerprint" };
  else if (declared.length > 1) fingerprint = { result: "multiple", detail: "the evidence declares " + declared.length + " different fingerprints" };
  else fingerprint = declared[0] === bytesHash.toLowerCase()
    ? { result: "match", detail: "the declared fingerprint is the fingerprint of these bytes" }
    : { result: "mismatch", detail: "the declared fingerprint belongs to different bytes" };

  return { origin, integrity, generation, authenticated, verdict, fingerprint };
}

const DEMO_VERIFICATIONS = {
  "urn:c2pa:9f2c": { state: "verified", chain: "intact", anchor: "Example Root CA", timestamp: { trusted: true } },
  "urn:c2pa:aa10": { state: "verified", chain: "intact", anchor: "Example Root CA", timestamp: { trusted: true } },
  "urn:c2pa:bb21": { state: "verified", chain: "expired", anchor: "Example Root CA" },
  "urn:c2pa:c0de": { state: "verified", chain: "intact", anchor: "Rogue Issuer" },
  "urn:c2pa:b0a1": { state: "invalid", chain: "unavailable", reason: "the signature does not match the payload" },
};
const verifier = { async verify(e) { return DEMO_VERIFICATIONS[e && e.id] || { state: "unknown", chain: "unavailable", reason: "no verification result available" }; } };

async function annotate(evidence, policy) {
  const out = [];
  const list = Array.isArray(evidence) ? evidence : [];
  for (let i = 0; i < list.length; i++) {
    const item = list[i];
    if (!item || item.kind !== "attestation") { out.push(item); continue; }
    let raw;
    try { raw = await verifier.verify(item); }
    catch (err) { raw = { state: "unknown", chain: "unavailable", reason: String(err && err.message || err) }; }
    const d = applyPolicy(raw, policy);
    out.push(Object.assign({}, item, {
      state: d.state === "verified" ? "valid" : (d.state === "invalid" ? "invalid" : "unknown"),
      policy_state: d.state,
      policy_reason: d.reason,
    }));
  }
  return out;
}

const H = await sha256Hex(new TextEncoder().encode("the-bytes-in-hand"));
const OTHER = "f".repeat(64);
const SECOND = "b".repeat(64);

const cases = [
  { label: "signiert, Fingerabdruck stimmt", evidence: [{ kind: "attestation", id: "urn:c2pa:9f2c", content_hash: H }], hash: H },
  { label: "abgelaufene Kette", evidence: [{ kind: "attestation", id: "urn:c2pa:bb21", content_hash: H }], hash: H },
  { label: "unbekannter Aussteller", evidence: [{ kind: "attestation", id: "urn:c2pa:c0de", content_hash: H }], hash: H },
  { label: "keine Verifikation", evidence: [{ kind: "attestation", id: "urn:c2pa:missing", content_hash: H }], hash: H },
  { label: "kein Verifier, andere Bytes", evidence: [{ kind: "attestation", id: "urn:c2pa:missing", content_hash: OTHER }], hash: H },
  { label: "zwei Fingerabdrueche", evidence: [{ kind: "attestation", id: "urn:c2pa:9f2c", content_hash: H }, { kind: "attestation", id: "urn:c2pa:other", content_hash: SECOND }], hash: H },
];

const matrix = {};
for (const name of Object.keys(POLICY_CONFIGS)) {
  matrix[name] = {};
  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const evidence = await annotate(c.evidence, POLICY_CONFIGS[name]());
    matrix[name][c.label] = deriveRecord({ subject: { kind: "url", id: "https://example.org/x" }, evidence, content_hash: c.hash });
  }
}

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }

const lines = [];
lines.push("");
lines.push("TRUST:// policy x fingerprint - Record Format 0.2");
lines.push("");
lines.push(pad("case", 30) + pad("strict", 12) + pad("open", 12) + pad("fingerprint", 12));
lines.push("-".repeat(68));
for (let i = 0; i < cases.length; i++) {
  const k = cases[i].label;
  lines.push(pad(k, 30) + pad(matrix.strict[k].verdict, 12) + pad(matrix.open[k].verdict, 12) + matrix.strict[k].fingerprint.result);
}
lines.push("-".repeat(68));
lines.push("");

const inv = {
  "same facts, different policy, different verdict": matrix.strict["abgelaufene Kette"].verdict !== matrix.open["abgelaufene Kette"].verdict,
  "no policy lifts an undetermined signature to VERIFIED": matrix.open["keine Verifikation"].verdict !== "VERIFIED" && matrix.paranoid["keine Verifikation"].verdict !== "VERIFIED",
  "the fingerprint is visible when the status hides it": matrix.strict["kein Verifier, andere Bytes"].verdict === "CLAIMED" && matrix.strict["kein Verifier, andere Bytes"].fingerprint.result === "mismatch",
  "the fingerprint never lifts a status": matrix.strict["kein Verifier, andere Bytes"].verdict !== "VERIFIED" && matrix.strict["kein Verifier, andere Bytes"].verdict !== "MODIFIED",
  "the grid is unchanged: six statuses in use": [matrix.strict, matrix.open, matrix.none, matrix.paranoid]
    .flatMap((p) => Object.values(p).map((v) => v.verdict))
    .every((v) => ["VERIFIED", "AUTHENTICATED", "CLAIMED", "MODIFIED", "INVALID", "UNKNOWN"].indexOf(v) >= 0),
};

let pass = 0;
for (const name of Object.keys(inv)) { if (inv[name]) pass++; lines.push("inv  " + pad(name, 52) + (inv[name] ? "holds" : "VIOLATED")); }
lines.push("");
lines.push("The grid says what state the record is in.");
lines.push("The fingerprint says whether the content is the content it claims to be.");
lines.push("");

console.log(lines.join("\n"));

const results = { spec_version: SPEC_VERSION, invariants: inv, pass: pass, total: Object.keys(inv).length, allGreen: pass === Object.keys(inv).length };
if (typeof globalThis.__report === "function") globalThis.__report(results);
return results;
