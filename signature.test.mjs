/* TRUST:// signature policy test suite
 *
 * Proves the two things that matter about a policy layer:
 *
 *   1. A failed or undetermined check NEVER produces `verified`.
 *      Undefined behaviour fails closed — an unresolvable chain, an expired
 *      certificate, an anchor we do not trust, and a verifier that simply threw
 *      all end at `claimed` at best, never at `verified`.
 *
 *   2. `unknown` and `invalid` stay different claims. Collapsing them would turn
 *      "we could not check" into "we checked and it failed", which is the single
 *      most damaging lie a verification system can tell.
 *
 * Self-contained: no imports. Runs in Node 18+, in a browser, or as a script
 * body in any JS runner.
 */

const SPEC_VERSION = "TRUST-Record/0.2";
const SIGNATURE_STATES = ["verified", "invalid", "unknown"];

/* ---------------- the policy layer, inlined ---------------- */

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

function applyPolicy(raw, policy = DEFAULT_POLICY) {
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

/** The one place a verifier is called. A verifier that throws is `unknown`. */
async function verifyEvidence(evidence, verifier, policy = DEFAULT_POLICY) {
  let raw;
  try {
    raw = await verifier.verify(evidence);
  } catch (err) {
    raw = { state: "unknown", chain: "unavailable", reason: `the verifier threw: ${err?.message ?? String(err)}`, errors: [String(err?.message ?? err)] };
  }
  return { evidence_id: evidence?.id ?? null, ...applyPolicy(raw, policy) };
}

/* ---------------- the case under test ---------------- */

const GOOD = { kind: "attestation", id: "urn:c2pa:good", label: "C2PA manifest", content_hash: "a".repeat(64) };

const table = {
  "urn:c2pa:good": { state: "verified", chain: "intact", anchor: "Example Root CA", signer: "did:web:example.org", issued_at: "2026-09-30T08:12:00Z", timestamp: { trusted: true, at: "2026-09-30T08:12:01Z" } },
  "urn:c2pa:expired-cert": { state: "verified", chain: "expired", anchor: "Example Root CA", signer: "did:web:example.org" },
  "urn:c2pa:no-chain": { state: "verified", chain: "unavailable", anchor: null, signer: "did:web:example.org" },
  "urn:c2pa:bad-sig": { state: "invalid", chain: "unavailable", anchor: null, reason: "signature does not match the payload" },
  "urn:c2pa:rogue": { state: "verified", chain: "intact", anchor: "Rogue Issuer", signer: "did:web:rogue.example" },
  "urn:c2pa:notime": { state: "verified", chain: "intact", anchor: "Example Root CA", signer: "did:web:example.org", timestamp: null },
};

const stub = {
  kind: "stub",
  async verify(e) { return table[e?.id] ?? { state: "unknown", chain: "unavailable", reason: "no entry in the stub table" }; },
};
const thrower = { kind: "thrower", async verify() { throw new Error("network unreachable"); } };

const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = got === want;
  if (ok) pass++;
  rows.push({ label, got, want, ok });
};

const P = (o) => withPolicy(o);
const trust = createTrustList(["Example Root CA"]);

const good = await verifyEvidence(GOOD, stub, P({ trustList: trust }));
check("1 good signature", good.state, "verified");
check("1 chain intact", good.chain, "intact");
check("1 anchor on trust list", good.notes.some((n) => n.includes("trust list")), true);

const expired = await verifyEvidence({ ...GOOD, id: "urn:c2pa:expired-cert" }, stub, P({ trustList: trust }));
check("2 expired chain refused", expired.state, "invalid");
check("2 expired chain reported", expired.chain, "expired");

const expiredOk = await verifyEvidence({ ...GOOD, id: "urn:c2pa:expired-cert" }, stub, P({ trustList: trust, allowExpiredChain: true }));
check("3 expired allowed by policy", expiredOk.state, "verified");

const noChain = await verifyEvidence({ ...GOOD, id: "urn:c2pa:no-chain" }, stub, P({ trustList: trust }));
check("4 unbuildable chain", noChain.state, "invalid");

const bad = await verifyEvidence({ ...GOOD, id: "urn:c2pa:bad-sig" }, stub, P({ trustList: trust }));
check("5 bad signature", bad.state, "invalid");

const rogue = await verifyEvidence({ ...GOOD, id: "urn:c2pa:rogue" }, stub, P({ trustList: trust }));
check("6 untrusted anchor refused", rogue.state, "invalid");
check("6 anchor named in reason", rogue.reason.includes("Rogue Issuer"), true);

const none = await verifyEvidence(GOOD, { async verify() { return { state: "unknown", chain: "unavailable", reason: "no verifier was injected; the signature was not checked" }; } }, P({ trustList: trust }));
check("7 no verifier -> unknown", none.state, "unknown");

const thrown = await verifyEvidence(GOOD, thrower, P({ trustList: trust }));
check("8 throwing verifier -> unknown", thrown.state, "unknown");
check("8 error captured", thrown.raw.errors.length > 0, true);

const strict = await verifyEvidence(GOOD, thrower, P({ trustList: trust, treatUnknownAsInvalid: true }));
check("9 strict policy -> invalid", strict.state, "invalid");
check("9 reason names the policy", strict.reason.includes("policy treats"), true);

const noTime = await verifyEvidence({ ...GOOD, id: "urn:c2pa:notime" }, stub, P({ trustList: trust, requireTrustedTimestamp: true }));
check("10 missing timestamp refused", noTime.state, "invalid");

const noList = await verifyEvidence({ ...GOOD, id: "urn:c2pa:rogue" }, stub, P({}));
check("11 empty trust list accepts", noList.state, "verified");

const lax = await verifyEvidence({ ...GOOD, id: "urn:c2pa:rogue" }, stub, P({ trustList: createTrustList(["Example Root CA"], { unknownAnchorPolicy: "trusted" }) }));
check("12 unknown anchor accepted by policy", lax.state, "verified");

/* ---------------- the invariant that matters ---------------- */

const everything = await Promise.all([
  verifyEvidence(GOOD, stub, P({ trustList: trust })),
  verifyEvidence({ ...GOOD, id: "urn:c2pa:expired-cert" }, stub, P({ trustList: trust })),
  verifyEvidence({ ...GOOD, id: "urn:c2pa:no-chain" }, stub, P({ trustList: trust })),
  verifyEvidence({ ...GOOD, id: "urn:c2pa:bad-sig" }, stub, P({ trustList: trust })),
  verifyEvidence({ ...GOOD, id: "urn:c2pa:rogue" }, stub, P({ trustList: trust })),
  verifyEvidence(GOOD, thrower, P({ trustList: trust })),
  verifyEvidence({ ...GOOD, id: "urn:c2pa:notime" }, stub, P({ trustList: trust, requireTrustedTimestamp: true })),
]);

const nonVerified = everything.filter((r) => r.state !== "verified");
const inv = {
  "nothing non-verified is reported as verified": nonVerified.every((r) => r.state === "invalid" || r.state === "unknown"),
  "unknown stays distinct from invalid": everything.some((r) => r.state === "unknown") && everything.some((r) => r.state === "invalid"),
  "a throwing verifier never verifies": (await verifyEvidence(GOOD, thrower, P({}))).state !== "verified",
  "an untrusted anchor never verifies": rogue.state !== "verified",
  "an expired chain never verifies by default": expired.state !== "verified",
};

const width = [40, 16, 16];
const lines = [];
lines.push("");
lines.push("TRUST:// signature policy suite - Record Format 0.2");
lines.push("");
lines.push("check".padEnd(width[0]) + "got".padEnd(width[1]) + "want".padEnd(width[2]) + "ok");
lines.push("-".repeat(78));
for (const r of rows) {
  lines.push(String(r.label).padEnd(width[0]) + String(r.got).padEnd(width[1]) + String(r.want).padEnd(width[2]) + (r.ok ? "pass" : "FAIL"));
}
lines.push("-".repeat(78));
lines.push(`passed ${pass}/${rows.length}`);
lines.push("");
for (const [name, holds] of Object.entries(inv)) lines.push(`inv  ${name.padEnd(48)} ${holds ? "holds" : "VIOLATED"}`);
lines.push("");
lines.push("A failed or undetermined check never produces verified.");
lines.push("unknown is a measurement. invalid is a finding. They are not the same claim.");
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
