import { bench, describe } from "vitest";
import {
  DEFAULT_POLICY,
  applyPolicy,
  annotateEvidence,
  createStubVerifier,
  createTrustList,
  verifierSummary,
  verifyAttestations,
  withPolicy,
} from "../signature.js";
import { makeEvidence } from "./fixtures.js";

const evidence = makeEvidence(400);
const anchors = Array.from({ length: 50 }, (_, i) => ({ name: `Anchor ${i}`, fingerprint: `fp-${i}` }));
const policy = withPolicy({ trustList: createTrustList(anchors), allowExpiredChain: true });

const table = {};
evidence.forEach((e, i) => {
  if (e.kind !== "attestation") return;
  table[e.id] = {
    state: ["verified", "invalid", "unknown"][i % 3],
    chain: ["intact", "expired", "unavailable"][i % 3],
    anchor: `Anchor ${i % 60}`,
    signer: `Signer ${i}`,
    issued_at: "2026-09-30T08:12:00Z",
    reason: "reported by stub verifier",
  };
});
const verifier = createStubVerifier(table);
const rawResults = Object.values(table);
const summaryInput = await verifyAttestations(evidence, verifier, policy);

describe("signature policy", () => {
  bench("applyPolicy: 200 raw results, default policy", () => {
    for (const raw of rawResults) applyPolicy(raw, DEFAULT_POLICY);
  });

  bench("applyPolicy: 200 raw results, 50-anchor trust list", () => {
    for (const raw of rawResults) applyPolicy(raw, policy);
  });

  bench("verifyAttestations: 400 evidence items", async () => {
    await verifyAttestations(evidence, verifier, policy);
  });

  bench("annotateEvidence: 400 evidence items", async () => {
    await annotateEvidence(evidence, verifier, policy);
  });

  bench("verifierSummary", () => {
    verifierSummary(summaryInput);
  });
});
