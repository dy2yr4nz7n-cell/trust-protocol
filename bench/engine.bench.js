import { bench, describe } from "vitest";
import { PRESETS, deriveRecord, check, recordJson, canonicalSubjectUrl, readManifestStructure } from "../engine.js";
import { checkFingerprint, attachChecks, checksJson } from "../fingerprint.js";
import { createTrustStore, pipeline, pipelineAndStore } from "../derivation.js";
import { CONTENT_HASH, fillPreset, hexOf, makeEvidence, makeManifestFile } from "./fixtures.js";

const OTHER_PARENT = hexOf(4242);
const presetInputs = Object.values(PRESETS).map(fillPreset);
const largeInput = {
  subject: { kind: "url", id: "https://example.org/gallery/hero-image-77" },
  issuer: "did:web:example.org",
  evidence: makeEvidence(500),
  content_hash: CONTENT_HASH,
  checked_at: "2026-10-08T12:00:00Z",
};
const largeRecord = (await check(largeInput)).record;
const manifestFile = (await makeManifestFile({ assetSize: 64 * 1024 })).bytes;

const urls = [
  "HTTPS://Example.org:443/pokemon/base-set/charizard-4-102?utm_source=x#top",
  "https://example.org/press/photo-1180",
  "http://EXAMPLE.org:80/feed/post-9001/",
  "https://example.org/news/photo-4711?b=2&a=1",
];

describe("engine", () => {
  bench("deriveRecord: all presets", () => {
    for (const input of presetInputs) deriveRecord(input);
  });

  bench("deriveRecord: 500 evidence items", () => {
    deriveRecord(largeInput);
  });

  bench("check + recordJson: all presets", async () => {
    for (const input of presetInputs) recordJson((await check(input)).record);
  });

  bench("recordJson: 500 evidence items", () => {
    recordJson(largeRecord);
  });

  bench("canonicalSubjectUrl", () => {
    for (const u of urls) canonicalSubjectUrl(u);
  });

  bench("readManifestStructure: 64 KiB JPEG", () => {
    readManifestStructure(manifestFile);
  });
});

describe("fingerprint", () => {
  const store = createTrustStore();
  store.store({ content_hash: OTHER_PARENT, origin: "verified", integrity: "intact" });
  const derivedInput = { ...largeInput, subject: { ...largeInput.subject, derived_from: [OTHER_PARENT, hexOf(9)] } };

  bench("checkFingerprint: 500 evidence items", () => {
    checkFingerprint(largeInput.evidence, CONTENT_HASH);
  });

  bench("attachChecks + checksJson: 500 evidence items", () => {
    checksJson(attachChecks(largeRecord, derivedInput, store));
  });
});

describe("derivation", () => {
  const scenarioInputs = presetInputs.map((input, i) => ({
    ...input,
    subject: { kind: "file", id: `scan-${i}`, derived_from: i > 0 ? [hexOf(i - 1)] : [] },
    content_hash: hexOf(i),
  }));

  bench("pipeline: 500 evidence items", () => {
    pipeline(largeInput, createTrustStore());
  });

  bench("pipelineAndStore: derivation chain over all presets", () => {
    const store = createTrustStore();
    for (const input of scenarioInputs) pipelineAndStore(input, store);
  });
});
