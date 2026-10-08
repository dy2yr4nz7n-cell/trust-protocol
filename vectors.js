/* TRUST:// test vectors — Record Format 0.2
 * One vector per status, plus the generation axis as a fourth field.
 * The conformance runner fills "<BERECHNET>" and "<ANDERER HASH>" with real
 * SHA-256 hex values, so a fixture never carries a stale hash.
 */

export const vectors = [
  { id: "verified", expect: { verdict: "VERIFIED", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", issued_at: "2026-09-30T08:12:00Z" },
    ] },

  { id: "authenticated", expect: { verdict: "AUTHENTICATED", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", identity_proof: true, issued_at: "2026-09-30T08:12:00Z" },
    ] },

  { id: "machine-signed", expect: { verdict: "VERIFIED", generation: "attested_by_signer" },
    subject: { kind: "url", id: "https://example.org/gallery/hero-image-77" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:aa10", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", generation: { kind: "trainedAlgorithmicMedia" }, issued_at: "2026-10-02T09:00:00Z" },
    ] },

  { id: "captured-signed", expect: { verdict: "VERIFIED", generation: "attested_by_signer" },
    subject: { kind: "url", id: "https://example.org/press/photo-1180" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:bb21", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", generation: { kind: "digitalCapture" }, issued_at: "2026-10-02T09:00:00Z" },
    ] },

  { id: "machine-rumour", expect: { verdict: "CLAIMED", generation: "asserted" },
    subject: { kind: "url", id: "https://example.org/feed/post-9001" },
    issuer: null, checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "some-forum-post", issued_at: "2026-10-05T14:22:00Z" },
    ] },

  { id: "detector-claim", expect: { verdict: "CLAIMED", generation: "asserted" },
    subject: { kind: "url", id: "https://example.org/news/photo-4711" },
    issuer: null, checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship", issued_at: "2026-10-01T10:00:00Z" },
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "detector-v3", confidence: 0.87, issued_at: "2026-10-06T08:00:00Z" },
    ] },

  { id: "claim-plus-signer", expect: { verdict: "VERIFIED", generation: "asserted" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<BERECHNET>", issued_at: "2026-09-30T08:12:00Z" },
      { kind: "generation_claim", generation_kind: "trainedAlgorithmicMedia", source: "forum", issued_at: "2026-10-05T14:22:00Z" },
    ] },

  { id: "assertion-only", expect: { verdict: "CLAIMED", generation: "none" },
    subject: { kind: "url", id: "https://example.org/news/photo-4711" },
    issuer: null, checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "assertion", id: "urn:claim:4711", label: "Publisher states authorship", issued_at: "2026-10-01T10:00:00Z" },
    ] },

  { id: "modified", expect: { verdict: "MODIFIED", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<ANDERER HASH>", issued_at: "2026-09-30T08:12:00Z" },
    ] },

  { id: "machine-modified", expect: { verdict: "MODIFIED", generation: "attested_by_signer" },
    subject: { kind: "url", id: "https://example.org/gallery/hero-image-77" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:aa10", label: "C2PA manifest", state: "valid", chain: "intact", content_hash: "<ANDERER HASH>", generation: { kind: "trainedAlgorithmicMedia" }, issued_at: "2026-10-02T09:00:00Z" },
    ] },

  { id: "contradiction", expect: { verdict: "INVALID", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:9f2c", label: "C2PA manifest A", state: "valid", chain: "intact", content_hash: "<BERECHNET>", issued_at: "2026-09-30T08:12:00Z" },
      { kind: "attestation", id: "urn:c2pa:aa11", label: "C2PA manifest B", state: "valid", chain: "intact", content_hash: "<ANDERER HASH>", issued_at: "2026-09-29T11:03:00Z" },
    ] },

  { id: "invalid-signature", expect: { verdict: "INVALID", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:unknown.example", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:b0a1", label: "C2PA manifest", state: "invalid", chain: "unavailable", content_hash: "<BERECHNET>", issued_at: "2026-09-28T19:44:00Z" },
    ] },

  { id: "expired-chain", expect: { verdict: "INVALID", generation: "none" },
    subject: { kind: "url", id: "https://example.org/pokemon/base-set/charizard-4-102" },
    issuer: "did:web:example.org", checked_at: "2026-10-08T12:00:00Z",
    evidence: [
      { kind: "attestation", id: "urn:c2pa:7711", label: "C2PA manifest", state: "invalid", chain: "expired", content_hash: "<BERECHNET>", issued_at: "2024-02-01T00:00:00Z" },
    ] },

  { id: "unknown", expect: { verdict: "UNKNOWN", generation: "none" },
    subject: { kind: "url", id: "https://example.org/unknown/asset-99" },
    issuer: null, checked_at: "2026-10-08T12:00:00Z",
    evidence: [] },
];
