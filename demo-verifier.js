/* TRUST:// demo verifier — same interface as signature.js, table-backed.
 * Kept separate from the module so the demo page can run without a network
 * while still exercising the REAL policy layer.
 *
 * A production verifier implements this interface with a CBOR/COSE parser,
 * X.509 chain building, CRL/OCSP and RFC 3161. Everything downstream of this
 * file is identical either way — which is the whole point of the split.
 */

export function createDemoVerifier(table = {}) {
  return {
    kind: "demo",
    async verify(evidence) {
      const entry = table[evidence?.id] ?? table[evidence?.content_hash] ?? table[evidence?.label];
      if (!entry) {
        return {
          state: "unknown",
          chain: "unavailable",
          anchor: null,
          signer: null,
          issued_at: null,
          timestamp: null,
          reason: "no verification result is available for this evidence",
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
        reason: entry.reason ?? "reported by the demo verifier",
        errors: entry.errors ?? [],
      };
    },
  };
}

/** The demo's verification results, keyed by attestation id.
 *  Deliberately includes one good case, one expired chain, one unknown anchor
 *  and one missing entry, so switching the trust policy visibly changes the
 *  verdict on the SAME record. */
export const DEMO_VERIFICATIONS = {
  "urn:c2pa:9f2c": {
    state: "verified", chain: "intact", anchor: "Example Root CA",
    signer: "did:web:example.org", issued_at: "2026-09-30T08:12:00Z",
    timestamp: { trusted: true, at: "2026-09-30T08:12:01Z" },
  },
  "urn:c2pa:aa10": {
    state: "verified", chain: "intact", anchor: "Example Root CA",
    signer: "did:web:example.org", issued_at: "2026-10-02T09:00:00Z",
    timestamp: { trusted: true, at: "2026-10-02T09:00:02Z" },
  },
  "urn:c2pa:bb21": {
    state: "verified", chain: "expired", anchor: "Example Root CA",
    signer: "did:web:example.org", issued_at: "2024-02-01T00:00:00Z",
  },
  "urn:c2pa:c0de": {
    state: "verified", chain: "intact", anchor: "Rogue Issuer",
    signer: "did:web:rogue.example", issued_at: "2026-10-03T11:20:00Z",
  },
  "urn:c2pa:b0a1": {
    state: "invalid", chain: "unavailable", anchor: null,
    reason: "the signature does not match the payload",
  },
};

export const DEMO_POLICIES = {
  strict: {
    label: "Streng — Trust-Liste erzwungen, abgelaufene Ketten abgelehnt",
    config: (trust) => ({
      trustList: trust(["Example Root CA"]),
      allowExpiredChain: false,
      requireTrustedTimestamp: true,
      treatUnknownAsInvalid: false,
    }),
  },
  open: {
    label: "Offen — Trust-Liste aktiv, abgelaufene Ketten akzeptiert",
    config: (trust) => ({
      trustList: trust(["Example Root CA"]),
      allowExpiredChain: true,
      requireTrustedTimestamp: false,
      treatUnknownAsInvalid: false,
    }),
  },
  none: {
    label: "Ohne Trust-Liste — nimmt, was der Verifier meldet",
    config: (trust) => ({
      trustList: trust([]),
      allowExpiredChain: false,
      requireTrustedTimestamp: false,
      treatUnknownAsInvalid: false,
    }),
  },
  paranoid: {
    label: "Paranoid — Unbestimmtes gilt als Fehler",
    config: (trust) => ({
      trustList: trust(["Example Root CA"]),
      allowExpiredChain: false,
      requireTrustedTimestamp: true,
      treatUnknownAsInvalid: true,
    }),
  },
};
