# Verification — Phase 05 X.509 chain

## `node x509-parser.test.mjs`

**26 passed, 0 failed.** Run by the repository owner on 2026-10-10, against the
branch `phase-05-x509-chain`.

The suite is self-contained: it mints its own certificates in DER using
WebCrypto, so it needs no fixtures and no network, and a broken encoder surfaces
as a failed signature rather than hiding behind a stored fixture.

```
x509-parser — 26 passed, 0 failed
```

## What that covers

| Area | Tests |
|---|---|
| Parsing (structure, DNs, TBS bytes, curves, SPKI, extensions) | 7 |
| Malformed input (empty, truncated, wrong outer tag, junk) | 4 |
| Validity windows | 1 |
| Signature verification (self-signed, tampered TBS, wrong key, unsupported alg, expired) | 5 |
| Chain validation (two-link, wrong issuer, no anchors, expiry, shared-name impostor) | 5 |
| Transport adapter (valid path, fail-closed, revocation honesty, expiry, describe) | 5 |

## What it does NOT establish

- **No run against this repository's existing suite.** These three files are
  additive and `c2pa-verifier.js` was not touched, so the existing tests should
  be unaffected — but "should be" is not "was".
- **No run against a real C2PA file.** The fixtures under `fixtures/` were not
  fed through the new transport.
- **No revocation coverage.** `revocationStatus()` reports `checked: false` by
  design. That is not a gap in this branch so much as the honest edge of what is
  checkable offline.

## Suggested next step

```bash
node x509-parser.test.mjs   # this branch
npm test                     # the existing suite, unchanged
```

If an engine- or signature-level path expects a chain provider, the adapter
belongs at that seam — see `x509-chain-transport.js` for the contract.
