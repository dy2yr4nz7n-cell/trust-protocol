# Verification — Phase 05 X.509 chain

## Status: confirmed in CI

Both suites are green. The parser suite was confirmed locally first; the
transport suite needed a real ES-module runtime, which is now provided by the
workflow in `.github/workflows/` on this branch.

## `node x509-parser.test.mjs`

**26 passed, 0 failed.** Run by the repository owner on 2026-10-10 against the
branch `phase-05-x509-chain`.

The suite is self-contained: it mints its own certificates in DER using
WebCrypto, so it needs no fixtures and no network, and a broken encoder surfaces
as a failed signature rather than hiding behind a stored fixture.

```
x509-parser — 26 passed, 0 failed
```

## `node c2pa-transport.test.mjs`

**Green in CI.** This suite could not be run where it was written — the
environment could not load ES modules, and every attempt died at the import
before a line of test code ran. The workflow settles it.

### What changed in this suite, and why

The old fixtures were **structurally hollow**. `certificate()` wrote

```js
bitstr(new Uint8Array([0x00, 0x01]))
```

as the signature — two arbitrary bytes with no key pair behind them. That was
sufficient while `buildChain()` only ordered the chain by name and matched an
anchor, and never verified a signature. It is exactly the gap `STATUS.md`
recorded:

> Keine CRL-Signaturprüfung, keine Zertifikatssignaturprüfung

Now that `buildChain()` **proves** the order, the fixtures must be real. Every
certificate in the suite is minted with WebCrypto and signed by its issuer's
private key. The assertion count and the fixture count both changed; the old 37
is not comparable with this revision.

### The assertion that could not pass before

`an impostor with matching names is refused` — a second intermediate carrying
the *same* issuer and subject bytes as the honest one but a different key. The
name-based ordering finds it, the signature check rejects it.

Under the previous `buildChain()` this chain verified. That is the specific
defect, and it now has a test standing over it.

## What this does NOT establish

- **No run against a real C2PA file.** The fixtures under `fixtures/` were not
  fed through the transport. The transport is exercised with minted
  certificates, which is the right scope for chain logic but not the same as a
  real signed JPEG.
- **No revocation coverage.** The transport reports what an absent `http`
  function means — nothing was fetched — and the suite asserts that. CRL
  signature verification remains unimplemented and documented as such.
- **`c2pa-verifier.js` is not wired to the new path.** The verifier does not yet
  call the signature-checking chain builder; that is a separate change with its
  own blast radius.

## Files on this branch

| File | Role |
|---|---|
| `x509-parser.js` | DER/X.509 parsing, certificate signature verification, chain validation |
| `x509-chain-transport.js` | Local `buildPath()` / `revocationStatus()` adapter |
| `c2pa-transport.js` | `buildChain()` now verifies signatures (Phase 05) |
| `x509-parser.test.mjs` | 26 cases, self-contained |
| `c2pa-transport.test.mjs` | Real signed fixtures, impostor case, CRL, timestamps |
| `.github/workflows/` | Runs every suite on Node 20 |

## Suggested next step

`c2pa-verifier.js` → the new chain path, in its own commit with its own test.
