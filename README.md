# TRUST Protocol Unified

Unified reference application for TRUST Record 0.2, X.509 validation, and C2PA manifest inspection.

> Status: scaffold in progress. This repository does not yet contain a complete verified integration. Never treat package availability, placeholder analysis, or a displayed UI badge as verification.

## Architecture

- `apps/api-go`: HTTPS/API boundary, input limits, X.509 chain validation, orchestration.
- `packages/trust-protocol-js`: TRUST record and verdict derivation; keep it aligned with `dy2yr4nz7n-cell/trust-protocol` and its test vectors.
- `packages/c2pa-python-adapter`: narrow adapter around the official `c2pa-python` Reader. A real check must open the submitted media file, read manifest JSON and validation state/results, and report unavailable/absent/invalid/valid distinctly.
- `packages/forensic-signals`: optional research-only heuristics. It must not upgrade a cryptographic verdict.
- `apps/web`: display of server-returned evidence and provenance; never hard-code a green success state.

The Go service validates certificate chains. C2PA checks media manifests. They are separate evidence domains; passing one must not imply passing the other. The combined verdict should be `verified` only when the explicit policy's required cryptographic checks succeed.

## Current upstreams to reconcile

- TRUST JS reference: `https://github.com/dy2yr4nz7n-cell/trust-protocol`
- Go/X.509 service: `https://github.com/dy2yr4nz7n-cell/trust-protocol-monorepo`
- Python binding: `https://github.com/dy2yr4nz7n-cell/c2pa-python` (fork of `contentauth/c2pa-python`)
- Native C2PA SDK: `https://github.com/contentauth/c2pa-rs`

Keep upstream license notices and attribution when importing code. Do not copy the C2PA binding wholesale; depend on its package/API and document the native runtime requirement.

## Real C2PA Python API

The supported approach is to use `c2pa.Reader` on the actual media path (or a stream), then inspect the Reader's manifest JSON and validation outputs. The binding version checked during planning exposes `Reader.json()`, `Reader.detailed_json()`, `Reader.get_validation_state()`, and `Reader.get_validation_results()`. Do not infer that a manifest is valid merely because `import c2pa` succeeds. Test the exact pinned `c2pa-python` release and native library together.

Example API usage (in the Python process that has `c2pa-python` installed):

```python
import json
import c2pa

with c2pa.Reader(asset_path) as reader:
    manifest_store = json.loads(reader.json())
    validation_state = reader.get_validation_state()
    validation_results = reader.get_validation_results()
```

Treat the returned validation fields according to the pinned SDK version and explicit trust-anchor settings. A parseable manifest alone is not proof of a trusted signer.

## Branch and commit plan

Use one integration branch at a time; don't create permanent branches per language or service.

1. `feature/contracts-and-ci`: API schema, lint/test workflows, input limits, baseline docs.
2. `feature/trust-x509`: port/adapt Go trust logic and add deterministic certificate-chain tests.
3. `feature/c2pa-reader`: implement the Python Reader adapter against an explicit pinned SDK version; test absent manifest, malformed media, valid fixture, and invalid validation results.
4. `feature/trust-record-mapping`: import/align TRUST JS engine and vectors, preserve upstream tests, map actual C2PA outputs to evidence without upgrading unknown to valid.
5. `feature/api-orchestration`: upload/path handling, safe temporary files, timeout/size limits, combined verdict, endpoint tests.
6. `feature/dashboard`: render actual API results and unknown/unavailable states; no prefilled verified badge.
7. Merge in that order to `main`; tag a release only after full CI and real fixtures pass.

For this Copilot task, the working branch is `copilot/unify-real-c2pa-api`.

## Local workflow

Requirements: Go 1.22+, Node.js 20+, Python 3.10+, and the platform-compatible native C2PA library required by the selected `c2pa-python` release. Docker support is not ready until an image installs a compatible native runtime and is covered by CI.

```bash
git clone https://github.com/dy2yr4nz7n-cell/trust-protocol-unified.git
cd trust-protocol-unified
git switch copilot/unify-real-c2pa-api
```

Once each component has been implemented, use its own tests before combined checks:

```bash
(cd apps/api-go && go test ./...)
(cd packages/trust-protocol-js && npm test)
(cd packages/c2pa-python-adapter && python -m pytest)
```

Do not start the service or rely on the UI until the API's request contract, C2PA adapter, and integration tests exist. Do not post private media to an untrusted service.

## Required API behavior before claiming completion

- Accept an uploaded asset rather than an arbitrary server filesystem path.
- Enforce body/file size limits and request timeouts; clean temporary files.
- Make C2PA result states explicit: `not_requested`, `unavailable`, `manifest_absent`, `invalid`, `valid`.
- Return the manifest validation state/results and adapter version/source, with sensitive content omitted by default.
- X.509 endpoints validate a certificate chain using configured roots and hostname policy; certificate serial-only checks are insufficient for revocation.
- Forensics is `not_evaluated` unless a real, documented model is configured. Any model output remains informational.
- Use `unknown` when required evidence is absent or unavailable. Never turn missing checks into success.

## Security and truthfulness

No fake DLT revocation results, fake AI scores, synthetic trust claims, or hard-coded success badges. A timestamp supplied by a client is an assertion, not trusted timestamp evidence. C2PA signer trust requires correctly configured trust anchors and SDK validation—not simply a valid signature or parsed manifest.
