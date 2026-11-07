# Proto Trust Protocol v12.0

Mobile-friendly web application for file fingerprinting, selected metadata extraction, C2PA inspection and an SQLite audit history.

## What it does
- Uploads one JPEG, PNG, WebP, TIFF, MP4 or PDF (25 MB maximum).
- Detects the actual file type from its bytes; it does not trust the extension or supplied MIME type.
- Calculates SHA-256 over the uploaded bytes.
- Extracts a small set of supported EXIF fields from images.
- Calls the official `c2patool` executable when it is installed on the server.
- Stores a JSON report and audit metadata in SQLite. The uploaded original is held in memory and is not stored by the app.
- Exports reports as JSON.

## Important limitations
This is a practical prototype, not a certified forensic laboratory system. It does not decide whether depicted events are true, does not provide AI/deepfake detection, does not guarantee chain of custody, and does not cryptographically seal the audit database. Missing C2PA data is not evidence of manipulation. A valid C2PA signature is not proof that the content is truthful.

If `c2patool` is not installed, the app explicitly reports `ENGINE_MISSING`; it never fabricates a successful C2PA result. C2PA output schemas and validation details can differ by c2patool release. The UI therefore preserves the raw parsed manifest in the exported report and uses conservative status labels.

## Requirements
- Node.js 18 or newer
- npm
- Optional but recommended: official C2PA `c2patool` installed on the same server and available on `PATH`.

Official c2patool documentation: https://opensource.contentauthenticity.org/docs/c2patool/

## Run locally
```bash
npm install
npm start
```
Open `http://localhost:3000`.

To use a non-standard executable path:
```bash
C2PATOOL_PATH=/absolute/path/to/c2patool npm start
```

To store the SQLite database outside the project directory:
```bash
DATA_DIR=/persistent/path npm start
```

## Deployment / iPhone use
An iPhone can open the app in Safari once this Node.js server is deployed to a reachable HTTPS host. The ZIP itself is source code, not a hosted website and not an iOS app. Deploy the project to a Node.js host with persistent disk storage; set `DATA_DIR` to that persistent location. Install `c2patool` in the host environment if real C2PA validation is required. Without it, the rest of the inspection works but C2PA is clearly marked unavailable.

## API
- `GET /api/health` – server and c2patool status
- `POST /api/verify` – multipart form upload with field name `file`
- `GET /api/audits` – last 100 audit records
- `GET /api/audits/:id` – full report
- `GET /api/audits/:id/export` – downloadable JSON report

## Privacy and security notes
- Do not expose this prototype publicly without adding authentication, rate limiting, request logging controls, CSRF/origin protections appropriate to your deployment, and operational monitoring.
- Uploads are processed in memory and a temporary file is created only while calling c2patool; that temporary directory is removed afterward.
- Reports contain the original filename, file hash, extracted metadata and C2PA report. Consider whether those details are sensitive before sharing exports.
- SQLite audit rows are not tamper-proof. A production evidence system needs signed/append-only audit storage and a documented evidence-handling procedure.
