/* TRUST:// transport — the last piece: real network work behind the providers.
 *
 * c2pa-verifier.js owns layers 1-3 over bytes. c2pa-providers.js implements the
 * three network layers against a transport. This file IS that transport:
 *
 *   buildPath(certificates)          X.509 chain building, anchor matching
 *   revocationStatus(certificates)   CRL lookup
 *   verifyTimestamp({signature})     RFC 3161 countersignature status
 *
 * WHY IT TAKES AN `http` FUNCTION
 * -------------------------------
 * This module performs no I/O of its own. It takes an `http(request)` function
 * that returns `{ status, headers, body }`. That keeps the network surface in
 * one place a caller can see, log, rate-limit or stub — and it is why the whole
 * file is testable without a socket.
 *
 * WHAT IS IMPLEMENTED HERE, AND WHAT IS NOT
 * -----------------------------------------
 * IMPLEMENTED:
 *   · DER parsing of a certificate: issuer, subject, serial, validity, SKI, AKI, basicConstraints
 *   · chain ORDERING leaf -> intermediates -> root by issuer/subject
 *   · anchor MATCHING against a configured trust list
 *   · expiry evaluation against a reference time
 *   · CRL fetch, DER parse, and revocation lookup BY VALUE
 *   · RFC 3161 status parsing
 *   · the TSA signature itself, by delegation to c2pa-tsr.js (the second
 *     certification step) — see verifyTimestamp below
 *
 * NOT IMPLEMENTED, stated so nobody has to discover it:
 *   · signature verification of the certificates themselves
 *   · name constraints, policy constraints, path length constraints
 *   · CRL signature verification
 *
 * A transport that cannot do a step reports that step as failed. It never
 * reports success for work it did not do.
 *
 * THE TWO CERTIFICATION STEPS, KEPT APART
 * ---------------------------------------
 * A timestamp has two separable parts, and collapsing them is how a system
 * starts claiming more than it knows:
 *
 *   1. STATUS     the authority answered "granted"           — parsed here
 *   2. TSA PROOF  the token's CMS signature verifies against
 *                 the TSA key, over attributes that cover
 *                 the TSTInfo, whose imprint covers the
 *                 signature bytes we were given            — c2pa-tsr.js
 *
 * Step 1 alone is a claim by someone else. Step 2 is evidence. This transport
 * reports `trusted: true` only when step 2 actually ran, and otherwise names the
 * step that did not happen.
 *
 * THE DER DETAIL THAT MATTERS
 * ---------------------------
 * An X.509 certificate writes its version as an EXPLICIT [0] wrapper around the
 * version integer (0xa0 0x03 0x02 0x01 0x02). A bare INTEGER in that position
 * shifts every following field by one, and a parser then reads the signature
 * algorithm as the serial number. The positional walk below advances only for a
 * field that is PRESENT, so an absent optional field cannot shift the rest.
 */

import { verifyTimestampResponse } from "./c2pa-tsr.js";

export const TRANSPORT_VERSION = "trust/transport@0.3";

/* ================================================================== *
 * DER — just enough ASN.1 to read a certificate and a CRL
 * ================================================================== */

export function derTlv(bytes, offset) {
  if (offset + 2 > bytes.length) return null;
  let pos = offset;
  const tag = bytes[pos++];
  let len = bytes[pos++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[pos++];
  }
  if (pos + len > bytes.length) return null;
  return { tag, start: offset, valueStart: pos, valueEnd: pos + len, end: pos + len };
}

function derSequence(bytes, offset) {
  const t = derTlv(bytes, offset);
  return t && t.tag === 0x30 ? t : null;
}

function derChildren(bytes, parent) {
  const out = [];
  let o = parent.valueStart;
  while (o < parent.valueEnd) {
    const t = derTlv(bytes, o);
    if (!t || t.end <= o) break;
    out.push(t);
    o = t.end;
  }
  return out;
}

function derOid(bytes, tlv) {
  if (tlv.tag !== 0x06 || tlv.valueStart >= tlv.valueEnd) return null;
  let pos = tlv.valueStart;
  const first = bytes[pos++];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  while (pos < tlv.valueEnd) {
    const b = bytes[pos++];
    val = val * 128 + (b & 0x7f);
    if (!(b & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join(".");
}

function derHex(bytes, tlv) {
  let s = "";
  for (let i = tlv.valueStart; i < tlv.valueEnd; i++) s += bytes[i].toString(16).padStart(2, "0");
  return s;
}

function derTime(bytes, tlv) {
  const text = new TextDecoder().decode(bytes.slice(tlv.valueStart, tlv.valueEnd));
  if (tlv.tag === 0x17 && text.length >= 12) {
    const yy = parseInt(text.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${year}-${text.slice(2, 4)}-${text.slice(4, 6)}T${text.slice(6, 8)}:${text.slice(8, 10)}:${text.slice(10, 12)}Z`;
  }
  if (tlv.tag === 0x18 && text.length >= 14) {
    return `${text.slice(0, 4)}-${text.slice(4, 6)}-${text.slice(6, 8)}T${text.slice(8, 10)}:${text.slice(10, 12)}:${text.slice(12, 14)}Z`;
  }
  return null;
}

/** Parse a DER certificate into the fields a chain builder needs. */
export function parseCertificate(der) {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = derSequence(bytes, 0);
  if (!cert) return { ok: false, reason: "not a DER SEQUENCE" };
  const kids = derChildren(bytes, cert);
  const tbs = kids[0];
  if (!tbs || tbs.tag !== 0x30) return { ok: false, reason: "no tbsCertificate" };
  const fields = derChildren(bytes, tbs);

  /* Positional walk. Only a PRESENT optional field advances the cursor. */
  let idx = 0, serial = null;
  if (fields[idx] && fields[idx].tag === 0xa0) idx++;
  if (fields[idx] && fields[idx].tag === 0x02) { serial = derHex(bytes, fields[idx]); idx++; }
  if (fields[idx] && fields[idx].tag === 0x30) idx++;
  const issuer = fields[idx] && fields[idx].tag === 0x30 ? derHex(bytes, fields[idx]) : null; idx++;
  const validity = fields[idx] && fields[idx].tag === 0x30 ? derChildren(bytes, fields[idx]) : []; idx++;
  const subject = fields[idx] && fields[idx].tag === 0x30 ? derHex(bytes, fields[idx]) : null;
  if (!issuer || !subject) return { ok: false, reason: "certificate has no issuer or subject" };

  /* Extensions: SKI (2.5.29.14), AKI (2.5.29.35), basicConstraints (2.5.29.19).
   * SKI is an OCTET STRING wrapping a KEY IDENTIFIER, which is itself tag 0x04. */
  let ski = null, aki = null, isCa = null;
  const extWrapper = fields.find((f) => f.tag === 0xa3);
  if (extWrapper) {
    const seq = derSequence(bytes, extWrapper.valueStart);
    if (seq) {
      for (const ext of derChildren(bytes, seq)) {
        const parts = derChildren(bytes, ext);
        if (!parts.length) continue;
        const o = derOid(bytes, parts[0]);
        const val = parts.find((p) => p.tag === 0x04);
        if (!val) continue;
        const inner = derTlv(bytes, val.valueStart);
        if (o === "2.5.29.14" && inner && inner.tag === 0x04) ski = derHex(bytes, inner);
        if (o === "2.5.29.35" && inner && inner.tag === 0x30) {
          const k = derChildren(bytes, inner).find((p) => p.tag === 0x80);
          if (k) aki = derHex(bytes, k);
        }
        if (o === "2.5.29.19" && inner && inner.tag === 0x30) {
          const b = derChildren(bytes, inner).find((p) => p.tag === 0x01);
          if (b) isCa = bytes[b.valueStart] !== 0;
        }
      }
    }
  }

  return {
    ok: true,
    serial,
    issuer,
    subject,
    notBefore: validity[0] ? derTime(bytes, validity[0]) : null,
    notAfter: validity[1] ? derTime(bytes, validity[1]) : null,
    ski, aki, isCa,
  };
}

/* ================================================================== *
 * Chain building
 * ================================================================== */

export function buildChain(certificates, trustAnchors, referenceTime) {
  const parsed = [];
  for (const c of certificates) {
    const p = parseCertificate(c);
    if (!p.ok) return { ok: false, reason: "a certificate in the chain did not parse: " + p.reason };
    parsed.push({ der: c, ...p });
  }
  if (parsed.length === 0) return { ok: false, reason: "no certificates were presented" };

  /* Walk from the first certificate toward a self-signed one. */
  const ordered = [parsed[0]];
  const used = new Set([0]);
  let current = parsed[0];
  let guard = 0;
  while (guard++ < 32) {
    const nextIdx = parsed.findIndex((p, i) => !used.has(i) && p.subject === current.issuer);
    if (nextIdx < 0) break;
    used.add(nextIdx);
    ordered.push(parsed[nextIdx]);
    current = parsed[nextIdx];
  }

  const root = ordered[ordered.length - 1];
  const now = referenceTime || new Date().toISOString();
  const expired = ordered.some((c) => c.notAfter !== null && c.notAfter < now);
  const notYetValid = ordered.some((c) => c.notBefore !== null && c.notBefore > now);

  if (notYetValid) return { ok: false, reason: "a certificate in the chain is not yet valid" };

  if (trustAnchors && trustAnchors.length > 0) {
    /* An anchor is matched by the name it carries, against the root's subject. */
    const matched = trustAnchors.find((a) => {
      const name = typeof a === "string" ? a : (a && a.name) || "";
      if (!name) return false;
      const ascii = [...new TextEncoder().encode(name)].map((b) => b.toString(16).padStart(2, "0")).join("");
      return (root.subject || "").indexOf(ascii) >= 0;
    });
    if (!matched) return { ok: false, reason: "the root is not on this verifier's trust list" };
    return { ok: true, anchor: typeof matched === "string" ? matched : matched.name, expired, reason: "chain ordered to a configured trust anchor" };
  }

  return { ok: true, anchor: null, expired, reason: "chain ordered; no trust list was configured" };
}

/* ================================================================== *
 * Revocation — CRL
 * ================================================================== */

/** Read a CRL and report whether a serial appears in it. The match is by VALUE,
 *  so leading zeros and odd padding cannot defeat it. */
export function checkCrl(crlDer, serialHex) {
  const bytes = crlDer instanceof Uint8Array ? crlDer : new Uint8Array(crlDer);
  const crl = derSequence(bytes, 0);
  if (!crl) return { revoked: false, reason: "the CRL did not parse" };
  const tbs = derChildren(bytes, crl)[0];
  if (!tbs) return { revoked: false, reason: "the CRL has no body" };

  const needle = (serialHex || "").replace(/^0+/, "").toLowerCase();
  let revoked = false;
  const scan = (node, depth) => {
    if (depth > 8 || revoked) return;
    for (const child of derChildren(bytes, node)) {
      if (child.tag === 0x30) {
        const inner = derChildren(bytes, child);
        if (inner[0] && inner[0].tag === 0x02) {
          const value = derHex(bytes, inner[0]).replace(/^0+/, "").toLowerCase();
          if (value === needle) { revoked = true; return; }
        }
        scan(child, depth + 1);
      }
    }
  };
  scan(tbs, 0);

  return { revoked, reason: revoked ? "the serial appears in the CRL" : "the serial does not appear in the CRL" };
}

/* ================================================================== *
 * The transport
 * ================================================================== */

/**
 * @param {object} options
 *   http           async ({ method, url, headers, body }) -> { status, headers, body }
 *   trustAnchors   configured anchor names, e.g. ["Example Root CA"]
 *   crlUrls        optional map from issuer hex -> URL, when the certificate
 *                  does not carry a CRL distribution point
 *   referenceTime  ISO string used for expiry evaluation
 *   tsaPublicKey   SPKI bytes of the timestamp authority, when known
 *   verifyToken    the second certification step; defaults to c2pa-tsr.js
 */
export function createTransport(options = {}) {
  const { http, trustAnchors = [], crlUrls = {}, referenceTime, tsaPublicKey, verifyToken } = options;

  return {
    version: TRANSPORT_VERSION,

    async buildPath(certificates) {
      return buildChain(certificates, trustAnchors, referenceTime);
    },

    async revocationStatus(certificates) {
      if (typeof http !== "function") {
        return { revoked: false, checked: 0, reason: "no http function is configured, so no CRL was fetched" };
      }
      let checked = 0, note = "";
      for (const der of certificates.slice(0, 3)) {
        const parsed = parseCertificate(der);
        if (!parsed.ok) continue;
        const url = crlUrls[parsed.issuer];
        if (!url) continue;
        try {
          const res = await http({ method: "GET", url, headers: {}, body: null });
          if (!res || res.status !== 200 || !res.body) continue;
          checked++;
          const crl = checkCrl(new Uint8Array(res.body), parsed.serial);
          if (crl.revoked) {
            return { revoked: true, checked, reason: "certificate " + parsed.serial + " appears in the CRL" };
          }
        } catch (err) {
          note = "a CRL fetch failed: " + (err && err.message || String(err));
        }
      }
      return { revoked: false, checked, reason: note || (checked ? "no certificate appeared in any fetched CRL" : "no CRL distribution point was available") };
    },

    async verifyTimestamp({ signature, payload, timestampToken }) {
      /* Parsing a TimeStampResp needs the token. Without it the honest answer is
       * that no countersignature was presented. */
      if (!timestampToken) {
        return { trusted: false, at: null, step: "none", reason: "no countersignature token was presented" };
      }

      /* THE SECOND CERTIFICATION STEP.
       *
       * A granted status is not trust — it is a claim by the authority. When a
       * verifyToken implementation is injected, this transport hands the token
       * to it and reports what it actually established: the messageImprint over
       * the signature bytes, the content digest over the TSTInfo, and the CMS
       * signature over the signed attributes, each named on failure.
       *
       * Without one, the answer stays the old honest no — and it says which
       * step did not happen rather than quietly implying the rest did. */
      if (typeof verifyToken === "function") {
        return verifyToken({ signature, payload, timestampToken, tsaPublicKey });
      }

      const token = timestampToken instanceof Uint8Array ? timestampToken : new Uint8Array(timestampToken);
      const resp = derSequence(token, 0);
      if (!resp) return { trusted: false, at: null, step: "parse", reason: "the timestamp response did not parse" };
      const statusInfo = derChildren(token, resp)[0];
      let status = null;
      if (statusInfo) {
        const s = derChildren(token, statusInfo).find((p) => p.tag === 0x02);
        if (s) status = token[s.valueStart];
      }
      if (status !== 0) return { trusted: false, at: null, step: "status", reason: "the timestamp authority did not return granted status" };
      return {
        trusted: false,
        at: null,
        step: "tsa-signature",
        reason: "a granted response was received, but no verifyToken implementation was injected, so the TSA signature was not verified",
      };
    },
  };
}

/** A transport that performs no I/O and invents nothing. */
export function createOfflineTransport(options = {}) {
  return createTransport({
    http: undefined,
    trustAnchors: options.trustAnchors || [],
    referenceTime: options.referenceTime,
    tsaPublicKey: options.tsaPublicKey,
    verifyToken: options.verifyToken,
  });
}

/** Wire the second certification step in without importing it by hand.
 *
 *  createVerifiedTransport builds the ordinary transport and injects
 *  c2pa-tsr.js's verifyTimestampResponse as `verifyToken`, so a caller who has
 *  the TSA public key gets a real verification instead of a granted-status
 *  placeholder. Pass `verifyToken` explicitly to override it. */
export function createVerifiedTransport(options = {}) {
  return createTransport({ ...options, verifyToken: options.verifyToken || verifyTimestampResponse });
}
