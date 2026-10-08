/* TRUST:// C2PA verifier PROVIDERS — the three network layers, implemented.
 *
 * The verifier (c2pa-verifier.js) owns layers 1-3 over bytes and leaves layers
 * 4-6 to injected providers. This file implements those providers against a
 * compliant C2PA validator, so the whole chain runs on real files.
 *
 * WHAT EACH PROVIDER OWNS
 * -----------------------
 *   crypto     the COSE_Sign1 signature over the Sig_structure
 *   chain      the X.509 path to a trust anchor, plus revocation
 *   timestamp  the RFC 3161 countersignature over the signature bytes
 *
 * NONE OF THEM CAN BE DONE OFFLINE, and that is the honest boundary: chain
 * building needs a trust store, revocation needs CRL/OCSP, timestamping needs an
 * authority. Each provider takes a transport and fails closed — an absent or
 * throwing transport yields `unknown`, never `verified`.
 *
 * THE SIG_STRUCTURE IS WHAT COSE ACTUALLY SIGNS
 * ---------------------------------------------
 * It is not "hash the payload and verify". COSE signs a CBOR array of four
 * things:
 *
 *   ["Signature1", body_protected, external_aad, payload]
 *
 * so the signature is over the ENCODED array. Getting this wrong is the single
 * most common reason a real C2PA file fails to verify.
 */

export const PROVIDER_VERSION = "trust/c2pa-providers@0.2";

/** COSE algorithm identifiers this profile hands to WebCrypto.
 *  WebCrypto verifies ECDSA as raw r||s, which is what COSE uses, so one path
 *  covers ECDSA and RSA PKCS#1 v1.5 without DER unwrapping. */
export const ALGORITHMS = {
  "-7": { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256", cose: "ES256" },
  "-35": { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384", cose: "ES384" },
  "-36": { name: "ECDSA", namedCurve: "P-521", hash: "SHA-512", cose: "ES512" },
  "-257": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", cose: "RS256" },
  "-258": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384", cose: "RS384" },
  "-259": { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512", cose: "RS512" },
};

/* ------------------------------------------------------------------ *
 * Sig_structure
 * ------------------------------------------------------------------ */

function encodeCborArray(parts) {
  const head = new Uint8Array([0x80 | parts.length]);
  let total = head.length;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  out.set(head, 0);
  let o = head.length;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

function encodeCborBytes(bytes) {
  const n = bytes.length;
  let head;
  if (n < 24) head = new Uint8Array([0x40 | n]);
  else if (n < 256) head = new Uint8Array([0x58, n]);
  else if (n < 65536) head = new Uint8Array([0x59, (n >> 8) & 0xff, n & 0xff]);
  else head = new Uint8Array([0x5a, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  const out = new Uint8Array(head.length + n);
  out.set(head, 0);
  out.set(bytes, head.length);
  return out;
}

function encodeCborText(str) {
  const bytes = new TextEncoder().encode(str);
  const out = encodeCborBytes(bytes);
  out[0] = 0x60 | bytes.length;
  return out;
}

/** Sig_structure for COSE_Sign1:
 *  ["Signature1", body_protected, external_aad, payload] */
export function buildSigStructure(protectedBytes, payloadBytes, externalAad) {
  const aad = externalAad instanceof Uint8Array ? externalAad : new Uint8Array(0);
  return encodeCborArray([
    encodeCborText("Signature1"),
    encodeCborBytes(protectedBytes instanceof Uint8Array ? protectedBytes : new Uint8Array(0)),
    encodeCborBytes(aad),
    encodeCborBytes(payloadBytes instanceof Uint8Array ? payloadBytes : new Uint8Array(0)),
  ]);
}

/* ------------------------------------------------------------------ *
 * crypto provider — the COSE signature
 * ------------------------------------------------------------------ *
 * Reads the leaf certificate from the x5chain, imports its public key through
 * WebCrypto and verifies the signature over the Sig_structure.
 *
 * Extracting a public key FROM a certificate is the platform's job. When that is
 * unavailable the honest answer is that we could not check — not that the
 * signature is bad.
 */

export function createCryptoProvider(options = {}) {
  const subtle = options.subtle || globalThis.crypto?.subtle;

  return async function cryptoProvider({ protectedBytes, payload, signature, alg, certificates }) {
    if (!subtle) return { ok: false, reason: "no WebCrypto implementation is available" };
    if (!signature || signature.length === 0) return { ok: false, reason: "the COSE structure carries no signature" };
    if (!certificates || certificates.length === 0) return { ok: false, reason: "no certificate is available to verify against" };

    const spec = ALGORITHMS[String(alg)];
    if (!spec) return { ok: false, reason: "unsupported COSE algorithm " + String(alg) };

    let key;
    try {
      key = await subtle.importKey("spki", certificates[0], { name: spec.name, namedCurve: spec.namedCurve, hash: spec.hash }, false, ["verify"]);
    } catch (err) {
      return { ok: false, reason: "the leaf certificate did not yield an importable public key: " + (err?.message ?? String(err)) };
    }

    const sigStructure = buildSigStructure(protectedBytes, payload, new Uint8Array(0));
    try {
      const ok = await subtle.verify({ name: spec.name, hash: spec.hash }, key, signature, sigStructure);
      return { ok, reason: ok ? "signature verified over the Sig_structure" : "signature does not hold over the Sig_structure" };
    } catch (err) {
      return { ok: false, reason: "signature verification failed: " + (err?.message ?? String(err)) };
    }
  };
}

/* ------------------------------------------------------------------ *
 * chain provider — the X.509 path
 * ------------------------------------------------------------------ *
 * Path building, trust-anchor matching and revocation are network work. The
 * provider takes a `transport` with two calls and never invents an answer:
 *
 *   transport.buildPath(certificates)         -> { ok, anchor, expired, reason? }
 *   transport.revocationStatus(certificates)  -> { revoked, reason? }
 *
 * A transport that throws, or one that is absent, yields ok: false — which the
 * verifier reports as `unavailable` and policy then decides about.
 */

export function createChainProvider(options = {}) {
  const transport = options.transport;
  const requireRevocationCheck = options.requireRevocationCheck === true;

  return async function chainProvider({ certificates }) {
    if (typeof transport?.buildPath !== "function") {
      return { ok: false, reason: "no transport: the X.509 path was not built" };
    }

    let path;
    try {
      path = await transport.buildPath(certificates);
    } catch (err) {
      return { ok: false, reason: "path building threw: " + (err?.message ?? String(err)) };
    }
    if (!path || !path.ok) {
      return { ok: false, reason: (path && path.reason) || "no path to a trust anchor could be built" };
    }

    /* Revocation is a separate question from validity, and a separate call. */
    let revoked = false;
    if (typeof transport.revocationStatus === "function") {
      try {
        const r = await transport.revocationStatus(certificates);
        revoked = Boolean(r && r.revoked);
        if (revoked) return { ok: false, anchor: path.anchor ?? null, expired: Boolean(path.expired), reason: "a certificate in the path is revoked" };
      } catch (err) {
        if (requireRevocationCheck) {
          return { ok: false, anchor: path.anchor ?? null, expired: Boolean(path.expired), reason: "revocation could not be determined: " + (err?.message ?? String(err)) };
        }
      }
    } else if (requireRevocationCheck) {
      return { ok: false, anchor: path.anchor ?? null, expired: Boolean(path.expired), reason: "policy requires a revocation check and no revocation source is configured" };
    }

    return {
      ok: true,
      anchor: path.anchor ?? null,
      expired: Boolean(path.expired),
      reason: path.reason || "chain built to a trust anchor",
    };
  };
}

/* ------------------------------------------------------------------ *
 * timestamp provider — RFC 3161
 * ------------------------------------------------------------------ */

export function createTimestampProvider(options = {}) {
  const transport = options.transport;

  return async function timestampProvider({ signature, payload }) {
    if (typeof transport?.verifyTimestamp !== "function") {
      return { trusted: false, at: null, reason: "no transport: no timestamp authority was consulted" };
    }
    try {
      const r = await transport.verifyTimestamp({ signature, payload });
      if (!r) return { trusted: false, at: null, reason: "the timestamp authority returned nothing" };
      return { trusted: Boolean(r.trusted), at: r.at ?? null, reason: r.reason || (r.trusted ? "countersignature verified" : "countersignature could not be verified") };
    } catch (err) {
      return { trusted: false, at: null, reason: "timestamp verification threw: " + (err?.message ?? String(err)) };
    }
  };
}

/* ------------------------------------------------------------------ *
 * Convenience: all three at once
 * ------------------------------------------------------------------ */

export function createProviders({ subtle, chainTransport, timestampTransport, requireRevocationCheck } = {}) {
  return {
    crypto: createCryptoProvider({ subtle }),
    chain: createChainProvider({ transport: chainTransport, requireRevocationCheck }),
    timestamp: createTimestampProvider({ transport: timestampTransport }),
  };
}

/** The reference transport: everything unknown, nothing invented. This is the
 *  default an unconfigured stack should get, so it reports the truth rather than
 *  a guess. */
export function createNullTransport() {
  return {
    async buildPath() { return { ok: false, reason: "no path builder is configured" }; },
    async revocationStatus() { return { revoked: false, reason: "no revocation source is configured" }; },
    async verifyTimestamp() { return { trusted: false, at: null, reason: "no timestamp authority is configured" }; },
  };
}
