/**
 * x509-chain-transport.js — a local `buildPath` transport for the TRUST://
 * C2PA verifier, backed by the offline X.509 chain validator in
 * ./x509-parser.js.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * c2pa-providers.js hands the X.509 path to an INJECTED transport:
 *
 *   transport.buildPath(certificates)        -> { ok, anchor, expired, reason? }
 *   transport.revocationStatus(certificates) -> { revoked, reason? }
 *
 * That is the right boundary — path building normally needs a trust store and
 * revocation needs CRL/OCSP, neither of which can be done offline. This module
 * is the one place where the *offline* half is supplied: certificate signatures,
 * validity windows and anchor matching, all checkable from bytes alone.
 *
 * It deliberately does NOT pretend to cover revocation. `revocationStatus()`
 * reports `revoked: false` with `checked: false` and a reason saying that no
 * revocation source is configured — so a policy that sets
 * `requireRevocationCheck` still fails closed.
 *
 * USAGE
 * -----
 *   import { createX509Transport } from "./x509-chain-transport.js";
 *   import { createProviders } from "./c2pa-providers.js";
 *
 *   const transport = createX509Transport({ trustAnchors: [rootDer, ...] });
 *   const providers = createProviders({ chainTransport: transport });
 *
 * Anchors may be DER bytes (Uint8Array) for an exact match, or strings compared
 * against the root's subject DN. An exact DER match is preferred; a string
 * anchor only ever accepts a root whose own self-signature has already been
 * verified.
 */

import { validateCertificateChain, parseX509Certificate } from "./x509-parser.js";

/**
 * @param {object} options
 * @param {Array<Uint8Array|string>} options.trustAnchors acceptable roots
 * @param {Date|string} [options.referenceTime] time at which validity is judged
 */
export function createX509Transport(options = {}) {
  const trustAnchors = Array.isArray(options.trustAnchors) ? options.trustAnchors.slice() : [];
  let referenceTime = options.referenceTime ? new Date(options.referenceTime) : null;

  return {
    trustAnchors,

    /** Move the evaluation clock, e.g. to a recorded signing timestamp. */
    setReferenceTime(t) {
      referenceTime = new Date(t);
    },

    /**
     * The call c2pa-providers.js expects. `certificates` arrives leaf-first from
     * the COSE x5chain. A chain holding only a leaf cannot be built without an
     * intermediate, and that is reported plainly rather than guessed.
     */
    async buildPath(certificates) {
      if (!Array.isArray(certificates) || certificates.length === 0) {
        return { ok: false, reason: "no certificates were supplied for path building" };
      }

      const normalized = certificates
        .map((c) => (c instanceof Uint8Array ? c : new Uint8Array(c)))
        .filter((c) => c.length > 0);

      if (normalized.length === 0) {
        return { ok: false, reason: "every supplied certificate was empty" };
      }

      if (trustAnchors.length === 0) {
        return { ok: false, reason: "no trust anchors are configured, so no path could be built" };
      }

      let result;
      try {
        result = await validateCertificateChain(normalized, trustAnchors, referenceTime || new Date());
      } catch (err) {
        return { ok: false, reason: "chain validation threw: " + (err && err.message ? err.message : String(err)) };
      }

      if (!result.ok) {
        // The verifier records expiry differently from other failures, so keep
        // the distinction rather than flattening every failure together.
        return {
          ok: false,
          anchor: result.anchor ?? null,
          expired: result.code === "certificate-expired",
          reason: result.reason || "no path to a trust anchor could be built",
        };
      }

      return {
        ok: true,
        anchor: result.anchor ?? null,
        expired: false,
        reason: result.reason || "chain built to a trust anchor",
      };
    },

    /**
     * Revocation is not answerable offline. Reporting `revoked: false` alone
     * would read as "checked, and clean" — which is a lie — so `checked: false`
     * travels with it and a policy requiring revocation fails closed.
     */
    async revocationStatus() {
      return {
        revoked: false,
        checked: false,
        reason: "no revocation source is configured; revocation status was not determined",
      };
    },

    /** Parse a chain and report signer identity, for display. */
    async describe(certificates) {
      const out = [];
      for (const cert of certificates || []) {
        const der = cert instanceof Uint8Array ? cert : new Uint8Array(cert);
        const parsed = parseX509Certificate(der);
        out.push(
          parsed.ok
            ? {
                ok: true,
                subject: parsed.subject,
                issuer: parsed.issuer,
                notBefore: parsed.notBefore,
                notAfter: parsed.notAfter,
                keyType: parsed.publicKey?.type ?? null,
                curve: parsed.publicKey?.curve ?? null,
                extensions: parsed.extensions ?? null,
              }
            : { ok: false, reason: parsed.reason }
        );
      }
      return out;
    },
  };
}

/**
 * A transport whose anchors can be added after construction, for a trust store
 * that is loaded lazily or from configuration.
 */
export function createMutableX509Transport(options = {}) {
  const transport = createX509Transport(options);
  return {
    ...transport,
    addAnchor(anchor) {
      transport.trustAnchors.push(anchor);
      return transport.trustAnchors.length;
    },
    clearAnchors() {
      transport.trustAnchors.length = 0;
    },
  };
}
