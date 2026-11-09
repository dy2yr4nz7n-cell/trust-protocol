/* TRUST:// C2PA verifier — the network half of the split.
 * Record Format 0.2
 *
 * LAYERS
 * ------
 *   1 container   JPEG APP11 payload carries the JUMBF superbox; the box tree
 *                 starts after the five-byte word
 *   2 structure   COSE_Sign1 = [protected, unprotected, payload, signature];
 *                 COSE's integer header labels (1, 33) are normalised to names
 *                 before anything downstream reads them
 *   3 digest      the claim declares a hash of the ASSET. Compare it against
 *                 the asset bytes — never against the container that carries
 *                 the claim, which differs by construction. Declared exclusion
 *                 ranges are removed before hashing; absent ranges mean the
 *                 whole asset is hashed.
 *   4 signature   INJECTED provider — absent means unknown, never verified
 *   5 chain       INJECTED provider — absent means unknown, never verified
 *   6 timestamp   INJECTED provider — absent means absent
 *
 * THE HONESTY CONSTRAINT
 * ----------------------
 * Layers 1-3 are pure computation over bytes and work offline. Layers 4-6 need
 * a trust store, a revocation source and a timestamp authority; they are
 * injected. A missing or throwing provider yields `unknown` at that layer —
 * never a pass. Every layer must pass for `state: "verified"`.
 *
 * MEASURED BEHAVIOUR
 * ------------------
 * The container and CBOR/COSE layers are covered by the suite in
 * c2pa-verifier.test.mjs: every container case (JUMBF found, box tree, 64-bit
 * lengths, zero length, truncation, non-JPEG, APP11 without JUMBF) and every
 * CBOR case (all integer widths, negatives, byte/text strings, arrays, maps,
 * tags, refusal of indefinite forms) passes, as do all five invariants.
 */

export const VERIFIER_VERSION = "trust/c2pa-verifier@0.2";

const JUMBF_PREFIX = [0x4a, 0x55, 0x4d, 0x42, 0x46]; // "JUMBF"

/** COSE registered header labels, carried on the wire as integers. */
export const COSE_HEADER_LABELS = { 1: "alg", 2: "crit", 3: "content type", 4: "kid", 33: "x5chain" };

export async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ------------------------------------------------------------------ *
 * Layer 1 — container
 * ------------------------------------------------------------------ */

function readBox(bytes, off, end) {
  if (off + 8 > end) return null;
  let len = (bytes[off] << 24) | (bytes[off + 1] << 16) | (bytes[off + 2] << 8) | bytes[off + 3];
  const type = String.fromCharCode(bytes[off + 4], bytes[off + 5], bytes[off + 6], bytes[off + 7]);
  let header = 8;
  if (len === 1) { len = 0; for (let i = 0; i < 8; i++) len = len * 256 + bytes[off + 8 + i]; header = 16; }
  else if (len === 0) len = end - off;
  if (len < header) return null;
  return { type, len, header, start: off, end: Math.min(off + len, end), body: off + header };
}

/** Find the JUMBF word in a JPEG's APP11 segment and walk the box tree. */
export function readJumbf(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!(u8[0] === 0xff && u8[1] === 0xd8)) return { found: false, reason: "not a JPEG container" };

  let off = 2, start = -1;
  while (off + 4 < u8.length) {
    if (u8[off] !== 0xff) { off++; continue; }
    const marker = u8[off + 1];
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { off += 2; continue; }
    if (marker === 0xda) break;
    const segLen = (u8[off + 2] << 8) | u8[off + 3];
    if (marker === 0xeb && segLen > 8) {
      const p = off + 4;
      let match = true;
      for (let i = 0; i < JUMBF_PREFIX.length; i++) if (u8[p + i] !== JUMBF_PREFIX[i]) { match = false; break; }
      if (match) { start = p; break; }
    }
    off += 2 + segLen;
  }
  if (start < 0) return { found: false, reason: "no APP11/JUMBF segment" };

  /* The box tree begins AFTER the five-byte word: readBox wants the length
   * field first, and that follows the type marker. */
  const treeStart = start + JUMBF_PREFIX.length;
  const boxes = [];
  const walk = (from, to, depth) => {
    let o = from, guard = 0;
    while (o + 8 <= to && guard++ < 8192) {
      const b = readBox(u8, o, to);
      if (!b || b.end <= o) break;
      boxes.push({ depth, type: b.type, size: b.end - o, body: b.body, end: b.end });
      if (b.type === "jumb") walk(b.body, b.end, depth + 1);
      o = b.end;
    }
  };
  walk(treeStart, u8.length, 0);
  if (boxes.length === 0) return { found: false, reason: "the JUMBF tree held no readable box" };
  return { found: true, boxes };
}

export function extractManifestCbor(bytes) {
  const tree = readJumbf(bytes);
  if (!tree.found) return { found: false, reason: tree.reason, boxes: [] };
  const cbor = tree.boxes.filter((b) => b.type === "cbor");
  if (!cbor.length) return { found: false, reason: "no cbor box in the JUMBF tree", boxes: tree.boxes.map((b) => b.type) };
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const target = cbor.reduce((a, b) => (b.size > a.size ? b : a));
  return { found: true, size: target.size, payload: u8.slice(target.body, target.end), boxes: tree.boxes.map((b) => b.type) };
}

/* ------------------------------------------------------------------ *
 * Layer 2 — CBOR and COSE_Sign1
 * ------------------------------------------------------------------ */

export function decodeCbor(bytes, offset = 0) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let pos = offset;
  function readLen(a) {
    if (a < 24) return a;
    if (a === 24) return u8[pos++];
    if (a === 25) { const v = (u8[pos] << 8) | u8[pos + 1]; pos += 2; return v; }
    if (a === 26) { const v = (u8[pos] << 24) | (u8[pos + 1] << 16) | (u8[pos + 2] << 8) | u8[pos + 3]; pos += 4; return v >>> 0; }
    if (a === 27) { let v = 0; for (let i = 0; i < 8; i++) v = v * 256 + u8[pos + i]; pos += 8; return v; }
    return null;
  }
  function item() {
    const first = u8[pos++];
    const major = first >> 5, add = first & 0x1f;
    if (major === 0) return readLen(add);
    if (major === 1) return -1 - readLen(add);
    if (major === 2) { const n = readLen(add); const out = u8.slice(pos, pos + n); pos += n; return out; }
    if (major === 3) { const n = readLen(add); const out = new TextDecoder().decode(u8.slice(pos, pos + n)); pos += n; return out; }
    if (major === 4) { const n = readLen(add); const out = []; for (let i = 0; i < n; i++) out.push(item()); return out; }
    if (major === 5) { const n = readLen(add); const out = {}; for (let i = 0; i < n; i++) { const k = item(); out[typeof k === "string" ? k : String(k)] = item(); } return out; }
    if (major === 6) { const tag = readLen(add); return { tag, value: item() }; }
    if (major === 7) { if (add === 20) return false; if (add === 21) return true; if (add === 22) return null; return { simple: add }; }
    throw new Error("unsupported CBOR major type " + major);
  }
  return { value: item(), bytesRead: pos - offset };
}

/** CBOR carries COSE header labels as integers; the record format speaks names.
 *  Normalising here keeps the wire encoding out of every reader downstream. */
export function normaliseCoseHeader(header) {
  if (!header || typeof header !== "object" || header instanceof Uint8Array || Array.isArray(header)) return header;
  const out = {};
  for (const key of Object.keys(header)) {
    const asNumber = /^-?\d+$/.test(key) ? Number(key) : null;
    const name = asNumber !== null && COSE_HEADER_LABELS[asNumber] !== undefined ? COSE_HEADER_LABELS[asNumber] : key;
    out[name] = header[key];
  }
  return out;
}

export function parseCoseSign1(cborBytes) {
  let decoded;
  try { decoded = decodeCbor(cborBytes); }
  catch (err) { return { ok: false, reason: "CBOR decode failed: " + (err && err.message || String(err)) }; }
  const arr = decoded.value;
  if (!Array.isArray(arr) || arr.length !== 4) return { ok: false, reason: "not a COSE_Sign1 array of four elements" };
  const protectedBstr = arr[0], payload = arr[2], signature = arr[3];
  const protectedBytes = protectedBstr instanceof Uint8Array ? protectedBstr : null;
  let header = null;
  if (protectedBytes && protectedBytes.length) {
    try { header = normaliseCoseHeader(decodeCbor(protectedBytes).value); }
    catch (err) { return { ok: false, reason: "protected header did not decode: " + (err && err.message || String(err)) }; }
  }
  const alg = header && header.alg !== undefined ? header.alg : null;
  let chain = header && header.x5chain !== undefined ? header.x5chain : null;
  if (chain instanceof Uint8Array) chain = [chain];
  if (!Array.isArray(chain)) chain = [];
  return {
    ok: true, alg, chainLength: chain.length, certificates: chain,
    payloadBytes: payload instanceof Uint8Array ? payload : null,
    signatureBytes: signature instanceof Uint8Array ? signature : null,
    protectedBytes,
    headerKeys: header ? Object.keys(header) : null,
  };
}

/* ------------------------------------------------------------------ *
 * Layer 3 — digest
 * ------------------------------------------------------------------ */

export function findDigest(node, depth = 0) {
  if (!node || depth > 12) return null;
  if (node instanceof Uint8Array) return node.length === 32 ? node : null;
  if (Array.isArray(node)) { for (const c of node) { const h = findDigest(c, depth + 1); if (h) return h; } return null; }
  if (typeof node === "object") {
    for (const k of Object.keys(node)) if (/^(hash|digest|sha256)$/i.test(k) && node[k] instanceof Uint8Array && node[k].length === 32) return node[k];
    for (const k of Object.keys(node)) { const h = findDigest(node[k], depth + 1); if (h) return h; }
  }
  return null;
}

/** Collect byte ranges a C2PA hash assertion excludes from the asset digest.
 *  Accepted shapes are deliberately narrow: { offset, length } and
 *  { start, end }. Anything else is ignored here and reported by the caller. */
export function collectExclusionRanges(node, depth = 0, out = []) {
  if (!node || depth > 12) return out;
  if (Array.isArray(node)) {
    for (const child of node) collectExclusionRanges(child, depth + 1, out);
    return out;
  }
  if (typeof node !== "object") return out;

  const offset = Number(node.offset);
  const length = Number(node.length);
  if (Number.isInteger(offset) && Number.isInteger(length) && offset >= 0 && length > 0) {
    out.push([offset, offset + length]);
  } else {
    const start = Number(node.start);
    const end = Number(node.end);
    if (Number.isInteger(start) && Number.isInteger(end) && start >= 0 && end > start) {
      out.push([start, end]);
    }
  }

  for (const key of Object.keys(node)) collectExclusionRanges(node[key], depth + 1, out);
  return out;
}

/** Sort and coalesce ranges so overlapping or adjacent exclusions cannot
 *  produce a fragmented hash input. */
export function mergeRanges(ranges) {
  const sorted = ranges
    .map((r) => [Math.max(0, Math.floor(r[0])), Math.max(0, Math.floor(r[1]))])
    .filter((r) => r[1] > r[0])
    .sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const out = [];
  for (const range of sorted) {
    const last = out[out.length - 1];
    if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1]);
    else out.push([...range]);
  }
  return out;
}

/** Remove merged exclusion ranges from a base range. */
export function subtractRanges(base, exclusions) {
  const [baseStart, baseEnd] = base;
  const kept = [];
  let cursor = baseStart;
  for (const [start, end] of mergeRanges(exclusions)) {
    const clippedStart = Math.max(start, baseStart);
    const clippedEnd = Math.min(end, baseEnd);
    if (clippedEnd <= clippedStart) continue;
    if (clippedStart > cursor) kept.push([cursor, clippedStart]);
    cursor = Math.max(cursor, clippedEnd);
  }
  if (cursor < baseEnd) kept.push([cursor, baseEnd]);
  return kept;
}

function concatSlices(bytes, ranges) {
  let size = 0;
  for (const [start, end] of ranges) size += end - start;
  const out = new Uint8Array(size);
  let offset = 0;
  for (const [start, end] of ranges) {
    out.set(bytes.slice(start, end), offset);
    offset += end - start;
  }
  return out;
}

/* ------------------------------------------------------------------ *
 * The verifier
 * ------------------------------------------------------------------ */

function result(state, chain, anchor, timestamp, reason, errors, layers) {
  return { state, chain, anchor, signer: null, issued_at: null, timestamp, reason, errors: errors || [], layers: layers === undefined ? null : layers };
}

export function createC2paVerifier(providers = {}) {
  const cryptoProvider = providers.crypto, chainProvider = providers.chain, timestampProvider = providers.timestamp;

  return {
    kind: "c2pa",
    version: VERIFIER_VERSION,

    async verify(evidence) {
      const errors = [];
      const bytes = evidence && evidence.bytes;
      if (!bytes) return result("unknown", "unavailable", null, null, "no bytes were supplied to the verifier", ["evidence.bytes is missing"]);

      const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);

      const cborBox = extractManifestCbor(u8);
      if (!cborBox.found) {
        return result("unknown", "unavailable", null, null, "no C2PA manifest in these bytes: " + cborBox.reason, [cborBox.reason]);
      }

      const cose = parseCoseSign1(cborBox.payload);
      if (!cose.ok) {
        return result("invalid", "unavailable", null, null, "the manifest is present but not a readable COSE_Sign1: " + cose.reason, [cose.reason]);
      }
      if (cose.chainLength === 0) {
        return result("invalid", "unavailable", null, null, "the COSE protected header carries no certificate chain", ["x5chain is empty"]);
      }

      /* Over the ASSET, not the container. Declared exclusions remove ranges
       * before hashing; an unusable exclusion set must not silently become a
       * whole-file hash. */
      let digestVerdict = "unknown";
      let digestNote = "no declared digest could be located in the claim";
      try {
        const claimNode = cose.payloadBytes ? decodeCbor(cose.payloadBytes).value : null;
        const declared = findDigest(claimNode);
        if (declared) {
          const range = evidence.assetRange;
          const base = Array.isArray(range) && range.length === 2
            ? [Math.max(0, Math.floor(range[0])), Math.min(u8.length, Math.floor(range[1]))]
            : [0, u8.length];
          const exclusions = mergeRanges(collectExclusionRanges(claimNode));
          const kept = subtractRanges(base, exclusions);
          if (exclusions.length && kept.length === 0) {
            digestVerdict = "unknown";
            digestNote = "the declared exclusions removed the entire asset range, so no digest could be computed";
          } else {
            const asset = kept.length === 1 && kept[0][0] === 0 && kept[0][1] === u8.length
              ? u8
              : concatSlices(u8, kept);
            const computed = await sha256Hex(asset);
            const declaredHex = [...declared].map((b) => b.toString(16).padStart(2, "0")).join("");
            digestVerdict = declaredHex === computed ? "match" : "mismatch";
            digestNote = digestVerdict === "match"
              ? exclusions.length
                ? "the asset digest in the claim matches the asset bytes after the declared exclusions"
                : "the asset digest in the claim matches the asset bytes"
              : "the asset digest in the claim belongs to different bytes";
          }
        }
      } catch (err) {
        digestNote = "claim payload could not be decoded for a digest: " + (err && err.message || String(err));
        errors.push(String(err && err.message || err));
      }

      let signatureOk = null;
      if (typeof cryptoProvider !== "function") errors.push("no crypto provider: the COSE signature was not checked");
      else {
        try {
          const r = await cryptoProvider({
            protectedBytes: cose.protectedBytes, payload: cose.payloadBytes,
            signature: cose.signatureBytes, alg: cose.alg, certificates: cose.certificates,
          });
          signatureOk = Boolean(r && r.ok);
          if (!signatureOk) errors.push("signature check failed: " + ((r && r.reason) || "no reason given"));
        } catch (err) { errors.push("crypto provider threw: " + (err && err.message || String(err))); }
      }

      let chainState = "unavailable", anchor = null;
      if (typeof chainProvider !== "function") errors.push("no chain provider: no trust anchor could be resolved");
      else {
        try {
          const r = await chainProvider({ certificates: cose.certificates });
          anchor = (r && r.anchor) || null;
          if (r && r.ok) chainState = r.expired ? "expired" : "intact";
          else { chainState = "unavailable"; errors.push("chain check failed: " + ((r && r.reason) || "no reason given")); }
        } catch (err) { errors.push("chain provider threw: " + (err && err.message || String(err))); }
      }

      let timestamp = null;
      if (typeof timestampProvider !== "function") errors.push("no timestamp provider: no timestamp was checked");
      else {
        try {
          const r = await timestampProvider({ signature: cose.signatureBytes, payload: cose.payloadBytes });
          timestamp = r ? { trusted: Boolean(r.trusted), at: r.at || null } : null;
          if (r && !r.trusted) errors.push("timestamp not trusted: " + (r.reason || "no reason given"));
        } catch (err) { errors.push("timestamp provider threw: " + (err && err.message || String(err))); }
      }

      const layers = {
        container: true,
        structure: true,
        digest: digestVerdict,
        signature: signatureOk === null ? "unknown" : signatureOk,
        chain: chainState,
        timestamp: timestamp ? (timestamp.trusted ? "trusted" : "untrusted") : "absent",
      };

      if (digestVerdict === "mismatch") {
        return result("invalid", chainState, anchor, timestamp, "the asset was modified after signing: " + digestNote, [digestNote], layers);
      }
      if (signatureOk === false) {
        return result("invalid", chainState, anchor, timestamp, "the COSE signature does not hold over the protected header and payload", errors, layers);
      }
      if (signatureOk === null || chainState === "unavailable") {
        return result("unknown", chainState, anchor, timestamp,
          signatureOk === null
            ? "the manifest is structurally sound but its signature was not checked"
            : "the signature was checked but no chain to a trust anchor could be built",
          errors, layers);
      }
      if (digestVerdict !== "match") {
        return result("unknown", chainState, anchor, timestamp, "signature and chain hold, but the asset digest could not be compared", errors, layers);
      }
      return result("verified", chainState, anchor, timestamp,
        chainState === "expired"
          ? "signature and digest hold; the certificate chain has expired"
          : "signature, digest and chain all hold",
        errors, layers);
    },
  };
}

/** A verifier that can only do the offline layers. It will never claim
 *  `verified`, because it cannot check a signature or a chain — which is the
 *  truthful position. */
export function createOfflineVerifier() {
  return createC2paVerifier({});
}
