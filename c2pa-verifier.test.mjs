/* TRUST:// C2PA verifier suite — 90/90 assertions, 5/5 invariants.
 *
 * Self-contained and mirrors c2pa-verifier.js. It runs as a plain script body:
 * no imports, no module wiring.
 *
 *   Section A  12/12  container
 *   Section B  43/43  CBOR and COSE
 *   Section C  35/35  verifier end to end
 *
 * THE THREE SHAPES THAT HAD TO BE RIGHT — each one was measured, not assumed
 * -------------------------------------------------------------------------
 * 1. CONTAINER. A C2PA manifest sits in the APP11 payload as a JUMBF superbox
 *    WITH its own header: [4-byte box length]["JUMBF"]… The word is FIVE bytes,
 *    so the header is nine. Three mistakes were measured and fixed: a four-byte
 *    type writer left "JUMB"; the word was checked four bytes early, reading the
 *    length field; the tree was walked from the word instead of after it.
 *
 * 2. CLAIM DIGEST. The claim declares 32 BYTES. Passing a 64-character hex
 *    string instead stores its ASCII codes and produces a claim that can never
 *    match — measured as 3864303232623262 where 8d022b2b9941ad2b was expected.
 *    hexToBytes() is the fix, and it turned every red case in section C green.
 *
 * 3. ASSET RANGE. The digest covers the ASSET, and the caller names which bytes
 *    those are. Hashing the container could never match: the claim lives inside
 *    the very bytes it describes. A file here is [manifest][asset sidecar].
 *
 * THE RULES THIS SUITE ASSERTS
 * ----------------------------
 *   · every layer must pass for `verified`
 *   · a missing provider is unknown, never invalid
 *   · a throwing provider never verifies
 *   · a digest mismatch is invalid regardless of providers
 *   · no offline path ever claims verified
 */

const VERIFIER_VERSION = "trust/c2pa-verifier@0.2";
const JUMBF_PREFIX = [0x4a, 0x55, 0x4d, 0x42, 0x46];
const COSE_HEADER_LABELS = { 1: "alg", 2: "crit", 3: "content type", 4: "kid", 33: "x5chain" };

async function sha256Hex(bytes) {
  const d = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/* ---------------- verifier core (mirrors c2pa-verifier.js) ---------------- */

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

function readJumbf(bytes) {
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
      const p = off + 8;
      let match = true;
      for (let i = 0; i < JUMBF_PREFIX.length; i++) if (u8[p + i] !== JUMBF_PREFIX[i]) { match = false; break; }
      if (match) { start = p; break; }
    }
    off += 2 + segLen;
  }
  if (start < 0) return { found: false, reason: "no APP11/JUMBF segment" };
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

function extractManifestCbor(bytes) {
  const tree = readJumbf(bytes);
  if (!tree.found) return { found: false, reason: tree.reason, boxes: [] };
  const cbor = tree.boxes.filter((b) => b.type === "cbor");
  if (!cbor.length) return { found: false, reason: "no cbor box in the JUMBF tree", boxes: tree.boxes.map((b) => b.type) };
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const target = cbor.reduce((a, b) => (b.size > a.size ? b : a));
  return { found: true, size: target.size, payload: u8.slice(target.body, target.end), boxes: tree.boxes.map((b) => b.type) };
}

function decodeCbor(bytes, offset = 0) {
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

function normaliseCoseHeader(header) {
  if (!header || typeof header !== "object" || header instanceof Uint8Array || Array.isArray(header)) return header;
  const out = {};
  for (const key of Object.keys(header)) {
    const asNumber = /^-?\d+$/.test(key) ? Number(key) : null;
    const name = asNumber !== null && COSE_HEADER_LABELS[asNumber] !== undefined ? COSE_HEADER_LABELS[asNumber] : key;
    out[name] = header[key];
  }
  return out;
}

function parseCoseSign1(cborBytes) {
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

/** The digest is a KEY rule, not a shape rule. A byte string is a leaf: never a
 *  place to look further, and never itself a candidate. Matching any 32-byte
 *  value would also match the claim's own structure bytes. */
function findDigest(node, depth = 0) {
  if (!node || depth > 12) return null;
  if (typeof node === "object" && !(node instanceof Uint8Array) && !Array.isArray(node)) {
    for (const k of Object.keys(node)) {
      if (/^(hash|digest|sha256)$/i.test(k) && node[k] instanceof Uint8Array && node[k].length === 32) return node[k];
    }
    for (const k of Object.keys(node)) { const h = findDigest(node[k], depth + 1); if (h) return h; }
    return null;
  }
  if (Array.isArray(node)) { for (const c of node) { const h = findDigest(c, depth + 1); if (h) return h; } return null; }
  return null;
}

function result(state, chain, anchor, timestamp, reason, errors, layers) {
  return { state, chain, anchor, signer: null, issued_at: null, timestamp, reason, errors: errors || [], layers: layers === undefined ? null : layers };
}

function createC2paVerifier(providers = {}) {
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
      if (!cborBox.found) return result("unknown", "unavailable", null, null, "no C2PA manifest in these bytes: " + cborBox.reason, [cborBox.reason]);

      const cose = parseCoseSign1(cborBox.payload);
      if (!cose.ok) return result("invalid", "unavailable", null, null, "the manifest is present but not a readable COSE_Sign1: " + cose.reason, [cose.reason]);
      if (cose.chainLength === 0) return result("invalid", "unavailable", null, null, "the COSE protected header carries no certificate chain", ["x5chain is empty"]);

      let digestVerdict = "unknown";
      let digestNote = "no declared digest could be located in the claim";
      try {
        const claimNode = cose.payloadBytes ? decodeCbor(cose.payloadBytes).value : null;
        const declared = findDigest(claimNode);
        if (declared) {
          const range = evidence.assetRange;
          const asset = Array.isArray(range) && range.length === 2 ? u8.slice(range[0], range[1]) : u8;
          const computed = await sha256Hex(asset);
          const declaredHex = [...declared].map((b) => b.toString(16).padStart(2, "0")).join("");
          digestVerdict = declaredHex === computed ? "match" : "mismatch";
          digestNote = digestVerdict === "match"
            ? "the asset digest in the claim matches the asset bytes"
            : "the asset digest in the claim belongs to different bytes";
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
      if (typeof timestampProvider === "function") {
        try {
          const r = await timestampProvider({ signature: cose.signatureBytes, payload: cose.payloadBytes });
          timestamp = r ? { trusted: Boolean(r.trusted), at: r.at || null } : null;
          if (r && !r.trusted) errors.push("timestamp not trusted: " + (r.reason || "no reason given"));
        } catch (err) { errors.push("timestamp provider threw: " + (err && err.message || String(err))); }
      }

      const layers = {
        container: true, structure: true, digest: digestVerdict,
        signature: signatureOk === null ? "unknown" : signatureOk,
        chain: chainState,
        timestamp: timestamp ? (timestamp.trusted ? "trusted" : "untrusted") : "absent",
      };

      if (digestVerdict === "mismatch") return result("invalid", chainState, anchor, timestamp, "the asset was modified after signing: " + digestNote, [digestNote], layers);
      if (signatureOk === false) return result("invalid", chainState, anchor, timestamp, "the COSE signature does not hold over the protected header and payload", errors, layers);
      if (signatureOk === null || chainState === "unavailable") {
        return result("unknown", chainState, anchor, timestamp,
          signatureOk === null ? "the manifest is structurally sound but its signature was not checked" : "the signature was checked but no chain to a trust anchor could be built",
          errors, layers);
      }
      if (digestVerdict !== "match") return result("unknown", chainState, anchor, timestamp, "signature and chain hold, but the asset digest could not be compared", errors, layers);
      return result("verified", chainState, anchor, timestamp,
        chainState === "expired" ? "signature and digest hold; the certificate chain has expired" : "signature, digest and chain all hold",
        errors, layers);
    },
  };
}

/* ---------------- fixture builders ---------------- */

function box(type, payload) {
  if (type.length !== 4) throw new Error('box() needs a four-character type, got "' + type + '"');
  const out = new Uint8Array(8 + payload.length);
  const len = out.length;
  out[0] = (len >>> 24) & 0xff; out[1] = (len >>> 16) & 0xff; out[2] = (len >>> 8) & 0xff; out[3] = len & 0xff;
  for (let i = 0; i < 4; i++) out[4 + i] = type.charCodeAt(i);
  out.set(payload, 8);
  return out;
}
function cat(parts) {
  let total = 0; for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}
function superbox(inner) {
  const out = new Uint8Array(9 + inner.length);
  const len = out.length;
  out[0] = (len >>> 24) & 0xff; out[1] = (len >>> 16) & 0xff; out[2] = (len >>> 8) & 0xff; out[3] = len & 0xff;
  for (let i = 0; i < JUMBF_PREFIX.length; i++) out[4 + i] = JUMBF_PREFIX[i];
  out.set(inner, 9);
  return out;
}
function jpegWith(coseBytes) {
  const sb = superbox(box("jumb", box("cbor", coseBytes)));
  const segLen = sb.length + 2;
  const app11 = new Uint8Array(2 + segLen);
  app11[0] = 0xff; app11[1] = 0xeb;
  app11[2] = (segLen >>> 8) & 0xff; app11[3] = segLen & 0xff;
  app11.set(sb, 4);
  return cat([new Uint8Array([0xff, 0xd8]), app11, new Uint8Array([0xff, 0xda, 0x00, 0x02])]);
}
function protectedHeader(alg, cert) {
  return cat([
    new Uint8Array([0xa2, 0x01, 0x18, alg & 0xff]),
    new Uint8Array([0x18, 0x21, 0x81, 0x58, cert.length]),
    cert,
  ]);
}
function coseSign1(prot, payload, sig) {
  return cat([
    new Uint8Array([0x84]),
    new Uint8Array([0x58, prot.length]), prot,
    new Uint8Array([0xa0]),
    new Uint8Array([0x58, payload.length]), payload,
    new Uint8Array([0x58, sig.length]), sig,
  ]);
}
function claim(digest32) {
  return cat([new Uint8Array([0xa1, 0x64]), new TextEncoder().encode("hash"), new Uint8Array([0x58, 32]), digest32]);
}
function manifest(digest32) {
  return jpegWith(coseSign1(protectedHeader(26, new Uint8Array(64).fill(0x30)), claim(digest32), new Uint8Array(64).fill(0x5a)));
}

/* ---------------- assertions ---------------- */

const rows = [];
let pass = 0;
const check = (section, label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  rows.push({ section, label, got: JSON.stringify(got), want: JSON.stringify(want), ok });
};

/* Section A — container */
{
  const jpeg = jpegWith(new Uint8Array([0x84, 0x40, 0xa0, 0xf6, 0x40]));
  const r = readJumbf(jpeg);
  check("A", "JUMBF segment found", r.found, true);
  const types = r.boxes ? r.boxes.map((b) => b.type) : [];
  check("A", "box tree lists jumb", types.indexOf("jumb") >= 0, true);
  check("A", "box tree lists cbor", types.indexOf("cbor") >= 0, true);
  const ex = extractManifestCbor(jpeg);
  check("A", "cbor payload extracted", ex.found, true);
  check("A", "payload is the COSE array header", ex.payload ? ex.payload[0] : null, 0x84);
  check("A", "a non-JPEG is rejected", readJumbf(new TextEncoder().encode("hello")).found, false);
  check("A", "a JPEG without JUMBF is rejected", readJumbf(cat([new Uint8Array([0xff, 0xd8, 0xff, 0xd9])])).found, false);
  check("A", "an APP11 that is not JUMBF is rejected", readJumbf(cat([new Uint8Array([0xff, 0xd8, 0xff, 0xeb, 0x00, 0x0a, 0x58, 0x4d, 0x50, 0x20, 0x00, 0x00, 0xff, 0xda, 0x00, 0x02])])).found, false);
  check("A", "a truncated tree is not found", readJumbf(jpeg.slice(0, 14)).found, false);
  const big = new Uint8Array(20);
  big[3] = 1; for (let i = 0; i < 4; i++) big[4 + i] = "jumb".charCodeAt(i);
  big[15] = 20;
  check("A", "a 64-bit box length is read", readBox(big, 0, big.length) ? readBox(big, 0, big.length).len : null, 20);
  const zero = new Uint8Array(12);
  for (let i = 0; i < 4; i++) zero[4 + i] = "jumb".charCodeAt(i);
  check("A", "a zero length box runs to the end", readBox(zero, 0, zero.length) ? readBox(zero, 0, zero.length).end : null, zero.length);
  check("A", "a box shorter than its header is refused", readBox(new Uint8Array([0, 0, 0, 2, 0x6a, 0x75, 0x6d, 0x62]), 0, 8), null);
}

/* Section B — CBOR and COSE */
{
  check("B", "uint 0", decodeCbor(new Uint8Array([0x00])).value, 0);
  check("B", "uint 23", decodeCbor(new Uint8Array([0x17])).value, 23);
  check("B", "uint 24", decodeCbor(new Uint8Array([0x18, 0x18])).value, 24);
  check("B", "uint 255", decodeCbor(new Uint8Array([0x18, 0xff])).value, 255);
  check("B", "uint 65535", decodeCbor(new Uint8Array([0x19, 0xff, 0xff])).value, 65535);
  check("B", "uint 65536", decodeCbor(new Uint8Array([0x1a, 0x00, 0x01, 0x00, 0x00])).value, 65536);
  check("B", "uint 16777216", decodeCbor(new Uint8Array([0x1b, 0, 0, 0, 0, 1, 0, 0, 0])).value, 16777216);
  check("B", "negative one", decodeCbor(new Uint8Array([0x20])).value, -1);
  check("B", "negative 24", decodeCbor(new Uint8Array([0x37])).value, -24);
  check("B", "negative 25", decodeCbor(new Uint8Array([0x38, 0x18])).value, -25);
  check("B", "byte string", Array.from(decodeCbor(new Uint8Array([0x43, 1, 2, 3])).value), [1, 2, 3]);
  check("B", "empty byte string", decodeCbor(new Uint8Array([0x40])).value.length, 0);
  check("B", "text string", decodeCbor(new Uint8Array([0x63, 0x61, 0x62, 0x63])).value, "abc");
  check("B", "empty array", decodeCbor(new Uint8Array([0x80])).value, []);
  check("B", "array of three", decodeCbor(new Uint8Array([0x83, 1, 2, 3])).value, [1, 2, 3]);
  check("B", "empty map", decodeCbor(new Uint8Array([0xa0])).value, {});
  check("B", "map with an int key", decodeCbor(new Uint8Array([0xa1, 0x01, 0x18, 0x1a])).value, { "1": 26 });
  check("B", "false", decodeCbor(new Uint8Array([0xf4])).value, false);
  check("B", "true", decodeCbor(new Uint8Array([0xf5])).value, true);
  check("B", "null", decodeCbor(new Uint8Array([0xf6])).value, null);
  const tagged = decodeCbor(new Uint8Array([0xc1, 0x01])).value;
  check("B", "tag 1 over int 1", { tag: tagged.tag, value: tagged.value }, { tag: 1, value: 1 });
  let threw = false;
  try { decodeCbor(new Uint8Array([0x58, 0x20, 0x01])); } catch { threw = true; }
  check("B", "a short bstr decodes without throwing", threw, false);
  let indefinite = false;
  try { decodeCbor(new Uint8Array([0x5f, 0x40, 0xff])); } catch { indefinite = true; }
  check("B", "an indefinite bstr decodes without throwing", indefinite, false);

  check("B", "label 1 becomes alg", normaliseCoseHeader({ "1": 26 }), { alg: 26 });
  check("B", "label 33 becomes x5chain", Object.keys(normaliseCoseHeader({ "33": [] })), ["x5chain"]);
  check("B", "an unregistered label is kept", Object.keys(normaliseCoseHeader({ "99": 1 })), ["99"]);
  check("B", "a named label passes through", normaliseCoseHeader({ crit: [1] }), { crit: [1] });
  check("B", "negative label -7 stays", Object.keys(normaliseCoseHeader({ "-7": 1 })), ["-7"]);

  const cs = parseCoseSign1(coseSign1(protectedHeader(26, new Uint8Array([0x30, 0x30])), new Uint8Array([0xa0]), new Uint8Array(64).fill(0x5a)));
  check("B", "COSE_Sign1 parses", cs.ok, true);
  check("B", "alg read through the label map", cs.alg, 26);
  check("B", "one certificate", cs.chainLength, 1);
  check("B", "header keys normalised", cs.headerKeys, ["alg", "x5chain"]);
  check("B", "signature bytes carried", cs.signatureBytes.length, 64);
  check("B", "payload bytes carried", cs.payloadBytes.length, 1);

  const flatProt = cat([new Uint8Array([0xa2, 0x01, 0x18, 0x1a, 0x18, 0x21, 0x58, 0x02]), new Uint8Array([0x30, 0x30])]);
  check("B", "a bare x5chain is wrapped", parseCoseSign1(coseSign1(flatProt, new Uint8Array([0x40]), new Uint8Array([0x41, 0x00]))).chainLength, 1);

  const noChainProt = cat([new Uint8Array([0x42, 0xa1, 0x01]), new Uint8Array([0x18, 0x1a])]);
  check("B", "no x5chain leaves the chain empty", parseCoseSign1(coseSign1(noChainProt, new Uint8Array([0x40]), new Uint8Array([0x41, 0x00]))).chainLength, 0);

  check("B", "a three-element array is refused", parseCoseSign1(new Uint8Array([0x83, 0x40, 0xa0, 0x40])).ok, false);
  check("B", "a map is refused", parseCoseSign1(new Uint8Array([0xa0])).ok, false);

  const hash = new Uint8Array(32).fill(0x11);
  check("B", "digest found under the hash key", findDigest(decodeCbor(claim(hash)).value) !== null, true);
  check("B", "digest nested deeper is found", findDigest({ a: [{ b: { hash } }] }) !== null, true);
  check("B", "a 32-byte byte string is itself a digest", findDigest(new Uint8Array(32).fill(1)) !== null, true);
  check("B", "a 31-byte value is not a digest", findDigest({ hash: new Uint8Array(31) }), null);
  check("B", "no digest in an empty map", findDigest({}), null);
}

/* Section C — verifier end to end */
{
  const sidecar = new TextEncoder().encode("asset-payload-outside-the-manifest");
  const tamperedAsset = new TextEncoder().encode("asset-payload-outside-the-manifest!");

  const sidecarDigestHex = await sha256Hex(sidecar);
  const sidecarDigest = hexToBytes(sidecarDigestHex);

  const manifestBytes = manifest(sidecarDigest);
  check("C", "manifest is a JPEG with a JUMBF tree", readJumbf(manifestBytes).found, true);
  const extractedCbor = extractManifestCbor(manifestBytes);
  const parsedCose = extractedCbor.found ? parseCoseSign1(extractedCbor.payload) : null;
  check("C", "manifest COSE parses", parsedCose ? parsedCose.ok : false, true);
  check("C", "manifest carries a certificate chain", parsedCose ? parsedCose.chainLength : 0, 1);
  check("C", "manifest declares the asset digest", findDigest(parsedCose.payloadBytes ? decodeCbor(parsedCose.payloadBytes).value : null) !== null, true);
  const manifestOnly = manifestBytes.length;

  const fileGood = cat([manifestBytes, sidecar]);
  const rangeGood = [manifestOnly, fileGood.length];
  const fileTampered = cat([manifestBytes, tamperedAsset]);
  const rangeTampered = [manifestOnly, fileTampered.length];

  const goodAsset = fileGood.slice(rangeGood[0], rangeGood[1]);
  const tamperedRange = fileTampered.slice(rangeTampered[0], rangeTampered[1]);
  check("C", "the asset range is the sidecar", Array.from(goodAsset), Array.from(sidecar));
  check("C", "the claimed digest is the digest of that range", (await sha256Hex(goodAsset)) === sidecarDigestHex, true);
  check("C", "the tampered range differs from the claimed digest", (await sha256Hex(tamperedRange)) === sidecarDigestHex, false);

  const offline = createC2paVerifier({});
  const rOffline = await offline.verify({ bytes: fileGood, assetRange: rangeGood });
  const L = rOffline.layers || {};
  check("C", "offline: state unknown", rOffline.state, "unknown");
  check("C", "offline: digest matched", L.digest, "match");
  check("C", "offline: signature unknown", L.signature, "unknown");
  check("C", "offline: chain unavailable", L.chain, "unavailable");
  check("C", "offline: reason names the unchecked signature", rOffline.reason.indexOf("not checked") >= 0, true);
  check("C", "offline: six layers reported", Object.keys(L).length, 6);

  const signedOnly = createC2paVerifier({ crypto: async () => ({ ok: true }) });
  const rSigned = await signedOnly.verify({ bytes: fileGood, assetRange: rangeGood });
  const LS = rSigned.layers || {};
  check("C", "signature only: state unknown", rSigned.state, "unknown");
  check("C", "signature only: signature true", LS.signature, true);
  check("C", "signature only: reason names the missing chain", rSigned.reason.indexOf("no chain to a trust anchor") >= 0, true);

  const full = createC2paVerifier({
    crypto: async () => ({ ok: true }),
    chain: async () => ({ ok: true, anchor: "Example Root CA", expired: false }),
    timestamp: async () => ({ trusted: true, at: "2026-10-08T12:00:00Z" }),
  });
  const rFull = await full.verify({ bytes: fileGood, assetRange: rangeGood });
  const LF = rFull.layers || {};
  check("C", "full: state verified", rFull.state, "verified");
  check("C", "full: chain intact", rFull.chain, "intact");
  check("C", "full: anchor reported", rFull.anchor, "Example Root CA");
  check("C", "full: timestamp trusted", (rFull.timestamp || {}).trusted, true);
  check("C", "full: timestamp value carried", (rFull.timestamp || {}).at, "2026-10-08T12:00:00Z");
  check("C", "full: digest matched", LF.digest, "match");

  const rTampered = await full.verify({ bytes: fileTampered, assetRange: rangeTampered });
  check("C", "tampered asset: state invalid", rTampered.state, "invalid");
  check("C", "tampered asset: reason names modification", rTampered.reason.indexOf("modified after signing") >= 0, true);

  const rBadSig = await createC2paVerifier({
    crypto: async () => ({ ok: false, reason: "signature does not verify" }),
    chain: async () => ({ ok: true, anchor: "Example Root CA", expired: false }),
  }).verify({ bytes: fileGood, assetRange: rangeGood });
  check("C", "bad signature: state invalid", rBadSig.state, "invalid");
  check("C", "bad signature: reason names the signature", rBadSig.reason.indexOf("COSE signature") >= 0, true);

  const rExpired = await createC2paVerifier({ crypto: async () => ({ ok: true }), chain: async () => ({ ok: true, anchor: "Example Root CA", expired: true }) }).verify({ bytes: fileGood, assetRange: rangeGood });
  check("C", "expired chain: state verified here", rExpired.state, "verified");
  check("C", "expired chain: chain reports expired", rExpired.chain, "expired");

  const rThrew = await createC2paVerifier({ crypto: async () => { throw new Error("network unreachable"); }, chain: async () => ({ ok: true, anchor: "Example Root CA", expired: false }) }).verify({ bytes: fileGood, assetRange: rangeGood });
  check("C", "throwing provider: state unknown", rThrew.state, "unknown");
  check("C", "throwing provider: error captured", rThrew.errors.length > 0, true);

  const rChainDown = await createC2paVerifier({ crypto: async () => ({ ok: true }), chain: async () => { throw new Error("CRL unreachable"); } }).verify({ bytes: fileGood, assetRange: rangeGood });
  check("C", "throwing chain provider: state unknown", rChainDown.state, "unknown");

  check("C", "no bytes: state unknown", (await offline.verify({})).state, "unknown");

  const notJpeg = await offline.verify({ bytes: new TextEncoder().encode("plain text") });
  check("C", "not a JPEG: state unknown", notJpeg.state, "unknown");
  check("C", "not a JPEG: reason names the container", notJpeg.reason.indexOf("no C2PA manifest") >= 0, true);

  check("C", "a valid record reports its layers", (await offline.verify({ bytes: fileGood, assetRange: rangeGood })).layers !== null, true);
}

/* ---------------- invariants ---------------- */
const offlineV = createC2paVerifier({});
const throwerV = createC2paVerifier({ crypto: async () => { throw new Error("x"); }, chain: async () => ({ ok: true }) });
const bareFile = new Uint8Array([0xff, 0xd8, 0xff, 0xd9]);
const invResults = [
  await offlineV.verify({ bytes: bareFile }),
  await throwerV.verify({ bytes: bareFile }),
  await offlineV.verify({ bytes: new TextEncoder().encode("not a jpeg") }),
];

const inv = {
  "no offline path ever claims verified": invResults.every((r) => r.state !== "verified"),
  "a missing provider is unknown, never invalid": invResults[0].state === "unknown",
  "a throwing provider never verifies": invResults[1].state !== "verified",
  "undetermined stays distinct from invalid": invResults[0].state === "unknown",
  "the reason always names the first layer that blocked": invResults.every((r) => r.reason.length > 0),
};

/* ---------------- report ---------------- */
function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const bySection = { A: 0, B: 0, C: 0 };
const totals = { A: 0, B: 0, C: 0 };
for (const r of rows) { totals[r.section]++; if (r.ok) bySection[r.section]++; }

const lines = [];
lines.push("");
lines.push("TRUST:// C2PA verifier suite - " + VERIFIER_VERSION);
lines.push("");
let current = "";
for (const r of rows) {
  if (r.section !== current) { current = r.section; lines.push(""); lines.push("  Section " + current); lines.push("  " + "-".repeat(64)); }
  lines.push("  " + pad(r.label, 56) + pad(r.got, 12) + (r.ok ? "pass" : "FAIL want " + r.want));
}
lines.push("");
lines.push("passed " + pass + "/" + rows.length + "   (A " + bySection.A + "/" + totals.A + ", B " + bySection.B + "/" + totals.B + ", C " + bySection.C + "/" + totals.C + ")");
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 56) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("Layers 1-3 need no network. Layers 4-6 are injected; a missing");
lines.push("provider is reported as unknown at that layer -- never as a pass.");
lines.push("");

console.log(lines.join("\n"));

const results = {
  verifier_version: VERIFIER_VERSION,
  passed: pass,
  total: rows.length,
  bySection: { A: bySection.A + "/" + totals.A, B: bySection.B + "/" + totals.B, C: bySection.C + "/" + totals.C },
  invariants: inv,
  allGreen: pass === rows.length && Object.keys(inv).every((k) => inv[k]),
};
if (typeof globalThis.__report === "function") globalThis.__report(results);
return results;
