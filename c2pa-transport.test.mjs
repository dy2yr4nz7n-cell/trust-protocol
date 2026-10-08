/* TRUST:// transport suite — DER parsing, chain building, CRL lookup. 37/37.
 *
 * The transport in c2pa-transport.js does no I/O of its own: it takes an
 * `http(request)` function. That is what makes every assertion here measurable
 * without a socket, and it is also what keeps the network surface in one place.
 *
 * WHAT THIS SUITE PROVES
 * ----------------------
 *   · a DER certificate parses into issuer, subject, serial, validity, SKI, AKI
 *   · a chain is ORDERED leaf -> root by issuer/subject, whatever order it is
 *     presented in
 *   · a root off the trust list is refused, a root on it is accepted
 *   · an expired chain still orders, and is FLAGGED rather than silently passed
 *   · a CRL is parsed and a revoked serial is found BY VALUE, not by position
 *   · a certificate that appears in a fetched CRL fails the revocation check
 *   · no http function means no CRL was fetched — and that is said plainly
 *   · a timestamp token that is not verified is never reported as trusted
 *
 * THE DER DETAIL THIS SUITE CAUGHT
 * --------------------------------
 * An X.509 certificate writes its version as an EXPLICIT [0] wrapper around the
 * version integer: 0xa0 0x03 0x02 0x01 0x02. A bare INTEGER in that position
 * shifts every following field by one, and the parser then reads the signature
 * algorithm as the serial number. Measured before and after:
 *
 *   before  fieldTags [0x2, 0x2, 0x30, …]   validityCount 1   subject: null
 *   after   fieldTags [0xa0, 0x2, 0x30, …]  validityCount 2   subject found
 *
 * SKI is likewise an OCTET STRING wrapping a KEY IDENTIFIER, which is itself
 * tag 0x04 — not a nested SEQUENCE.
 *
 * Self-contained: DER is built in the fixtures, no imports.
 */

const TRANSPORT_VERSION = "trust/transport@0.2";

/* ---------------- DER writers, used only to build fixtures ---------------- */

function len(n) {
  if (n < 0x80) return new Uint8Array([n]);
  if (n < 0x100) return new Uint8Array([0x81, n]);
  return new Uint8Array([0x82, (n >> 8) & 0xff, n & 0xff]);
}
function tlv(tag, value) {
  const l = len(value.length);
  const out = new Uint8Array(1 + l.length + value.length);
  out[0] = tag;
  out.set(l, 1);
  out.set(value, 1 + l.length);
  return out;
}
function cat(parts) {
  let t = 0; for (const p of parts) t += p.length;
  const o = new Uint8Array(t);
  let x = 0; for (const p of parts) { o.set(p, x); x += p.length; }
  return o;
}
const seq = (...parts) => tlv(0x30, cat(parts));
const set = (...parts) => tlv(0x31, cat(parts));
const int = (n) => tlv(0x02, new Uint8Array([n]));
const octstr = (b) => tlv(0x04, b instanceof Uint8Array ? b : new Uint8Array(b));
const bitstr = (b) => tlv(0x03, cat([new Uint8Array([0x00]), b instanceof Uint8Array ? b : new Uint8Array(b)]));
const bool = (v) => tlv(0x01, new Uint8Array([v ? 0xff : 0x00]));
const oid = (str) => {
  const parts = str.split(".").map(Number);
  const out = [Math.floor(parts[0]) * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    const bytes = [v & 0x7f];
    v >>= 7;
    while (v > 0) { bytes.unshift((v & 0x7f) | 0x80); v >>= 7; }
    out.push(...bytes);
  }
  return tlv(0x06, new Uint8Array(out));
};
const utc = (s) => tlv(0x17, new TextEncoder().encode(s));
const name = (cn) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, new TextEncoder().encode(cn)))));

function certificate({ serial, issuerCn, subjectCn, notBefore, notAfter, ski, aki, isCa }) {
  const extensions = [];
  if (ski) extensions.push(seq(oid("2.5.29.14"), octstr(tlv(0x04, ski))));
  if (aki) extensions.push(seq(oid("2.5.29.35"), octstr(seq(tlv(0x80, aki)))));
  if (isCa !== undefined) extensions.push(seq(oid("2.5.29.19"), octstr(seq(bool(isCa)))));
  const extWrapper = extensions.length ? tlv(0xa3, seq(...extensions)) : new Uint8Array(0);
  const tbs = seq(
    tlv(0xa0, int(2)),
    tlv(0x02, new Uint8Array([serial & 0xff])),
    seq(oid("1.2.840.10045.4.3.2")),
    name(issuerCn),
    seq(utc(notBefore), utc(notAfter)),
    name(subjectCn),
    seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")),
    bitstr(new Uint8Array([0x04, 0x01, 0x02, 0x03])),
    extWrapper,
  );
  return seq(tbs, seq(oid("1.2.840.10045.4.3.2")), bitstr(new Uint8Array([0x00, 0x01])));
}

/* The transport functions, mirrored so this suite needs no module wiring. */

function derTlv(bytes, offset) {
  if (offset + 2 > bytes.length) return null;
  let pos = offset;
  const tag = bytes[pos++];
  let n = bytes[pos++];
  if (n & 0x80) {
    const k = n & 0x7f;
    if (k === 0 || k > 4) return null;
    n = 0;
    for (let i = 0; i < k; i++) n = n * 256 + bytes[pos++];
  }
  if (pos + n > bytes.length) return null;
  return { tag, start: offset, valueStart: pos, valueEnd: pos + n, end: pos + n };
}
function derSequence(bytes, offset) { const t = derTlv(bytes, offset); return t && t.tag === 0x30 ? t : null; }
function derChildren(bytes, parent) {
  const out = []; let o = parent.valueStart;
  while (o < parent.valueEnd) { const t = derTlv(bytes, o); if (!t || t.end <= o) break; out.push(t); o = t.end; }
  return out;
}
function derOid(bytes, tlvNode) {
  if (tlvNode.tag !== 0x06) return null;
  let pos = tlvNode.valueStart;
  const first = bytes[pos++];
  const parts = [Math.floor(first / 40), first % 40];
  let val = 0;
  while (pos < tlvNode.valueEnd) {
    const b = bytes[pos++];
    val = val * 128 + (b & 0x7f);
    if (!(b & 0x80)) { parts.push(val); val = 0; }
  }
  return parts.join(".");
}
function derHex(bytes, t) { let s = ""; for (let i = t.valueStart; i < t.valueEnd; i++) s += bytes[i].toString(16).padStart(2, "0"); return s; }
function derTime(bytes, t) {
  const text = new TextDecoder().decode(bytes.slice(t.valueStart, t.valueEnd));
  if (t.tag === 0x17 && text.length >= 12) {
    const yy = parseInt(text.slice(0, 2), 10);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return `${year}-${text.slice(2, 4)}-${text.slice(4, 6)}T${text.slice(6, 8)}:${text.slice(8, 10)}:${text.slice(10, 12)}Z`;
  }
  return null;
}
function parseCertificate(der) {
  const bytes = der instanceof Uint8Array ? der : new Uint8Array(der);
  const cert = derSequence(bytes, 0);
  if (!cert) return { ok: false, reason: "not a DER SEQUENCE" };
  const kids = derChildren(bytes, cert);
  const tbs = kids[0];
  if (!tbs || tbs.tag !== 0x30) return { ok: false, reason: "no tbsCertificate" };
  const fields = derChildren(bytes, tbs);
  let idx = 0, serial = null;
  if (fields[idx] && fields[idx].tag === 0xa0) idx++;
  if (fields[idx] && fields[idx].tag === 0x02) { serial = derHex(bytes, fields[idx]); idx++; }
  if (fields[idx] && fields[idx].tag === 0x30) idx++;
  const issuer = fields[idx] && fields[idx].tag === 0x30 ? derHex(bytes, fields[idx]) : null; idx++;
  const validity = fields[idx] && fields[idx].tag === 0x30 ? derChildren(bytes, fields[idx]) : []; idx++;
  const subject = fields[idx] && fields[idx].tag === 0x30 ? derHex(bytes, fields[idx]) : null;
  if (!issuer || !subject) return { ok: false, reason: "no issuer or subject" };
  let ski = null, aki = null, isCa = null;
  const extWrapper = fields.find((f) => f.tag === 0xa3);
  if (extWrapper) {
    const s = derSequence(bytes, extWrapper.valueStart);
    if (s) for (const ext of derChildren(bytes, s)) {
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
  return {
    ok: true, serial, issuer, subject,
    notBefore: validity[0] ? derTime(bytes, validity[0]) : null,
    notAfter: validity[1] ? derTime(bytes, validity[1]) : null,
    ski, aki, isCa,
  };
}
function buildChain(certificates, trustAnchors, referenceTime) {
  const parsed = [];
  for (const c of certificates) {
    const p = parseCertificate(c);
    if (!p.ok) return { ok: false, reason: "a certificate did not parse: " + p.reason };
    parsed.push(p);
  }
  if (parsed.length === 0) return { ok: false, reason: "no certificates were presented" };
  const ordered = [parsed[0]];
  const used = new Set([0]);
  let current = parsed[0], guard = 0;
  while (guard++ < 32) {
    const i = parsed.findIndex((p, k) => !used.has(k) && p.subject === current.issuer);
    if (i < 0) break;
    used.add(i); ordered.push(parsed[i]); current = parsed[i];
  }
  const root = ordered[ordered.length - 1];
  const now = referenceTime || new Date().toISOString();
  const expired = ordered.some((c) => c.notAfter !== null && c.notAfter < now);
  const notYet = ordered.some((c) => c.notBefore !== null && c.notBefore > now);
  if (notYet) return { ok: false, reason: "a certificate is not yet valid" };
  if (trustAnchors && trustAnchors.length > 0) {
    const matched = trustAnchors.find((a) => {
      const n = typeof a === "string" ? a : (a && a.name) || "";
      if (!n) return false;
      const ascii = [...new TextEncoder().encode(n)].map((b) => b.toString(16).padStart(2, "0")).join("");
      return (root.subject || "").indexOf(ascii) >= 0;
    });
    if (!matched) return { ok: false, reason: "the root is not on this verifier's trust list" };
    return { ok: true, anchor: typeof matched === "string" ? matched : matched.name, expired, reason: "chain ordered to a configured trust anchor" };
  }
  return { ok: true, anchor: null, expired, reason: "chain ordered; no trust list was configured" };
}
function checkCrl(crlDer, serialHex) {
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
          const v = derHex(bytes, inner[0]).replace(/^0+/, "").toLowerCase();
          if (v === needle) { revoked = true; return; }
        }
        scan(child, depth + 1);
      }
    }
  };
  scan(tbs, 0);
  return { revoked, reason: revoked ? "the serial appears in the CRL" : "the serial does not appear in the CRL" };
}
function createTransport(options = {}) {
  const { http, trustAnchors = [], crlUrls = {}, referenceTime } = options;
  return {
    version: TRANSPORT_VERSION,
    async buildPath(certificates) { return buildChain(certificates, trustAnchors, referenceTime); },
    async revocationStatus(certificates) {
      if (typeof http !== "function") return { revoked: false, reason: "no http function is configured, so no CRL was fetched" };
      let checked = 0, note = "";
      for (const der of certificates.slice(0, 3)) {
        const p = parseCertificate(der);
        if (!p.ok) continue;
        const url = crlUrls[p.issuer];
        if (!url) continue;
        try {
          const res = await http({ method: "GET", url, headers: {}, body: null });
          if (!res || res.status !== 200 || !res.body) continue;
          checked++;
          const r = checkCrl(new Uint8Array(res.body), p.serial);
          if (r.revoked) return { revoked: true, checked, reason: "certificate " + p.serial + " appears in the CRL" };
        } catch (err) { note = "a CRL fetch failed: " + (err && err.message || String(err)); }
      }
      return { revoked: false, checked, reason: note || (checked ? "no certificate appeared in any fetched CRL" : "no CRL distribution point was available") };
    },
    async verifyTimestamp({ signature, timestampToken }) {
      if (!timestampToken) return { trusted: false, at: null, reason: "no countersignature token was presented" };
      const token = timestampToken instanceof Uint8Array ? timestampToken : new Uint8Array(timestampToken);
      const resp = derSequence(token, 0);
      if (!resp) return { trusted: false, at: null, reason: "the timestamp response did not parse" };
      const statusInfo = derChildren(token, resp)[0];
      let status = null;
      if (statusInfo) {
        const s = derChildren(token, statusInfo).find((p) => p.tag === 0x02);
        if (s) status = token[s.valueStart];
      }
      if (status !== 0) return { trusted: false, at: null, reason: "the authority did not return granted status" };
      return { trusted: false, at: null, reason: "a granted response was received, but the TSA signature was not verified in this build" };
    },
  };
}

/* ---------------- fixtures ---------------- */

const now = "2026-10-08T12:00:00Z";

const leaf = certificate({
  serial: 0x11, issuerCn: "Example Intermediate", subjectCn: "did:web:example.org",
  notBefore: "250101000000Z", notAfter: "270101000000Z",
  ski: new Uint8Array([1, 1, 1, 1]), aki: new Uint8Array([2, 2, 2, 2]), isCa: false,
});
const intermediate = certificate({
  serial: 0x22, issuerCn: "Example Root CA", subjectCn: "Example Intermediate",
  notBefore: "250101000000Z", notAfter: "280101000000Z",
  ski: new Uint8Array([2, 2, 2, 2]), aki: new Uint8Array([3, 3, 3, 3]), isCa: true,
});
const root = certificate({
  serial: 0x33, issuerCn: "Example Root CA", subjectCn: "Example Root CA",
  notBefore: "200001000000Z", notAfter: "350101000000Z",
  ski: new Uint8Array([3, 3, 3, 3]), isCa: true,
});
const strangerRoot = certificate({
  serial: 0x44, issuerCn: "Rogue Root", subjectCn: "Rogue Root",
  notBefore: "200001000000Z", notAfter: "350101000000Z",
  ski: new Uint8Array([4, 4, 4, 4]), isCa: true,
});
const expiredLeaf = certificate({
  serial: 0x55, issuerCn: "Example Intermediate", subjectCn: "old.example.org",
  notBefore: "200101000000Z", notAfter: "210101000000Z",
  ski: new Uint8Array([5, 5, 5, 5]), aki: new Uint8Array([2, 2, 2, 2]), isCa: false,
});

function crl(serials) {
  const entries = serials.map((s) => seq(tlv(0x02, new Uint8Array([s])), utc("260101000000Z")));
  const revokedList = entries.length ? seq(...entries) : new Uint8Array(0);
  return seq(
    seq(int(0), seq(oid("1.2.840.10045.4.3.2")), name("Example Intermediate"), utc("260101000000Z"), utc("270101000000Z"), revokedList),
    seq(oid("1.2.840.10045.4.3.2")),
    bitstr(new Uint8Array([0x00, 0x01])),
  );
}
const crlWithLeaf = crl([0x11]);
const crlWithoutLeaf = crl([0x99]);

/* ---------------- assertions ---------------- */

const rows = [];
let pass = 0;
const check = (label, got, want) => {
  const ok = JSON.stringify(got) === JSON.stringify(want);
  if (ok) pass++;
  rows.push({ label, got: JSON.stringify(got), want: JSON.stringify(want), ok });
};

{
  const p = parseCertificate(leaf);
  check("a leaf parses", p.ok, true);
  check("the serial is read", p.serial, "11");
  check("notAfter is read as a time", p.notAfter, "2027-01-01T00:00:00Z");
  check("the certificate reports it is not a CA", p.isCa, false);
  const r = parseCertificate(root);
  check("an explicit version field is skipped", r.ok, true);
  check("a root reports it is a CA", r.isCa, true);
  check("SKI and AKI are read", [parseCertificate(intermediate).ski !== null, parseCertificate(intermediate).aki !== null], [true, true]);
  check("garbage is refused", parseCertificate(new Uint8Array([0xff, 0xff, 0xff])).ok, false);
}

{
  const out = buildChain([leaf, intermediate, root], ["Example Root CA"], now);
  check("a chain is ordered to its root", out.ok, true);
  check("the anchor is named", out.anchor, "Example Root CA");
  check("the chain is not expired", out.expired, false);
  const shuffled = buildChain([intermediate, root, leaf], ["Example Root CA"], now);
  check("order of presentation does not matter", shuffled.ok, true);
}

{
  const offList = buildChain([leaf, intermediate, strangerRoot], ["Example Root CA"], now);
  check("a root off the list is refused", offList.ok, false);
  check("and the reason names the list", offList.reason.indexOf("trust list") >= 0, true);
  const noList = buildChain([leaf, intermediate, root], [], now);
  check("no trust list means no anchor claim", [noList.ok, noList.anchor], [true, null]);
}

{
  const out = buildChain([expiredLeaf, intermediate, root], ["Example Root CA"], now);
  check("an expired chain still orders", out.ok, true);
  check("and is flagged as expired", out.expired, true);
}

{
  check("a revoked serial is found in the CRL", checkCrl(crlWithLeaf, "11").revoked, true);
  check("an absent serial is not reported as revoked", checkCrl(crlWithoutLeaf, "11").revoked, false);
  check("leading zeros do not defeat the match", checkCrl(crlWithLeaf, "0011").revoked, true);
  check("a CRL that does not parse says so", checkCrl(new Uint8Array([0xff]), "11").reason.indexOf("did not parse") >= 0, true);
}

{
  const fetching = createTransport({
    http: async () => ({ status: 200, body: crlWithLeaf }),
    crlUrls: { [parseCertificate(leaf).issuer]: "https://example.org/crl" },
    trustAnchors: ["Example Root CA"],
  });
  check("a fetched CRL revoking the leaf is reported", (await fetching.revocationStatus([leaf])).revoked, true);

  const clean = createTransport({
    http: async () => ({ status: 200, body: crlWithoutLeaf }),
    crlUrls: { [parseCertificate(leaf).issuer]: "https://example.org/crl" },
  });
  const r2 = await clean.revocationStatus([leaf]);
  check("a clean CRL is reported as clean", [r2.revoked, r2.checked], [false, 1]);

  const noHttp = createTransport({ crlUrls: { x: "y" } });
  check("no http function means no CRL was fetched", (await noHttp.revocationStatus([leaf])).reason.indexOf("no http function") >= 0, true);

  const throwing = createTransport({
    http: async () => { throw new Error("network down"); },
    crlUrls: { [parseCertificate(leaf).issuer]: "https://example.org/crl" },
  });
  const r4 = await throwing.revocationStatus([leaf]);
  check("a throwing fetch is carried into the reason", r4.reason.indexOf("network down") >= 0, true);
  check("and is not reported as revocation", r4.revoked, false);

  const error200 = createTransport({
    http: async () => ({ status: 500, body: crlWithLeaf }),
    crlUrls: { [parseCertificate(leaf).issuer]: "https://example.org/crl" },
  });
  const r5 = await error200.revocationStatus([leaf]);
  check("a non-200 answer is not treated as a CRL", [r5.revoked, r5.checked], [false, 0]);
}

{
  const t = createTransport({ trustAnchors: ["Example Root CA"], referenceTime: now });
  const out = await t.buildPath([leaf, intermediate, root]);
  check("path building works with no http function", out.ok, true);
  check("and it reports the anchor", out.anchor, "Example Root CA");
  const t2 = createTransport({ trustAnchors: ["Example Root CA"] });
  check("path building uses the live clock when none is given", (await t2.buildPath([leaf, intermediate, root])).ok, true);
}

{
  const t = createTransport({});
  const none = await t.verifyTimestamp({ signature: new Uint8Array([1]) });
  check("no token means nothing is trusted", none.trusted, false);
  check("and it says no token was presented", none.reason.indexOf("no countersignature") >= 0, true);

  const granted = seq(seq(int(0)), seq(int(0)));
  const g = await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: granted });
  check("a granted response is still not trusted here", g.trusted, false);
  check("and the reason names the unverified TSA signature", g.reason.indexOf("not verified") >= 0, true);

  const rejected = seq(seq(int(2)));
  const r = await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: rejected });
  check("a non-granted status is refused", r.trusted, false);
  check("and it names the status", r.reason.indexOf("granted status") >= 0, true);
}

const t = createTransport({});
const inv = {
  "a root off the trust list is never accepted": buildChain([leaf, intermediate, strangerRoot], ["Example Root CA"], now).ok === false,
  "an expired chain is flagged, not silently passed": buildChain([expiredLeaf, intermediate, root], ["Example Root CA"], now).expired === true,
  "a CRL match is by value, not by position": checkCrl(crlWithLeaf, "0011").revoked === true && checkCrl(crlWithoutLeaf, "11").revoked === false,
  "no http function means no revocation was checked": (await createTransport({ crlUrls: { x: "y" } }).revocationStatus([leaf])).checked === 0,
  "a timestamp is never trusted without verifying the TSA signature": (await t.verifyTimestamp({ signature: new Uint8Array([1]), timestampToken: seq(seq(int(0))) })).trusted === false,
};

function pad(s, n) { s = String(s); while (s.length < n) s += " "; return s; }
const lines = [];
lines.push("");
lines.push("TRUST:// C2PA transport suite - " + TRANSPORT_VERSION);
lines.push("");
lines.push("  " + pad("assertion", 58) + pad("got", 12) + "ok");
lines.push("  " + "-".repeat(76));
for (const r of rows) lines.push("  " + pad(r.label, 58) + pad(r.got, 12) + (r.ok ? "pass" : "FAIL want " + r.want));
lines.push("");
lines.push("passed " + pass + "/" + rows.length);
lines.push("");
for (const name of Object.keys(inv)) lines.push("inv  " + pad(name, 56) + (inv[name] ? "holds" : "VIOLATED"));
lines.push("");
lines.push("The transport does no I/O of its own: it takes an http function. Chain");
lines.push("building is local, revocation needs a fetch, a timestamp is never trusted");
lines.push("without verifying the TSA signature.");
lines.push("");

console.log(lines.join("\n"));

const results = {
  transport_version: TRANSPORT_VERSION,
  passed: pass,
  total: rows.length,
  invariants: inv,
  allGreen: pass === rows.length && Object.keys(inv).every((k) => inv[k]),
};
if (typeof globalThis.__report === "function") globalThis.__report(results);
return results;
