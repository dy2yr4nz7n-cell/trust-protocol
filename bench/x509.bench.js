import { bench, describe } from "vitest";
import { decodeOid, parseX509Certificate, verifyCertificateSignature } from "../x509-parser.js";
import { encodeOid, mintChain } from "./fixtures.js";

const ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

const { intermediate, leaf, chain } = await mintChain();
const oids = [
  "1.2.840.10045.2.1",
  ECDSA_WITH_SHA256,
  "1.3.132.0.34",
  "2.5.4.3",
  "1.2.840.113549.1.1.11",
].map((o) => encodeOid(o).slice(2));

describe("x509 parsing", () => {
  bench("parseX509Certificate: 3-cert chain", () => {
    for (const der of chain) parseX509Certificate(der);
  });

  bench("decodeOid", () => {
    for (const o of oids) decodeOid(o);
  });
});

describe("x509 signatures", () => {
  bench("verifyCertificateSignature: ECDSA P-384 leaf", async () => {
    await verifyCertificateSignature(leaf.tbs, leaf.signature, intermediate.spki, ECDSA_WITH_SHA256);
  });
});
