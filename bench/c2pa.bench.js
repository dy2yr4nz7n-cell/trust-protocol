import { bench, describe } from "vitest";
import {
  readJumbf,
  extractManifestCbor,
  decodeCbor,
  parseCoseSign1,
  findDigest,
  sha256Hex,
  createC2paVerifier,
} from "../c2pa-verifier.js";
import { makeManifestFile } from "./fixtures.js";

const small = await makeManifestFile({ assetSize: 4 * 1024, extraAssertions: 8, certSize: 256 });
const large = await makeManifestFile({ assetSize: 1024 * 1024, extraAssertions: 200, certSize: 4096 });
const largeClaim = decodeCbor(large.payload).value;

/* Signature and chain providers that always succeed, so the verifier walks
 * every layer (container, COSE, digest, signature, chain) end to end. */
const verifier = createC2paVerifier({
  crypto: async () => ({ ok: true }),
  chain: async () => ({ ok: true, anchor: "Bench Root" }),
});

describe("c2pa container", () => {
  bench("readJumbf: 1 MiB file", () => {
    readJumbf(large.bytes);
  });

  bench("extractManifestCbor: 1 MiB file", () => {
    extractManifestCbor(large.bytes);
  });
});

describe("c2pa cbor/cose", () => {
  bench("decodeCbor: claim with 200 assertions", () => {
    decodeCbor(large.payload);
  });

  bench("parseCoseSign1: 4 KiB certificate", () => {
    parseCoseSign1(large.cose);
  });

  bench("findDigest: claim with 200 assertions", () => {
    findDigest(largeClaim);
  });
});

describe("c2pa digest", () => {
  bench("sha256Hex: 1 MiB", async () => {
    await sha256Hex(large.bytes);
  });
});

describe("c2pa verifier", () => {
  bench("verify: small manifest", async () => {
    await verifier.verify({ bytes: small.bytes, assetRange: small.assetRange });
  });

  bench("verify: 1 MiB asset", async () => {
    await verifier.verify({ bytes: large.bytes, assetRange: large.assetRange });
  });
});
