import { copyFile } from 'node:fs/promises';
import { join } from 'node:path';

export const PROTOCOL_ASSETS = Object.freeze([
  'index.html', 'manifest.webmanifest', 'record-0.2.schema.json',
  'engine.js', 'derivation.js', 'signature.js', 'fingerprint.js',
  'verifier-bridge.js', 'demo-verifier.js', 'vectors.js',
  'c2pa-providers.js', 'c2pa-transport.js', 'c2pa-tsr.js',
  'c2pa-verifier.js', 'x509-chain-transport.js', 'x509-parser.js'
]);

export async function copyProtocolAssets(root, destination) {
  for (const file of PROTOCOL_ASSETS) {
    await copyFile(join(root, file), join(destination, file));
  }
}
