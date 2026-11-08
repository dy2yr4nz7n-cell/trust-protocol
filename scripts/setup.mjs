import './load-env.mjs';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import { createAuth } from '../apps/verifier/auth.js';
import { writePrivateFile } from './private-file.mjs';
let secret = process.env.JWT_SECRET;
if (!secret) {
  if (existsSync('.env')) throw new Error('.env exists without JWT_SECRET. Please configure it; existing settings will not be overwritten.');
  secret = randomBytes(48).toString('base64url');
  await writeFile('.env', `JWT_SECRET=${secret}\nPUBLIC_ORIGIN=http://127.0.0.1:3000\nDATA_DIR=./data\n`, { mode: 0o600, flag: 'wx' });
}
await writePrivateFile('access-token.txt', createAuth(secret).createAccessToken({ id: process.argv[2] || 'local-owner' }) + '\n');
console.log('Local setup ready. Your 1-hour token is in access-token.txt (never commit or share). Use http://127.0.0.1:3000.');
