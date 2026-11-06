// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import jwt from 'jsonwebtoken';

const secret = randomBytes(48).toString('hex');
process.env.JWT_SECRET = secret;
const { createAccessToken, verifyToken } = await import('../auth.js');
const now = Math.floor(Date.now() / 1000);

function run(header) {
  const req = { headers: { authorization: header }, user: { id: 'stale' } };
  const res = {
    headers: {}, code: 200, body: undefined,
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.code = code; return this; },
    json(body) { this.body = body; return this; }
  };
  let calls = 0;
  let forwarded;
  verifyToken(req, res, error => { calls++; forwarded = error; });
  return { req, res, get calls() { return calls; }, get forwarded() { return forwarded; } };
}
function signed(payload, options = {}) {
  return jwt.sign(payload, secret, { algorithm: 'HS256', ...options });
}
function rejected(header) {
  const result = run(header);
  assert.equal(result.res.code, 401);
  assert.equal(result.calls, 0);
  assert.equal(result.req.user, undefined);
  assert.equal(result.res.headers['WWW-Authenticate'], 'Bearer');
  assert.equal(result.res.headers['Cache-Control'], 'no-store');
  assert.deepEqual(result.res.body, { error: 'Missing or invalid token' });
}

test('object payload expires in exactly one hour and omits private fields', () => {
  const decoded = jwt.verify(createAccessToken({ id: 42, password: 'do-not-copy', role: 'admin' }), secret);
  assert.equal(decoded.exp - decoded.iat, 3600);
  assert.equal(decoded.id, 42);
  assert.equal(decoded.sub, '42');
  assert.equal(decoded.password, undefined);
  assert.equal(decoded.role, undefined);
});
for (const id of [0, 42, 'abc-123']) {
  test(`accepts supported user id ${JSON.stringify(id)}`, () => {
    const result = run(`Bearer ${createAccessToken({ id })}`);
    assert.equal(result.calls, 1);
    assert.equal(result.forwarded, undefined);
    assert.equal(result.req.user.id, id);
  });
}
for (const [label, user] of [
  ['missing', undefined], ['null', null], ['empty', {}], ['empty id', { id: '' }],
  ['whitespace id', { id: ' ' }], ['object id', { id: {} }], ['negative id', { id: -1 }],
  ['fractional id', { id: 1.5 }], ['unsafe integer', { id: Number.MAX_SAFE_INTEGER + 1 }]
]) {
  test(`rejects invalid user: ${label}`, () => assert.throws(() => createAccessToken(user), TypeError));
}
for (const [label, header] of [
  ['missing', undefined], ['null', null], ['array', ['Bearer a']], ['empty', ''],
  ['basic', 'Basic abc'], ['no token', 'Bearer '], ['extra token', 'Bearer abc def'],
  ['malformed jwt', 'Bearer abc'], ['newline', 'Bearer abc\n'], ['oversized', 'Bearer ' + 'a'.repeat(8192)]
]) {
  test(`rejects authorization header: ${label}`, () => rejected(header));
}
test('accepts case-insensitive scheme and multiple separator spaces', () => {
  assert.equal(run(`bearer  ${createAccessToken({ id: 'u' })}`).calls, 1);
});
test('rejects invalid signature', () => rejected('Bearer ' + jwt.sign({ id: 'u' }, randomBytes(48), { expiresIn: '1h' })));
test('rejects expired token', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', iat: now - 100, exp: now - 1 })));
test('rejects not-yet-active token', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', exp: now + 3600, nbf: now + 120 })));
test('rejects different algorithm', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', exp: now + 3600 }, { algorithm: 'HS384' })));
test('rejects unsigned token', () => rejected('Bearer ' + jwt.sign({ id: 'u', sub: 'u', exp: now + 3600 }, null, { algorithm: 'none' })));
test('rejects string payload', () => rejected('Bearer ' + signed('u')));
test('rejects missing expiration', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u' })));
test('rejects missing issued-at', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', exp: now + 100 }, { noTimestamp: true })));
test('rejects mismatched subject', () => rejected('Bearer ' + signed({ id: 'u', sub: 'other', exp: now + 100 })));
test('rejects missing id', () => rejected('Bearer ' + signed({ sub: 'u', exp: now + 100 })));
test('rejects overlong lifetime', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', iat: now, exp: now + 7200 })));
test('rejects expiration before issuance', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', iat: now + 200, exp: now + 100 })));
test('does not expose additional signed payload fields', () => {
  const result = run('Bearer ' + signed({ id: 'u', sub: 'u', exp: now + 100, admin: true }));
  assert.equal(result.calls, 1);
  assert.deepEqual(Object.keys(result.req.user).sort(), ['exp', 'iat', 'id', 'sub']);
});
test('does not catch downstream middleware exceptions', () => {
  assert.throws(() => verifyToken(
    { headers: { authorization: `Bearer ${createAccessToken({ id: 1 })}` } }, {},
    () => { throw new Error('downstream'); }
  ), /downstream/);
});
for (const [label, value] of [['missing', undefined], ['empty', ''], ['short', 'abc'], ['whitespace', ' '.repeat(40)]]) {
  test(`fails at startup with ${label} secret`, () => {
    const env = { ...process.env };
    if (value === undefined) delete env.JWT_SECRET;
    else env.JWT_SECRET = value;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', 'import "./auth.js";'], {
      cwd: fileURLToPath(new URL('../', import.meta.url)), env, encoding: 'utf8'
    });
    assert.equal(child.status, 1);
    assert.match(child.stderr, /JWT_SECRET must be set/);
  });
}
test('unexpected verifier exceptions go to application error handling', () => {
  const original = jwt.verify;
  const fault = new Error('unexpected internal failure');
  jwt.verify = () => { throw fault; };
  try {
    const result = run('Bearer abc');
    assert.equal(result.calls, 1);
    assert.equal(result.forwarded, fault);
    assert.equal(result.res.code, 200);
    assert.equal(result.req.user, undefined);
  } finally { jwt.verify = original; }
});
test('rejects issuance in the future', () => rejected('Bearer ' + signed({ id: 'u', sub: 'u', iat: now + 120, exp: now + 3600 })));
test('rejects a changed payload retaining the original signature', () => {
  const parts = createAccessToken({ id: 'u' }).split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
  payload.id = 'admin';
  payload.sub = 'admin';
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  rejected('Bearer ' + parts.join('.'));
});
