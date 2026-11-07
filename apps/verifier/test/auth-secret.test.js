import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createAuth } from '../auth.js';

for (const [name, secret] of [
  ['spaces', ' '.repeat(32)],
  ['tabs and line breaks', '\t\n'.repeat(32)],
  ['Unicode whitespace', '\u2003'.repeat(32)]
]) {
  test(`rejects a JWT secret made only of ${name}`, () => {
    assert.throws(() => createAuth(secret), /JWT_SECRET/);
  });
}

test('a randomly generated secret still signs and verifies tokens', () => {
  const auth = createAuth(randomBytes(32).toString('hex'));
  const req = { headers: { authorization: `Bearer ${auth.createAccessToken({ id: 'secret-regression-user' })}` } };
  const res = { set() { assert.fail('valid token must not be denied'); } };
  let calls = 0;
  auth.verifyToken(req, res, () => { calls++; });
  assert.equal(calls, 1);
  assert.deepEqual(req.user, { id: 'secret-regression-user' });
});
