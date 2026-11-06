import jwt from 'jsonwebtoken';

export function createAuth(secret = process.env.JWT_SECRET) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new Error('JWT_SECRET must contain at least 32 bytes of random secret material');
  }
  const issuer = 'trust-protocol', audience = 'trust-verifier-api';
  function createAccessToken(user) {
    const id = Number.isSafeInteger(user?.id) ? String(user.id) : user?.id;
    if (typeof id !== 'string' || !id.trim() || id.length > 200) throw new TypeError('Invalid user.id');
    return jwt.sign({ id }, secret, { subject: id, algorithm: 'HS256', expiresIn: '1h', issuer, audience });
  }
  function verifyToken(req, res, next) {
    const header = req.headers.authorization;
    const match = typeof header === 'string' && /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i.exec(header);
    const deny = () => res.set('WWW-Authenticate', 'Bearer realm="trust-api"').status(401).json({ error: 'Missing or invalid token' });
    if (!match || match[1].length > 8192) return deny();
    let payload;
    try {
      payload = jwt.verify(match[1], secret, { algorithms: ['HS256'], issuer, audience, maxAge: '1h' });
    } catch { return deny(); }
    const now = Math.floor(Date.now() / 1000);
    if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string' || !payload.sub.trim() || payload.sub.length > 200 || payload.id !== payload.sub || !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp) || payload.iat > now || payload.exp <= payload.iat || payload.exp - payload.iat > 3600) return deny();
    req.user = Object.freeze({ id: payload.sub });
    next();
  }
  return { createAccessToken, verifyToken };
}
