// SPDX-License-Identifier: Apache-2.0
// Server-only module. Never import this file into the browser application.
import jwt from 'jsonwebtoken';

const config = Object.freeze({
  secret: process.env.JWT_SECRET,
  expiresIn: '1h',
  algorithm: 'HS256'
});

if (typeof config.secret !== 'string' ||
    config.secret.trim().length === 0 ||
    Buffer.byteLength(config.secret, 'utf8') < 32) {
  throw new Error('JWT_SECRET must be set to a random secret of at least 32 bytes');
}

function isValidUserId(id) {
  return (typeof id === 'string' && id.trim().length > 0) ||
    (typeof id === 'number' && Number.isSafeInteger(id) && id >= 0);
}

// Issue tokens only AFTER authenticating the user in the application.
export function createAccessToken(user) {
  if (!user || !isValidUserId(user.id)) {
    throw new TypeError('A user with a valid id is required');
  }

  return jwt.sign({ id: user.id }, config.secret, {
    algorithm: config.algorithm,
    expiresIn: config.expiresIn,
    subject: String(user.id)
  });
}

function unauthorized(res) {
  res.setHeader('WWW-Authenticate', 'Bearer');
  res.setHeader('Cache-Control', 'no-store');
  return res.status(401).json({ error: 'Missing or invalid token' });
}

export function verifyToken(req, res, next) {
  delete req.user;
  const authHeader = req.headers && req.headers.authorization;
  if (typeof authHeader !== 'string' || authHeader.length > 8192) {
    return unauthorized(res);
  }

  const match = /^Bearer[ \t]+([^\s]+)$/i.exec(authHeader);
  if (!match) return unauthorized(res);

  let decoded;
  try {
    decoded = jwt.verify(match[1], config.secret, {
      algorithms: [config.algorithm],
      maxAge: config.expiresIn
    });
  } catch (error) {
    if (error instanceof jwt.JsonWebTokenError) return unauthorized(res);
    return next(error);
  }

  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded) ||
      !isValidUserId(decoded.id) || decoded.sub !== String(decoded.id) ||
      !Number.isFinite(decoded.iat) || !Number.isFinite(decoded.exp) ||
      decoded.iat > Math.floor(Date.now() / 1000) ||
      decoded.exp <= decoded.iat || decoded.exp - decoded.iat > 3600) {
    return unauthorized(res);
  }

  req.user = {
    id: decoded.id,
    sub: decoded.sub,
    iat: decoded.iat,
    exp: decoded.exp
  };
  // Downstream errors must not be converted into authentication failures.
  return next();
}
