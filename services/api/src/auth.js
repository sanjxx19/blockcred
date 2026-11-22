import { randomUUID } from 'node:crypto';
import { BlockCredError } from '@blockcred/sdk/util';
import { deriveAuthSecret } from '@blockcred/sdk/keywrap';
import { hashSecret, newToken, sha256Hex, verifySecret } from './crypto.js';

export const SESSION_COOKIE = 'bc_session';
const DUMMY_HASH = hashSecret('timing-equaliser');

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

/** Loads req.user from the HttpOnly session cookie (SameSite=Strict => no CSRF from other sites). */
export function sessionMiddleware({ pool }) {
  return async (req, _res, next) => {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (token) {
      const { rows } = await pool.query(
        `SELECT u.id, u.email, u.role, u.display_name
           FROM sessions s JOIN users u ON u.id = s.user_id
          WHERE s.token_hash = $1 AND s.expires_at > now() AND NOT u.disabled`,
        [sha256Hex(token)],
      );
      if (rows[0]) {
        req.user = rows[0];
        req.sessionTokenHash = sha256Hex(token);
      }
    }
    next();
  };
}

export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'UNAUTHENTICATED', message: 'Please log in' });
    if (roles.length && !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'FORBIDDEN', message: `This action requires a ${roles.join(' or ')} account` });
    }
    next();
  };
}

export async function startSession({ pool, config }, res, userId) {
  const token = newToken();
  const expires = new Date(Date.now() + config.sessionTtlHours * 3600_000);
  await pool.query('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [sha256Hex(token), userId, expires]);
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: 'strict',
    secure: config.cookieSecure,
    path: '/',
    expires,
  });
}

export async function endSession({ pool }, req, res) {
  if (req.sessionTokenHash) await pool.query('DELETE FROM sessions WHERE token_hash = $1', [req.sessionTokenHash]);
  res.clearCookie(SESSION_COOKIE, { path: '/' });
}

export async function createUser(db, { email, secret, role, displayName }) {
  const id = randomUUID();
  try {
    await db.query('INSERT INTO users (id, email, password_hash, role, display_name) VALUES ($1, $2, $3, $4, $5)', [
      id,
      email.toLowerCase(),
      await hashSecret(secret),
      role,
      displayName,
    ]);
  } catch (err) {
    if (err.code === '23505') throw new BlockCredError('EMAIL_TAKEN', 'An account with this email already exists');
    throw err;
  }
  return id;
}

export async function authenticate({ pool }, email, secret) {
  const { rows } = await pool.query('SELECT id, password_hash, disabled FROM users WHERE email = $1', [email.toLowerCase()]);
  const user = rows[0];
  // Always run scrypt to avoid leaking which emails exist via timing.
  const ok = await verifySecret(secret, user?.password_hash ?? (await DUMMY_HASH));
  if (!user || !ok || user.disabled) throw new BlockCredError('INVALID_CREDENTIALS', 'Wrong email or password');
  return user.id;
}

/** Creates or updates the accreditation-admin account from .env at start-up. */
export async function ensureAdmin({ pool, config, logger }) {
  const secret = await deriveAuthSecret(config.admin.email, config.admin.password);
  const { rows } = await pool.query('SELECT id FROM users WHERE email = $1', [config.admin.email]);
  if (rows[0]) {
    await pool.query(`UPDATE users SET password_hash = $2, role = 'admin', display_name = $3 WHERE id = $1`, [
      rows[0].id,
      await hashSecret(secret),
      config.admin.name,
    ]);
  } else {
    await createUser(pool, { email: config.admin.email, secret, role: 'admin', displayName: config.admin.name });
    logger.info({ email: config.admin.email }, 'created admin account');
  }
}
