import jwt from 'jsonwebtoken';

import logger from '../utils/logger';

const SECRET = process.env.WS_JWT_SECRET || '';

export type JwtVerifyResult =
  | {
      ok: true;
      payload: any;
    }
  | {
      ok: false;
      error: string;
      details?: string;
    };

export function verifyWsToken(token: string): JwtVerifyResult {
  if (!SECRET) {
    logger.error('JWT Error: No secret configured');
    return { ok: false, error: 'no_secret_configured' };
  }

  if (!token) {
    logger.error('JWT Error: No token provided');
    return { ok: false, error: 'no_token_provided' };
  }

  try {
    const verified = jwt.verify(token, SECRET, { complete: false, ignoreExpiration: false });
    const decoded = typeof verified === 'string' ? JSON.parse(verified) : verified;

    if (!decoded) {
      logger.error('JWT Error: Invalid token format - cannot decode');
      return { ok: false, error: 'invalid_token_format' };
    }

    const userId = decoded.sub || decoded.userId;

    if (!userId) {
      logger.error('JWT Error: Missing required fields (sub or userId)');
      return { ok: false, error: 'missing_user_identifier' };
    }

    const payload = {
      ...decoded,
      sub: userId,
      userId: userId,
      uid: userId,
      ...(decoded.roomId && { roomId: decoded.roomId }),
      ...(decoded.name && { name: decoded.name }),
      ...(decoded.role && { role: decoded.role }),
    };

    logger.debug('JWT verified successfully', { userId, roomId: decoded.roomId });

    return { ok: true, payload };
  } catch (err: any) {
    logger.warn('JWT verification failed', {
      name: err.name,
      message: err.message,
      expiredAt: err.expiredAt,
    });

    return {
      ok: false,
      error: err.name === 'TokenExpiredError' ? 'token_expired' : 'invalid_token',
      details: err.message,
    };
  }
}

interface SignTokenOptions {
  expiresIn?: string | number;
}

export function signWsToken(payload: Record<string, any>, opts?: SignTokenOptions): string {
  if (!SECRET) {
    throw new Error('WS_JWT_SECRET is not configured on the server');
  }
  // Ensure we don't accidentally sign dangerous fields here — sanitize payload in real world.
  const signOptions: jwt.SignOptions = {
    algorithm: 'HS256',
  };

  if (opts?.expiresIn !== undefined) {
    signOptions.expiresIn = opts.expiresIn as any;
  } else {
    signOptions.expiresIn = '5m';
  }

  return jwt.sign(payload, SECRET, signOptions);
}

export function verifyWsTokenStrict(token: string): JwtVerifyResult {
  if (!SECRET) {
    logger.error('JWT Error: No secret configured');
    return { ok: false, error: 'no_secret_configured' };
  }

  if (!token) {
    return { ok: false, error: 'no_token_provided' };
  }

  try {
    const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] }) as any;

    if (!decoded || typeof decoded !== 'object') {
      return { ok: false, error: 'invalid_token_format' };
    }

    const userId = decoded.sub ?? decoded.userId ?? decoded.uid;
    if (!userId) {
      return { ok: false, error: 'missing_user_identifier' };
    }

    const payload = {
      ...decoded,
      sub: userId,
      userId,
      uid: userId,
      roomId: decoded.roomId ?? null,
      role: decoded.role ?? null,
      name: decoded.name ?? null,
    };

    return { ok: true, payload };
  } catch (err: any) {
    const name = err?.name ?? 'UnknownError';
    const message = err?.message ?? String(err);
    logger.warn('JWT verification failed (strict)', { name, message });

    const error =
      name === 'TokenExpiredError'
        ? 'token_expired'
        : name === 'JsonWebTokenError'
          ? 'invalid_token'
          : 'token_verification_failed';

    return { ok: false, error, details: message };
  }
}
