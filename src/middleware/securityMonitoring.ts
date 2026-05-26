// Core Node.js modules
import { IncomingHttpHeaders } from 'http';

// Third-party modules
import type { Request, Response, NextFunction } from 'express';

// Internal modules
import logger from '../utils/logger';

type SecurityContext = {
  method: string;
  path: string;
  ip?: string;
  userId?: string;
  requestId: string;
  userAgent?: string | IncomingHttpHeaders['user-agent'];
};

interface CustomRequest extends Request {
  user?: {
    id?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export function securityMonitoringMiddleware(
  req: CustomRequest,
  res: Response,
  next: NextFunction
): void {
  const start = Date.now();
  const requestId =
    typeof req.headers['x-request-id'] === 'string'
      ? req.headers['x-request-id']
      : Math.random().toString(36).substring(2, 9);

  // Create security context for logging
  const securityContext: SecurityContext = {
    method: req.method,
    path: req.path,
    ip: req.ip || (req.connection && req.connection.remoteAddress) || undefined,
    userAgent: req.headers['user-agent'],
    userId: (req.user && req.user.id) || 'anonymous',
    requestId,
  };

  // Monitor for suspicious headers
  monitorSuspiciousHeaders(req.headers, securityContext);

  // Monitor for common attack patterns
  monitorAttackPatterns(req, securityContext);

  // Log authentication attempts
  if (isAuthPath(req.path)) {
    // mark attempt; successful auth should update this later
    logger.logAuthAttempt(
      false,
      'Authentication attempt',
      { path: req.path, method: req.method },
      securityContext
    );
  }

  // Response monitoring — wrap send to capture body & timing
  const originalSend = res.send.bind(res);
   
  res.send = function (body?: unknown): Response {
    const responseTime = Date.now() - start;

    // Log slow responses (> 1s)
    if (responseTime > 1000) {
      logger.warn('Slow response detected', {
        ...securityContext,
        responseTime: `${responseTime}ms`,
        statusCode: res.statusCode,
      });
    }

    // Log error responses (>= 400)
    if (res.statusCode >= 400) {
      const safeBody =
        typeof body === 'string'
          ? body.substring(0, 500)
          : typeof body === 'object'
            ? JSON.stringify(body).substring(0, 500)
            : 'Response body not logged';
      logger.error('Error response', {
        ...securityContext,
        statusCode: res.statusCode,
        response: safeBody,
      });
    }

    // call original send
    // `originalSend` expects unknown typed body; use as unknown
    return originalSend(body as any);
  };

  next();
}

export function monitorSuspiciousHeaders(
  headers: IncomingHttpHeaders,
  context: SecurityContext
): void {
  // x-forwarded-for, x-real-ip, and cf-connecting-ip are standard proxy/CDN headers
  // and are intentionally excluded to avoid false-positive alerts
  const suspiciousHeaders = [
    'x-originating-ip',
    'x-remote-ip',
    'x-remote-addr',
    'x-client-ip',
  ];

  const detectedSuspiciousHeaders = Object.entries(headers).filter(([key]) =>
    suspiciousHeaders.includes(key.toLowerCase())
  );

  if (detectedSuspiciousHeaders.length > 0) {
    logger.logSuspiciousActivity(
      {
        message: 'Suspicious headers detected',
        metadata: {
          headers: detectedSuspiciousHeaders,
          requestId: context.requestId,
        },
      },
      context
    );
  }
}

export function monitorAttackPatterns(req: Request, context: SecurityContext): void {
  const attackPatterns: Array<{ pattern: RegExp; name: string }> = [
    { pattern: /<script[^>]*>.*<\/script>/gi, name: 'HTML Injection' },
    {
      pattern: /\b(?:union\s+select|select\s+\*\s+from|drop\s+table|1=1|\/\*.*\*\/)/gi,
      name: 'SQL Injection',
    },
    {
      pattern:
        /\b(?:eval\(|setTimeout\(|setInterval\(|Function\(|document\.|window\.|location\.)/gi,
      name: 'JavaScript Injection',
    },
    { pattern: /\$\{[^}]+\}/gi, name: 'Template Injection' },
  ];

  const queryString = ((): string => {
    try {
      return JSON.stringify(req.query);
    } catch {
      return String(req.query);
    }
  })();

  const bodyString = ((): string => {
    try {
      // don't stringify huge bodies
      const s = JSON.stringify((req as unknown as { body?: unknown }).body);
      return s.length > 1000 ? s.substring(0, 1000) : s;
    } catch {
      return 'unserializable';
    }
  })();

  const requestString = `${req.method} ${req.path} ${queryString} ${bodyString}`;

  const detectedAttacks = attackPatterns
    .filter(({ pattern }) => pattern.test(requestString))
    .map(({ name }) => name);

  if (detectedAttacks.length > 0) {
    logger.logSuspiciousActivity(
      {
        message: 'Possible attack pattern detected in request',
        metadata: {
          attackTypes: detectedAttacks,
          requestId: context.requestId,
          path: req.path,
          method: req.method,
        },
      },
      context
    );
  }
}

export function isAuthPath(path: string): boolean {
  const authPaths = ['/auth', '/login', '/signin', '/register', '/signup'];
  return authPaths.some((authPath) => path.includes(authPath));
}

type LimiterLike = {
  limit: (ip: string | undefined, cb: (err?: unknown) => void) => void;
};

export function createWebSocketRateLimitMiddleware(limiter: LimiterLike) {
  return (req: Request, res: Response, next: NextFunction): void => {
    limiter.limit(
      req.ip || (req.connection && req.connection.remoteAddress) || undefined,
      (err?: unknown) => {
        if (err) {
          logger.logSuspiciousActivity(
            {
              message: 'WebSocket rate limit exceeded',
              metadata: {
                ip: req.ip || (req.connection && req.connection.remoteAddress),
                path: req.path,
                userAgent: req.headers['user-agent'],
              },
            },
            {
              method: req.method,
              path: req.path,
              requestId: req.headers['x-request-id']?.toString() || 'unknown',
            } as SecurityContext
          );

          res.status(429).json({ error: 'Too many requests, please try again later.' });
          return;
        }
        next();
      }
    );
  };
}
