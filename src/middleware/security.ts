import cors, { CorsOptions } from 'cors';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import type { Request, Response, NextFunction, RequestHandler } from 'express';

import type { Config } from '../configuration';
import { logger } from '../utils/logger';

import { securityMonitoringMiddleware } from './securityMonitoring';


export function createSecurityMiddleware(config: Config): RequestHandler[] {
  const corsOptions: CorsOptions = {
    origin: (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void
    ) => {
      try {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);

        if (!config.cors?.allowedOrigins?.length) {
          // If no allowed origins are configured, allow all in development only
          if (config.nodeEnv === 'development') {
            logger.warn('No CORS allowed origins configured, allowing all in development');
            return callback(null, true);
          }
          logger.error('CORS not properly configured in production');
          return callback(new Error('CORS not configured properly'));
        }

        // Allow if origin is in allowed list or if wildcard is present
        if (
          config.cors.allowedOrigins.includes(origin) ||
          config.cors.allowedOrigins.includes('*')
        ) {
          return callback(null, true);
        }

        logger.warn(`CORS request blocked from origin: ${origin}`);
        callback(new Error('Not allowed by CORS'));
      } catch (error) {
        logger.error('Error in CORS validation', { error });
        callback(error instanceof Error ? error : new Error('CORS validation failed'));
      }
    },
    credentials: true,
    optionsSuccessStatus: 200, // For legacy browser support
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
  };

  // Default rate limiter for most API endpoints
  const defaultLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req: Request, res: Response) => {
      res.status(429).json({ error: 'Too many requests, please try again later.' });
    },
    skip: (req: Request) => {
      // Skip rate limiting for health checks and in development
      return req.path === '/api/health' || config.nodeEnv === 'development';
    },
  });

  // Stricter rate limiter for authentication endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 20, // limit each IP to 20 requests per windowMs for auth endpoints
    message: { error: 'Too many login attempts, please try again later.' },
    handler: (req: Request, res: Response) => {
      logger.warn('Authentication rate limit exceeded', {
        ip: req.ip,
        path: req.path,
        method: req.method,
        userAgent: req.headers['user-agent'],
      });
      res.status(429).json({ error: 'Too many login attempts, please try again later.' });
    },
  });

  // Apply rate limiting based on path
  const rateLimiter: RequestHandler = (req: Request, res: Response, next: NextFunction) => {
    if (req.path.startsWith('/api/auth/')) {
      return authLimiter(req, res, next);
    }
    if (req.path.startsWith('/api/')) {
      return defaultLimiter(req, res, next);
    }
    return next();
  };

  // Security headers middleware with enhanced CSP
  return [
    // Security monitoring middleware (should be first to catch all requests)
    securityMonitoringMiddleware as unknown as RequestHandler,

    // Apply CORS before other middleware
    cors(corsOptions),

    // Rate limiting for HTTP requests
    rateLimiter,

    // Set security headers using helmet with more permissive CSP for web apps
    helmet({
      contentSecurityPolicy: {
        useDefaults: true,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "'unsafe-inline'", // Required for some web frameworks
            "'unsafe-eval'", // Required for some web frameworks
          ],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https: data:'],
          connectSrc: ["'self'", 'ws:', 'wss:'],
          fontSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          mediaSrc: ["'self'"],
          frameAncestors: ["'none'"],
          formAction: ["'self'"],
          baseUri: ["'self'"],
        },
      },
      frameguard: {
        action: 'deny',
      },
      hsts: {
        maxAge: 63072000, // 2 years
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      referrerPolicy: {
        policy: 'strict-origin-when-cross-origin',
      },
    }),

    // Disable X-Powered-By header
    (_req: Request, res: Response, next: NextFunction): void => {
      res.removeHeader('X-Powered-By');
      next();
    },
  ];
}

// Ensure module exposes both named + default export to avoid CJS/ESM interop issues
export default createSecurityMiddleware;
