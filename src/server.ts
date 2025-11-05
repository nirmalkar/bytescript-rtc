import http from 'http';

import compression from 'compression';
import express from 'express';
import type { Request, Response } from 'express';

import { config } from './configuration';
import { signWsToken } from './auth/jwt';
import createSecurityMiddleware from './middleware/security';
import { createWsServer } from './ws/wsServer';

interface ServerWithShutdown extends http.Server {
  shutdown?: () => Promise<void>;
}

interface ServerReturnType {
  app: express.Express;
  server: ServerWithShutdown;
  wsServer: ReturnType<typeof createWsServer>;
}

export function createServer(): ServerReturnType {
  const app = express();

  const securityMiddleware = createSecurityMiddleware(config);
  app.use(securityMiddleware);

  app.use(express.json({ limit: '10kb' }));

  // Enable compression
  app.use(compression());

  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ ok: true, service: 'bytescript-rtc' });
  });

  // Return ICE servers object for clients (protect in prod)
  app.get('/api/turn', (_req: Request, res: Response) => {
    const iceServers: Array<Record<string, unknown>> = [];

    // Add STUN server if configured
    if (config.turn.stunUrl) {
      iceServers.push({ urls: config.turn.stunUrl });
    }

    // Add TURN server if configured
    if (config.turn.turnUrl && config.turn.turnUsername && config.turn.turnPassword) {
      iceServers.push({
        urls: config.turn.turnUrl,
        username: config.turn.turnUsername,
        credential: config.turn.turnPassword,
      });
    }

    return res.json({ iceServers });
  });

  app.post('/api/ws-token', (req: Request, res: Response) => {
    // In production, you should validate the user session/authorization here
    // For example:
    // if (!req.user) {
    //   return res.status(403).json({ error: 'Unauthorized' });
    // }

    // Get user ID and room ID from the request
    const userId = typeof req.body?.userId === 'string' ? req.body.userId : undefined;
    const roomId = typeof req.body?.roomId === 'string' ? req.body.roomId : undefined;

    if (!userId) {
      return res.status(400).json({ error: 'User ID is required' });
    }

    if (!config.jwt.secret || config.jwt.secret === 'default_jwt_secret') {
      console.error('JWT secret is not properly configured');
      return res.status(500).json({ error: 'server_misconfigured' });
    }

    try {
      const token = signWsToken(
        // payload
        {
          ...(userId ? { userId } : {}),
          ...(roomId ? { roomId } : {}),
        },
        // opts
        { expiresIn: '5m' }
      );

      return res.json({ token });
    } catch (err) {
      console.error('Failed to sign WS token', err);
      return res.status(500).json({ error: 'token_generation_failed' });
    }
  });

  const server: ServerWithShutdown = http.createServer(app) as ServerWithShutdown;
  const wsServer = createWsServer(server);

  return { app, server, wsServer };
}
