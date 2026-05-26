import { IncomingMessage } from 'http';
import { Socket } from 'net';
import { URL } from 'url';

import { WebSocketServer as WSS, WebSocket } from 'ws';

import { verifyWsToken } from '../../auth/jwt';
import logger from '../../utils/logger';

type UpgradeHandler = (req: IncomingMessage, socket: Socket, head: Buffer) => void;

export function createUpgradeHandler(opts: { wss: WSS; allowedOrigins: string[] }): UpgradeHandler {
  const { wss, allowedOrigins } = opts;

  return (req: IncomingMessage, socket: Socket, head: Buffer): void => {
    (async (): Promise<void> => {
      const origin = (req.headers.origin as string) || '';
      const requestIp = req.socket.remoteAddress || 'unknown';
      const isDevelopment = process.env.NODE_ENV !== 'production';

      // CORS / origin check (skip strict check in development)
      if (!isDevelopment && allowedOrigins[0] !== '*') {
        try {
          const isAllowed = allowedOrigins.some((allowedOrigin) => {
            if (allowedOrigin === '*') return true;
            if (!origin) return false;
            try {
              const originHostname = new URL(origin).hostname;
              const allowedHostname = new URL(allowedOrigin).hostname;
              return (
                originHostname === allowedHostname || originHostname.endsWith(`.${allowedHostname}`)
              );
            } catch (e) {
              logger.warn('Error parsing URL during CORS check: %o', e);
              return false;
            }
          });

          if (!isAllowed) {
            logger.warn(
              `🚫 Blocked WebSocket connection from unauthorized origin: ${origin} (${requestIp})`
            );
            socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
            socket.destroy();
            return;
          }
        } catch (err) {
          logger.error('Error during CORS check: %o', err);
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
          socket.destroy();
          return;
        }
      }

      try {
        const url = new URL(req.url || '/', `http://${req.headers.host}`);
        const token = url.searchParams.get('token');
        const roomId = url.searchParams.get('roomId');

        // Identity comes from the verified JWT in production; URL param is only
        // used as a fallback in development where the token is optional.
        let authenticatedUserId: string | null = isDevelopment
          ? (url.searchParams.get('userId') ?? null)
          : null;

        if (!isDevelopment && !token) {
          socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
          socket.destroy();
          return;
        }

        if (!isDevelopment && token) {
          const jwtResult = await verifyWsToken(token);
          if (!jwtResult || !('ok' in jwtResult) || !jwtResult.ok) {
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
          }
          // Trust JWT payload for identity — never accept URL-param userId in prod
          authenticatedUserId =
            jwtResult.payload.userId ?? jwtResult.payload.sub ?? null;
        }

        wss.handleUpgrade(req, socket, head, (ws: WebSocket) => {
          const client = ws as WebSocket & {
            id?: string;
            userId?: string | null;
            isAlive?: boolean;
            ip?: string;
            userAgent?: string;
            origin?: string;
            roomId?: string | null;
          };

          try {
            client.id =
              authenticatedUserId ||
              client.id ||
              Math.random().toString(36).substring(2, 10);
            client.userId = authenticatedUserId || null;
            client.isAlive = true;
            client.ip = requestIp;
            client.userAgent = (req.headers['user-agent'] as string) || 'unknown';
            client.origin = origin;
            client.roomId = roomId || null;
          } catch (e) {
            logger.debug('Error setting preliminary client fields: %o', e);
          }

          wss.emit('connection', ws, req);
        });
      } catch (err) {
        logger.error('Error during WebSocket upgrade: %o', err);
        try {
          socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        } catch (e) {
          logger.debug('Error writing error response to socket: %o', e);
        } finally {
          socket.destroy();
        }
      }
    })().catch((err) => {
      logger.error('Unexpected error in upgrade handler: %o', err);
      try {
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
      } catch {
        // Ignore errors when trying to write to a potentially closed socket
      }
      socket.destroy();
    });
  };
}
