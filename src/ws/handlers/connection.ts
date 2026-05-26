import { IncomingMessage } from 'http';
import { URL } from 'url';

import { RawData, WebSocket as WS } from 'ws';
import { RateLimiterMemory } from 'rate-limiter-flexible';

import logger from '../../utils/logger';
import { safeParse } from '../../utils/safeParse';
import { WebSocketClient, RoomDoc, RoomManagerLike } from '../../types/webSocket';

import { startHeartbeat } from './heartbeat';
import { handleMessage } from './messageHandler';

const messageRateLimiter = new RateLimiterMemory({
  points: 100, // 100 messages
  duration: 10, // per 10 seconds per client
  blockDuration: 60, // block for 1 minute if limit is exceeded
});

// Track message rates per client
const clientMessageRates = new Map<string, number>();

interface Ctx {
  wss: InstanceType<typeof WS.Server>;
  rooms: Map<string, RoomDoc>;
  roomManager: RoomManagerLike;
  activeConnections: Set<WebSocketClient>;
  instanceId: string;
  logger: typeof logger;
}

export async function handleConnection(wsRaw: WS, req: IncomingMessage, ctx: Ctx): Promise<void> {
  const { rooms, roomManager, activeConnections } = ctx;
  const ws = wsRaw as WebSocketClient;

  // Initialize socket metadata — keep same as original
  ws.id = ws.id || Math.random().toString(36).slice(2, 10); // fallback if not set earlier
  ws.isAlive = true;
  ws.ip = ws.ip || req.socket?.remoteAddress || 'unknown';
  ws.userAgent =
    ws.userAgent || (req.headers && (req.headers['user-agent'] as string)) || 'unknown';
  ws.origin = ws.origin || (req.headers && (req.headers.origin as string)) || 'unknown';
  ws.roomId =
    ws.roomId ??
    (req.url ? new URL(req.url, `http://${req.headers.host}`).searchParams.get('roomId') : null);

  activeConnections.add(ws);
  logger.info('New WebSocket connection', { clientId: ws.id, userId: ws.userId });

  // heartbeat
  const stopHeartbeat = startHeartbeat(ws as any, {
    intervalMs: 30_000,
    maxMissed: 3,
    onTerminate() {
      activeConnections.delete(ws);
      try {
        removeClientFromAuthoritativeRoom();
      } catch (err) {
        logger.warn('removeClientFromAuthoritativeRoom threw in onTerminate: %o', err);
      }
      void (async (): Promise<void> => {
        try {
          await roomManager.removeAllByClientId(ws.id);
        } catch (e) {
          logger.warn('removeAllByClientId failed: %o', e);
        }
      })();
    },
  });

  // helper to remove from authoritative rooms (used in cleanup)
  function removeClientFromAuthoritativeRoom(): void {
    try {
      const prevRoom = ws.roomId ?? null;
      if (!prevRoom) return;
      const room = rooms.get(prevRoom);
      if (!room) return;
      room.clients.delete(ws);
      // delete room when empty, same as before
      if (room.clients.size === 0) rooms.delete(prevRoom);
    } catch (err) {
      logger.warn('Error removing client from authoritative room: %o', err);
    }
  }

  // cleanup routine
  const cleanup = async (): Promise<void> => {
    const prevRoom = ws.roomId ?? null;
    logger.debug('Starting cleanup for connection', { clientId: ws.id, roomId: prevRoom });

    try {
      stopHeartbeat();
    } catch (error) {
      logger.warn('Error stopping heartbeat', {
        clientId: ws.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }

    // remove from active set
    activeConnections.delete(ws);

    // remove rate tracking
    clientMessageRates.delete(ws.id);

    // notify peers
    try {
      // broadcastPeersUpdate imported inside handler to avoid circular import
      const { broadcastPeersUpdate } = await import('../../utils/wsHelpers');
      broadcastPeersUpdate(activeConnections, prevRoom);
    } catch (err) {
      logger.warn('broadcastPeersUpdate failed in cleanup: %o', err);
    }

    removeClientFromAuthoritativeRoom();

    try {
      await roomManager.removeAllByClientId(ws.id);
    } catch (err) {
      logger.warn('roomManager.removeAllByClientId failed for %s: %o', ws.id, err);
    }
  };

  ws.on('close', () => {
    logger.info('WebSocket connection closed', { clientId: ws.id });
    void cleanup();
  });

  ws.on('error', (err: Error) => {
    logger.error('WebSocket client error', {
      clientId: ws.id,
      error: err.message,
      stack: err.stack,
    });
    // Terminate triggers 'close', which runs cleanup — don't call cleanup() here directly.
    ws.terminate();
  });

  // Message handler with rate limiting and error handling
  ws.on('message', async (data: RawData, isBinary: boolean): Promise<void> => {
    const startTime = Date.now();
    let messageType = 'unknown';

    try {
      // Parse the incoming message
      const strOrBuffer = isBinary ? data : data.toString();
      const message = safeParse<unknown>(strOrBuffer as any);

      if (!message || typeof message !== 'object') {
        throw new Error('Invalid message format');
      }

      // message is unknown but we can treat it as Record<string, unknown>
      const msgObj = message as Record<string, unknown>;
      messageType = (typeof msgObj.type === 'string' && msgObj.type) || 'unknown';

      logger.debug('Processing message', {
        clientId: ws.id,
        messageType,
        isBinary,
        size: typeof data === 'string' ? Buffer.byteLength(data) : (data as Buffer).length,
      });

      // Apply rate limiting
      try {
        const rateLimit = await messageRateLimiter.get(ws.id);
        if (rateLimit && rateLimit.consumedPoints > 90) {
          logger.debug('Approaching rate limit', {
            clientId: ws.id,
            consumed: rateLimit.consumedPoints,
            remaining: rateLimit.remainingPoints,
          });
        }

        await messageRateLimiter.consume(ws.id);
      } catch (rateLimiterRes: unknown) {
        const rateLimitInfo =
          (rateLimiterRes as { msBeforeNext?: number; remainingPoints?: number }) || {};
        logger.warn('Rate limit exceeded', {
          clientId: ws.id,
          messageType,
          remainingMs: rateLimitInfo.msBeforeNext || 0,
          remainingPoints: rateLimitInfo.remainingPoints || 0,
        });

        try {
          ws.send(
            JSON.stringify({
              type: 'error',
              from: 'server',
              error: 'Rate limit exceeded. Please try again later.',
              retryAfter: rateLimitInfo.msBeforeNext
                ? Math.ceil(rateLimitInfo.msBeforeNext / 1000)
                : 60,
            })
          );
        } catch (sendError: unknown) {
          logger.warn('Failed to send rate limit error to client', {
            clientId: ws.id,
            error: sendError instanceof Error ? sendError.message : String(sendError),
          });
        }
        return;
      }

      // Track message rate for analytics
      const messageCount = (clientMessageRates.get(ws.id) || 0) + 1;
      clientMessageRates.set(ws.id, messageCount);

      if (messageCount % 10 === 0) {
        logger.debug('Message rate update', {
          clientId: ws.id,
          messageCount,
          messageType,
        });
      }

      // Process the message
      const processStart = Date.now();
      await handleMessage({ ws, message: msgObj, ctx });

      logger.debug('Message processed', {
        clientId: ws.id,
        messageType,
        durationMs: Date.now() - processStart,
        totalDurationMs: Date.now() - startTime,
      });
    } catch (error: unknown) {
      const errorContext = {
        clientId: ws.id,
        messageType,
        durationMs: Date.now() - startTime,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      };

      logger.error('Error handling message', errorContext);

      try {
        const { sendToClient } = await import('../../utils/wsHelpers');
        sendToClient(ws, {
          type: 'error',
          from: 'server',
          payload: {
            message: 'Error processing message',
            requestId: Math.random().toString(36).substring(2, 10),
          },
        });
      } catch (sendError: unknown) {
        logger.warn('Failed to send error to client', {
          ...errorContext,
          sendError: sendError instanceof Error ? sendError.message : String(sendError),
        });
      }
    }
  });

  // send initial connected message + peers
  try {
    if (ws.readyState === (WS as any).OPEN) {
      const { getPeers } = await import('../../utils/wsHelpers');
      ws.send(
        JSON.stringify({
          type: 'connected',
          from: 'server',
          payload: {
            message: 'Connected',
            id: ws.id,
            peers: getPeers(activeConnections, ws.roomId ?? null),
          },
          timestamp: Date.now(),
        })
      );
    }
  } catch (err: unknown) {
    logger.debug('Failed to send connected payload to %s: %o', ws.id, err);
  }

  // broadcast peers update
  try {
    const { broadcastPeersUpdate } = await import('../../utils/wsHelpers');
    broadcastPeersUpdate(activeConnections, ws.roomId ?? null);
  } catch (err: unknown) {
    logger.warn('broadcastPeersUpdate failed after connect: %o', err);
  }
}
