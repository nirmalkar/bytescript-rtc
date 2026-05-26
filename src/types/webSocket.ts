import { WebSocket as WS } from 'ws';
import { SignalingMessage } from './types';

export interface CustomWebSocket extends WS {
  isAlive?: boolean;
  lastActivity?: number;
  roomId?: string;
  userId?: string;
  clientId?: string;
  uid?: string;
  [key: string]: any;
}

export type RoomManagerLike = {
  addMember: (
    roomId: string,
    clientId: string,
    ws: CustomWebSocket | undefined,
    uid: string,
    name?: string | null
  ) => Promise<void>;
  removeMember: (roomId: string, clientId: string) => Promise<void>;
  removeAllByClientId: (clientId: string) => Promise<void>;
  listParticipants: (roomId: string) => Promise<any[]>;
  broadcast: (roomId: string, message: SignalingMessage, exceptClientId?: string) => Promise<void>;
  sendToClient?: (
    roomId: string,
    targetClientId: string,
    message: SignalingMessage
  ) => Promise<boolean>;
};

export interface CursorPayload {
  type: string;
  [key: string]: any;
}

export interface PeerInfo {
  id: string;
  userAgent?: string;
  ip?: string;
  origin?: string;
  roomId?: string | null;
}

export interface WebSocketClient extends WS {
  id: string;
  userId?: string;
  isAlive: boolean;
  ip?: string;
  userAgent?: string;
  origin?: string;
  roomId?: string | null;
}

/** Authoritative room document */
export interface RoomDoc {
  version: number;
  text: string;
  clients: Set<WebSocketClient>;
}

export const DEFAULT_ALLOWED_ORIGINS = ['http://localhost:3000', 'http://localhost:3001'];
