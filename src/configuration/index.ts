import path from 'path';

import dotenv from 'dotenv';

// Load environment variables from .env file
dotenv.config({
  path: path.resolve(process.cwd(), '.env'),
});

// Define configuration interface
export interface Config {
  // Server
  port: number;
  nodeEnv: 'development' | 'production' | 'test';

  // JWT
  jwt: {
    secret: string;
    expiresIn: string;
  };

  // CORS
  cors: {
    allowedOrigins: string[];
  };

  // TURN/STUN
  turn: {
    stunUrl?: string;
    turnUrl?: string;
    turnUsername?: string;
    turnPassword?: string;
  };

  // Rate limiting
  rateLimit: {
    windowMs: number;
    max: number;
  };

  // Logging
  logging: {
    level: string;
    toFile: boolean;
  };

  // Firebase
  firebase: {
    projectId: string;
  };

  // Monitoring
  monitoring: {
    prometheus: {
      enabled: boolean;
      path: string;
    };
  };
}

// Validate and export configuration
export const config: Config = {
  // Server
  port: parseInt(process.env.PORT || '3000', 10),
  nodeEnv: (process.env.NODE_ENV as 'development' | 'production' | 'test') || 'development',

  // JWT
  jwt: {
    secret: process.env.WS_JWT_SECRET || 'default_jwt_secret',
    expiresIn: process.env.JWT_EXPIRES_IN || '1d',
  },

  // CORS
  cors: {
    allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',').map((s) => s.trim()) || [],
  },

  // TURN/STUN
  turn: {
    stunUrl: process.env.STUN_URL,
    turnUrl: process.env.TURN_URL,
    turnUsername: process.env.TURN_USER,
    turnPassword: process.env.TURN_PASS,
  },

  // Rate limiting
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10), // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  },

  // Logging
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    toFile: process.env.LOG_TO_FILE === 'true',
  },

  // Firebase
  firebase: {
    projectId: process.env.FIREBASE_PROJECT_ID || '',
  },

  // Monitoring
  monitoring: {
    prometheus: {
      enabled: process.env.PROMETHEUS_METRICS_ENABLED === 'true',
      path: process.env.PROMETHEUS_METRICS_PATH || '/metrics',
    },
  },
};

// Validate required configuration
if (!config.jwt.secret || config.jwt.secret === 'your_jwt_secret_here') {
  console.warn('WARNING: Using default JWT secret. Set WS_JWT_SECRET in production!');
}

if (config.nodeEnv === 'production') {
  if (!process.env.WS_JWT_SECRET) {
    throw new Error('WS_JWT_SECRET is required in production');
  }

  if (!process.env.FIREBASE_PROJECT_ID) {
    throw new Error('FIREBASE_PROJECT_ID is required in production');
  }

  if (config.cors.allowedOrigins.length === 0) {
    console.warn('WARNING: No allowed origins configured. Set ALLOWED_ORIGINS for production!');
  }
}

export default config;
