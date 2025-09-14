import { DatabaseConfig, ConnectionPoolConfig } from '../types/index.js';

export function createDatabaseConfig(): DatabaseConfig {
  const requiredEnvVars = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'AWS_REGION'];

  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Required environment variable ${envVar} is not set`);
    }
  }

  return {
    host: process.env.DB_HOST!,
    port: parseInt(process.env.DB_PORT!, 10),
    database: process.env.DB_NAME!,
    user: process.env.DB_USER!,
    region: process.env.AWS_REGION!
  };
}

export function createConnectionPoolConfig(): ConnectionPoolConfig {
  return {
    max: parseInt(process.env.DB_POOL_MAX ?? '10', 10),
    min: parseInt(process.env.DB_POOL_MIN ?? '2', 10),
    idle_timeout_ms: parseInt(process.env.DB_POOL_IDLE_TIMEOUT ?? '30000', 10),
    connection_timeout_ms: parseInt(process.env.DB_POOL_CONNECTION_TIMEOUT ?? '5000', 10)
  };
}