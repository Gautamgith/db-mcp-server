import { Pool, PoolClient } from 'pg';
import { DatabaseConfig, ConnectionPoolConfig } from '../types/index.js';

export class DatabaseConnection {
  private pool: Pool | null = null;
  private config: DatabaseConfig;
  private poolConfig: ConnectionPoolConfig;

  constructor(config: DatabaseConfig, poolConfig: ConnectionPoolConfig) {
    this.config = config;
    this.poolConfig = poolConfig;
  }

  async initialize(): Promise<void> {
    if (this.pool) {
      return;
    }

    this.pool = new Pool({
      host: this.config.host,
      port: this.config.port,
      database: this.config.database,
      user: this.config.user,
      ssl: {
        rejectUnauthorized: false
      },
      max: this.poolConfig.max,
      min: this.poolConfig.min,
      idleTimeoutMillis: this.poolConfig.idle_timeout_ms,
      connectionTimeoutMillis: this.poolConfig.connection_timeout_ms,
    });

    this.pool.on('error', (err) => {
      console.error('Database pool error:', err);
    });

    await this.testConnection();
  }

  async testConnection(): Promise<void> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    const client = await this.pool.connect();
    try {
      await client.query('SELECT 1');
    } finally {
      client.release();
    }
  }

  async getClient(): Promise<PoolClient> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }
    return await this.pool.connect();
  }

  async query<T = any>(text: string, params?: any[]): Promise<{ rows: T[]; rowCount: number }> {
    const client = await this.getClient();
    try {
      const start = Date.now();
      const result = await client.query(text, params);
      const duration = Date.now() - start;

      console.log('Query executed:', {
        duration: `${duration}ms`,
        rows: result.rowCount ?? 0
      });

      return {
        rows: result.rows,
        rowCount: result.rowCount ?? 0
      };
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }

  isConnected(): boolean {
    return this.pool !== null;
  }
}