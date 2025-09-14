import { Pool, PoolClient, PoolConfig } from 'pg';
import { DatabaseConfig, ConnectionPoolConfig } from '../types/index.js';
import { IAMAuthenticator } from '../auth/iam-auth.js';
import { Logger } from '../logging/logger.js';

export class IAMDatabaseConnection {
  private pool: Pool | null = null;
  private config: DatabaseConfig;
  private poolConfig: ConnectionPoolConfig;
  private iamAuth: IAMAuthenticator;
  private logger: Logger;
  private reconnectAttempts = 0;
  private readonly MAX_RECONNECT_ATTEMPTS = 3;

  constructor(
    config: DatabaseConfig,
    poolConfig: ConnectionPoolConfig,
    logger: Logger
  ) {
    this.config = config;
    this.poolConfig = poolConfig;
    this.logger = logger;
    this.iamAuth = new IAMAuthenticator(config, logger);
  }

  async initialize(): Promise<void> {
    if (this.pool) {
      return;
    }

    await this.createPool();
    await this.testConnection();

    this.logger.info('IAM-authenticated database connection initialized', {
      host: this.config.host,
      database: this.config.database,
      user: this.config.user
    });
  }

  private async createPool(): Promise<void> {
    try {
      const token = await this.iamAuth.getAuthToken();

      const poolConfig: PoolConfig = {
        host: this.config.host,
        port: this.config.port,
        database: this.config.database,
        user: this.config.user,
        password: token,
        ssl: {
          rejectUnauthorized: false
        },
        max: this.poolConfig.max,
        min: this.poolConfig.min,
        idleTimeoutMillis: this.poolConfig.idle_timeout_ms,
        connectionTimeoutMillis: this.poolConfig.connection_timeout_ms,
        allowExitOnIdle: false
      };

      this.pool = new Pool(poolConfig);

      this.pool.on('error', async (err) => {
        this.logger.error('Database pool error detected', {
          error: err.message,
          reconnect_attempts: this.reconnectAttempts
        });

        if (this.isAuthenticationError(err) && this.reconnectAttempts < this.MAX_RECONNECT_ATTEMPTS) {
          await this.handleAuthenticationError();
        }
      });

      this.pool.on('connect', () => {
        this.reconnectAttempts = 0;
        this.logger.debug('New database connection established');
      });

    } catch (error) {
      this.logger.error('Failed to create database pool', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  private async handleAuthenticationError(): Promise<void> {
    this.reconnectAttempts++;

    this.logger.warn('Handling authentication error, attempting reconnect', {
      attempt: this.reconnectAttempts,
      max_attempts: this.MAX_RECONNECT_ATTEMPTS
    });

    try {
      // Close existing pool
      if (this.pool) {
        await this.pool.end();
        this.pool = null;
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * this.reconnectAttempts));

      // Create new pool with fresh token
      await this.createPool();

      this.logger.info('Successfully reconnected after authentication error', {
        attempt: this.reconnectAttempts
      });

    } catch (error) {
      this.logger.error('Reconnection attempt failed', {
        attempt: this.reconnectAttempts,
        error: error instanceof Error ? error.message : String(error)
      });

      if (this.reconnectAttempts >= this.MAX_RECONNECT_ATTEMPTS) {
        throw new Error(`Failed to reconnect after ${this.MAX_RECONNECT_ATTEMPTS} attempts`);
      }
    }
  }

  private isAuthenticationError(error: Error): boolean {
    const authErrorMessages = [
      'password authentication failed',
      'connection terminated unexpectedly',
      'connection closed',
      'iam authentication',
      'authentication failed'
    ];

    return authErrorMessages.some(msg =>
      error.message.toLowerCase().includes(msg.toLowerCase())
    );
  }

  async testConnection(): Promise<void> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    const client = await this.pool.connect();
    try {
      const result = await client.query('SELECT current_user, version(), now() as connected_at');

      this.logger.info('Database connection test successful', {
        user: result.rows[0]?.current_user,
        connected_at: result.rows[0]?.connected_at,
        token_expires_in_ms: this.iamAuth.getTimeUntilExpiry()
      });

    } finally {
      client.release();
    }
  }

  async getClient(): Promise<PoolClient> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    // Check if token needs refresh before getting connection
    if (this.iamAuth.isTokenExpired()) {
      this.logger.info('Token expired, refreshing connection pool');
      await this.refreshPool();
    }

    try {
      return await this.pool.connect();
    } catch (error) {
      if (this.isAuthenticationError(error as Error)) {
        this.logger.warn('Connection failed due to authentication, attempting refresh');
        await this.handleAuthenticationError();
        return await this.pool!.connect();
      }
      throw error;
    }
  }

  private async refreshPool(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }

    await this.createPool();
  }

  async query<T = any>(text: string, params?: any[]): Promise<{ rows: T[]; rowCount: number }> {
    const client = await this.getClient();
    try {
      const start = Date.now();
      const result = await client.query(text, params);
      const duration = Date.now() - start;

      this.logger.debug('Query executed with IAM auth', {
        duration: `${duration}ms`,
        rows: result.rowCount ?? 0,
        token_expires_in_ms: this.iamAuth.getTimeUntilExpiry()
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
      this.logger.info('Closing IAM database connection pool');
      await this.pool.end();
      this.pool = null;
    }
  }

  isConnected(): boolean {
    return this.pool !== null && !this.iamAuth.isTokenExpired();
  }

  getAuthInfo() {
    return {
      token_info: this.iamAuth.getTokenInfo(),
      reconnect_attempts: this.reconnectAttempts,
      is_connected: this.isConnected()
    };
  }
}