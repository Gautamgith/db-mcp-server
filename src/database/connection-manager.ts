/**
 * Multi-Database Connection Manager
 *
 * Manages connections to multiple PostgreSQL databases
 * Supports both standard and IAM authentication per database
 */

import { DatabaseConnection } from './connection.js';
import { DatabaseQueries } from './queries.js';
import { IAMDatabaseConnection } from './iam-connection.js';
import { IAMDatabaseQueries } from './iam-queries.js';
import { Logger } from '../logging/logger.js';
import { DatabaseConfig, ConnectionPoolConfig } from '../types/index.js';

export interface DatabaseDefinition {
  id: string;
  name: string;
  description: string | undefined;
  host: string;
  port: number;
  database: string;
  user: string;
  password: string | undefined;
  useIAM: boolean;
  awsRegion: string | undefined;
  enabled: boolean;
  poolConfig: Partial<ConnectionPoolConfig> | undefined;
}

export interface DatabaseConnectionInfo {
  id: string;
  name: string;
  description: string | undefined;
  host: string;
  port: number;
  database: string;
  user: string;
  useIAM: boolean;
  enabled: boolean;
  connected: boolean;
  lastChecked: Date | undefined;
  error: string | undefined;
}

export class DatabaseConnectionManager {
  private logger: Logger;
  private connections: Map<string, DatabaseConnection | IAMDatabaseConnection>;
  private queries: Map<string, DatabaseQueries | IAMDatabaseQueries>;
  private definitions: Map<string, DatabaseDefinition>;
  private defaultDatabaseId: string | undefined;

  constructor(logger: Logger) {
    this.logger = logger;
    this.connections = new Map();
    this.queries = new Map();
    this.definitions = new Map();
  }

  /**
   * Load database configurations from environment variables
   */
  loadFromEnvironment(): void {
    // Parse DATABASE_CONFIGS JSON array from environment
    const configsJson = process.env.DATABASE_CONFIGS;

    if (configsJson) {
      try {
        const configs = JSON.parse(configsJson) as DatabaseDefinition[];
        configs.forEach(config => this.addDatabase(config));
        this.logger.info('Loaded database configurations from DATABASE_CONFIGS', {
          count: configs.length,
          databases: configs.map(c => c.id)
        });
      } catch (error) {
        this.logger.error('Failed to parse DATABASE_CONFIGS', {
          error: error instanceof Error ? error.message : String(error)
        });
      }
    } else {
      // Fallback: Load single database from legacy env vars
      this.loadLegacyConfiguration();
    }

    // Set default database
    const defaultId = process.env.DEFAULT_DATABASE_ID;
    if (defaultId && this.definitions.has(defaultId)) {
      this.defaultDatabaseId = defaultId;
    } else if (this.definitions.size > 0) {
      // Use first database as default
      const firstKey = Array.from(this.definitions.keys())[0];
      this.defaultDatabaseId = firstKey || undefined;
    }

    this.logger.info('Database connection manager initialized', {
      total_databases: this.definitions.size,
      default_database: this.defaultDatabaseId
    });
  }

  /**
   * Load legacy single-database configuration
   */
  private loadLegacyConfiguration(): void {
    const config: DatabaseDefinition = {
      id: 'default',
      name: process.env.DB_NAME || 'Default Database',
      description: 'Legacy single database configuration',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '5432', 10),
      database: process.env.DB_NAME || 'postgres',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || undefined,
      useIAM: process.env.USE_IAM_AUTH === 'true',
      awsRegion: process.env.AWS_REGION || undefined,
      enabled: true,
      poolConfig: undefined
    };

    this.addDatabase(config);
    this.defaultDatabaseId = 'default';

    this.logger.info('Loaded legacy single-database configuration', {
      database_id: 'default',
      host: config.host,
      database: config.database,
      use_iam: config.useIAM
    });
  }

  /**
   * Add a database configuration
   */
  addDatabase(definition: DatabaseDefinition): void {
    if (this.definitions.has(definition.id)) {
      this.logger.warn('Database already exists, replacing', {
        database_id: definition.id
      });
    }

    this.definitions.set(definition.id, definition);

    this.logger.info('Database configuration added', {
      database_id: definition.id,
      name: definition.name,
      host: definition.host,
      database: definition.database,
      use_iam: definition.useIAM
    });
  }

  /**
   * Get or create connection to a database
   */
  async getConnection(databaseId?: string): Promise<DatabaseConnection | IAMDatabaseConnection> {
    const dbId = databaseId || this.defaultDatabaseId;

    if (!dbId) {
      throw new Error('No database specified and no default database configured');
    }

    if (!this.definitions.has(dbId)) {
      throw new Error(`Database not found: ${dbId}`);
    }

    const definition = this.definitions.get(dbId)!;

    if (!definition.enabled) {
      throw new Error(`Database is disabled: ${dbId}`);
    }

    // Return existing connection if available
    if (this.connections.has(dbId)) {
      return this.connections.get(dbId)!;
    }

    // Create new connection
    await this.createConnection(dbId, definition);
    return this.connections.get(dbId)!;
  }

  /**
   * Get queries interface for a database
   */
  async getQueries(databaseId?: string): Promise<DatabaseQueries | IAMDatabaseQueries> {
    const dbId = databaseId || this.defaultDatabaseId;

    if (!dbId) {
      throw new Error('No database specified and no default database configured');
    }

    // Ensure connection exists
    await this.getConnection(dbId);

    return this.queries.get(dbId)!;
  }

  /**
   * Create connection for a database
   */
  private async createConnection(
    databaseId: string,
    definition: DatabaseDefinition
  ): Promise<void> {
    this.logger.info('Creating database connection', {
      database_id: databaseId,
      name: definition.name,
      host: definition.host,
      use_iam: definition.useIAM
    });

    const dbConfig: DatabaseConfig = {
      host: definition.host,
      port: definition.port,
      database: definition.database,
      user: definition.user,
      region: definition.awsRegion || process.env.AWS_REGION || 'us-west-2'
    };

    const poolConfig: ConnectionPoolConfig = {
      max: parseInt(process.env.DB_POOL_MAX || '10', 10),
      min: parseInt(process.env.DB_POOL_MIN || '2', 10),
      idle_timeout_ms: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '30000', 10),
      connection_timeout_ms: parseInt(process.env.DB_POOL_CONNECTION_TIMEOUT || '5000', 10)
    };

    try {
      if (definition.useIAM) {
        // Create IAM connection
        const connection = new IAMDatabaseConnection(dbConfig, poolConfig, this.logger);
        const queries = new IAMDatabaseQueries(connection, this.logger);

        this.connections.set(databaseId, connection);
        this.queries.set(databaseId, queries);

        // Test connection
        await connection.initialize();
      } else {
        // Create standard connection
        const connection = new DatabaseConnection(dbConfig, poolConfig);
        const queries = new DatabaseQueries(connection);

        this.connections.set(databaseId, connection);
        this.queries.set(databaseId, queries);

        // Test connection
        await connection.initialize();
      }

      this.logger.info('Database connection established', {
        database_id: databaseId,
        name: definition.name
      });
    } catch (error) {
      this.logger.error('Failed to create database connection', {
        database_id: databaseId,
        name: definition.name,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * List all configured databases
   */
  listDatabases(): DatabaseConnectionInfo[] {
    const databases: DatabaseConnectionInfo[] = [];

    for (const [id, definition] of this.definitions.entries()) {
      const connected = this.connections.has(id);

      databases.push({
        id,
        name: definition.name,
        description: definition.description,
        host: definition.host,
        port: definition.port,
        database: definition.database,
        user: definition.user,
        useIAM: definition.useIAM,
        enabled: definition.enabled,
        connected,
        lastChecked: undefined,
        error: undefined
      });
    }

    return databases;
  }

  /**
   * Check connection health for a database
   */
  async checkConnection(databaseId: string): Promise<DatabaseConnectionInfo> {
    const definition = this.definitions.get(databaseId);

    if (!definition) {
      throw new Error(`Database not found: ${databaseId}`);
    }

    const info: DatabaseConnectionInfo = {
      id: databaseId,
      name: definition.name,
      description: definition.description,
      host: definition.host,
      port: definition.port,
      database: definition.database,
      user: definition.user,
      useIAM: definition.useIAM,
      enabled: definition.enabled,
      connected: false,
      lastChecked: new Date(),
      error: undefined
    };

    if (!definition.enabled) {
      info.error = 'Database is disabled';
      return info;
    }

    try {
      const connection = await this.getConnection(databaseId);

      // Test connection by calling testConnection
      await connection.testConnection();

      info.connected = true;
    } catch (error) {
      info.connected = false;
      info.error = error instanceof Error ? error.message : String(error);

      this.logger.error('Database connection check failed', {
        database_id: databaseId,
        error: info.error
      });
    }

    return info;
  }

  /**
   * Close connection to a database
   */
  async closeConnection(databaseId: string): Promise<void> {
    const connection = this.connections.get(databaseId);

    if (!connection) {
      return;
    }

    try {
      await connection.close();
      this.connections.delete(databaseId);
      this.queries.delete(databaseId);

      this.logger.info('Database connection closed', {
        database_id: databaseId
      });
    } catch (error) {
      this.logger.error('Failed to close database connection', {
        database_id: databaseId,
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Close all connections
   */
  async closeAll(): Promise<void> {
    const closePromises = Array.from(this.connections.keys()).map(id =>
      this.closeConnection(id).catch(error => {
        this.logger.error('Error closing connection during shutdown', {
          database_id: id,
          error: error instanceof Error ? error.message : String(error)
        });
      })
    );

    await Promise.all(closePromises);

    this.logger.info('All database connections closed', {
      count: closePromises.length
    });
  }

  /**
   * Get default database ID
   */
  getDefaultDatabaseId(): string | undefined {
    return this.defaultDatabaseId;
  }

  /**
   * Set default database
   */
  setDefaultDatabase(databaseId: string): void {
    if (!this.definitions.has(databaseId)) {
      throw new Error(`Database not found: ${databaseId}`);
    }

    this.defaultDatabaseId = databaseId;

    this.logger.info('Default database changed', {
      database_id: databaseId
    });
  }

  /**
   * Get database definition
   */
  getDatabase(databaseId: string): DatabaseDefinition | undefined {
    return this.definitions.get(databaseId);
  }
}
