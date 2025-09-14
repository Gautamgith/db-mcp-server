#!/usr/bin/env node

import { DatabaseConnection } from '../database/connection.js';
import { createDatabaseConfig, createConnectionPoolConfig } from '../database/config.js';
import { Logger } from '../logging/logger.js';

async function testConnection(): Promise<void> {
  const logger = new Logger();

  try {
    logger.info('Testing database connection...');

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    logger.info('Database configuration:', {
      host: dbConfig.host,
      port: dbConfig.port,
      database: dbConfig.database,
      user: dbConfig.user,
      region: dbConfig.region
    });

    const db = new DatabaseConnection(dbConfig, poolConfig);

    logger.info('Initializing connection...');
    await db.initialize();

    logger.info('Testing basic query...');
    const result = await db.query('SELECT version(), current_database(), current_user');

    logger.info('Connection test successful!', {
      version: result.rows[0]?.version,
      database: result.rows[0]?.current_database,
      user: result.rows[0]?.current_user
    });

    await db.close();
    logger.info('Connection closed successfully');

  } catch (error) {
    logger.error('Connection test failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  testConnection().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}