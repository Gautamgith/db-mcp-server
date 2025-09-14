#!/usr/bin/env node

import { IAMDatabaseConnection } from '../database/iam-connection.js';
import { createDatabaseConfig, createConnectionPoolConfig } from '../database/config.js';
import { Logger } from '../logging/logger.js';

async function testIAMConnection(): Promise<void> {
  const logger = new Logger();

  try {
    logger.info('Testing IAM database connection...');

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    logger.info('Database configuration for IAM auth:', {
      host: dbConfig.host,
      port: dbConfig.port,
      database: dbConfig.database,
      user: dbConfig.user,
      region: dbConfig.region
    });

    const db = new IAMDatabaseConnection(dbConfig, poolConfig, logger);

    logger.info('Initializing IAM connection...');
    await db.initialize();

    logger.info('Testing IAM-authenticated query...');
    const result = await db.query(`
      SELECT
        version() as pg_version,
        current_database() as database,
        current_user as authenticated_user,
        now() as connection_time
    `);

    logger.info('IAM connection test successful!', {
      pg_version: result.rows[0]?.pg_version?.split(' ')[0],
      database: result.rows[0]?.database,
      authenticated_user: result.rows[0]?.authenticated_user,
      connection_time: result.rows[0]?.connection_time,
      auth_info: db.getAuthInfo()
    });

    // Test connection health
    const health = await db.query(`
      SELECT
        pg_is_in_recovery() as is_replica,
        extract(epoch from now() - pg_postmaster_start_time()) as uptime_seconds,
        (SELECT count(*) FROM pg_stat_activity) as active_connections
    `);

    logger.info('Database health check:', {
      is_replica: health.rows[0]?.is_replica,
      uptime_hours: Math.round((health.rows[0]?.uptime_seconds || 0) / 3600),
      active_connections: health.rows[0]?.active_connections
    });

    await db.close();
    logger.info('IAM connection closed successfully');

  } catch (error) {
    logger.error('IAM connection test failed', {
      error: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  testIAMConnection().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}