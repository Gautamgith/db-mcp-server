/**
 * Health Check Module
 *
 * Provides health check endpoints for monitoring service status
 * and database connectivity
 */

import { DatabaseConnectionManager } from '../database/connection-manager.js';
import { Logger } from '../logging/logger.js';

export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  uptime: number;
  version: string;
  checks: {
    server: HealthCheckResult;
    databases: DatabaseHealthResult[];
  };
}

export interface HealthCheckResult {
  status: 'pass' | 'fail';
  message: string;
  timestamp: string;
}

export interface DatabaseHealthResult {
  id: string;
  name: string;
  status: 'pass' | 'fail';
  message: string;
  responseTime: number | undefined;
  connected: boolean;
}

/**
 * Health check handler
 */
export class HealthCheckHandler {
  private startTime: number;
  private connectionManager: DatabaseConnectionManager;
  private logger: Logger;

  constructor(connectionManager: DatabaseConnectionManager, logger: Logger) {
    this.startTime = Date.now();
    this.connectionManager = connectionManager;
    this.logger = logger;
  }

  /**
   * Get comprehensive health status
   */
  async getHealthStatus(): Promise<HealthStatus> {
    const serverHealth = this.checkServerHealth();
    const databasesHealth = await this.checkDatabasesHealth();

    // Determine overall status
    let overallStatus: 'healthy' | 'degraded' | 'unhealthy' = 'healthy';

    if (serverHealth.status === 'fail') {
      overallStatus = 'unhealthy';
    } else if (databasesHealth.some(db => db.status === 'fail')) {
      const failedCount = databasesHealth.filter(db => db.status === 'fail').length;
      overallStatus = failedCount === databasesHealth.length ? 'unhealthy' : 'degraded';
    }

    return {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: this.getUptime(),
      version: process.env.MCP_SERVER_VERSION || '1.0.0',
      checks: {
        server: serverHealth,
        databases: databasesHealth
      }
    };
  }

  /**
   * Get simple liveness check
   */
  getLivenessStatus(): { status: string; timestamp: string } {
    return {
      status: 'alive',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Get readiness check
   */
  async getReadinessStatus(): Promise<{ status: string; timestamp: string; ready: boolean }> {
    const databases = this.connectionManager.listDatabases();
    const enabledDatabases = databases.filter(db => db.enabled);

    // Service is ready if at least one database is connected
    const connectedCount = enabledDatabases.filter(db => db.connected).length;
    const ready = connectedCount > 0 || enabledDatabases.length === 0;

    return {
      status: ready ? 'ready' : 'not_ready',
      timestamp: new Date().toISOString(),
      ready
    };
  }

  /**
   * Check server health
   */
  private checkServerHealth(): HealthCheckResult {
    try {
      const uptime = this.getUptime();
      const memoryUsage = process.memoryUsage();
      const heapUsedMB = Math.round(memoryUsage.heapUsed / 1024 / 1024);

      return {
        status: 'pass',
        message: `Server running for ${uptime}s, heap: ${heapUsedMB}MB`,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      return {
        status: 'fail',
        message: error instanceof Error ? error.message : 'Unknown error',
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Check all database connections
   */
  private async checkDatabasesHealth(): Promise<DatabaseHealthResult[]> {
    const databases = this.connectionManager.listDatabases();

    const healthChecks = databases.map(async (db) => {
      if (!db.enabled) {
        return {
          id: db.id,
          name: db.name,
          status: 'pass' as const,
          message: 'Disabled',
          responseTime: undefined,
          connected: false
        };
      }

      try {
        const startTime = Date.now();
        const connectionInfo = await this.connectionManager.checkConnection(db.id);
        const responseTime = Date.now() - startTime;

        if (connectionInfo.connected) {
          return {
            id: db.id,
            name: db.name,
            status: 'pass' as const,
            message: 'Connected',
            responseTime,
            connected: true
          };
        } else {
          return {
            id: db.id,
            name: db.name,
            status: 'fail' as const,
            message: connectionInfo.error || 'Connection failed',
            responseTime,
            connected: false
          };
        }
      } catch (error) {
        return {
          id: db.id,
          name: db.name,
          status: 'fail' as const,
          message: error instanceof Error ? error.message : 'Unknown error',
          responseTime: undefined,
          connected: false
        };
      }
    });

    return Promise.all(healthChecks);
  }

  /**
   * Get server uptime in seconds
   */
  private getUptime(): number {
    return Math.floor((Date.now() - this.startTime) / 1000);
  }
}
