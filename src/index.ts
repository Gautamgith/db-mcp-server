#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DatabaseConnection } from './database/connection.js';
import { DatabaseQueries } from './database/queries.js';
import { IAMDatabaseConnection } from './database/iam-connection.js';
import { IAMDatabaseQueries } from './database/iam-queries.js';
import { UnifiedDatabaseTools } from './tools/database-tools-unified.js';
import { Logger } from './logging/logger.js';
import { createDatabaseConfig, createConnectionPoolConfig } from './database/config.js';

/**
 * Unified PostgreSQL MCP Server
 *
 * Features:
 * - Supports both standard and IAM authentication (configured via USE_IAM_AUTH env var)
 * - Comprehensive security: SQL injection prevention, rate limiting, complexity analysis
 * - Complete toolset: introspection, query execution, security analysis, monitoring
 * - Production-ready: audit logging, error handling, graceful shutdown
 */
class PostgreSQLMCPServer {
  private server: Server;
  private logger: Logger;
  private db: DatabaseConnection | IAMDatabaseConnection;
  private queries: DatabaseQueries | IAMDatabaseQueries;
  private tools: UnifiedDatabaseTools;
  private useIAM: boolean;

  constructor() {
    this.logger = new Logger();
    this.useIAM = process.env.USE_IAM_AUTH === 'true';

    this.logger.info('Initializing PostgreSQL MCP Server', {
      authentication_method: this.useIAM ? 'IAM' : 'Standard',
      security_features: [
        'SQL injection prevention',
        'Query pattern validation',
        'Rate limiting',
        'Complexity analysis',
        'Audit logging'
      ]
    });

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    // Initialize database connection based on authentication method
    if (this.useIAM) {
      this.db = new IAMDatabaseConnection(dbConfig, poolConfig, this.logger);
      this.queries = new IAMDatabaseQueries(this.db as IAMDatabaseConnection, this.logger);
    } else {
      this.db = new DatabaseConnection(dbConfig, poolConfig);
      this.queries = new DatabaseQueries(this.db as DatabaseConnection);
    }

    // Initialize unified tools with all features
    this.tools = new UnifiedDatabaseTools(this.queries, this.logger, this.useIAM);

    // Initialize MCP server
    this.server = new Server(
      {
        name: process.env.MCP_SERVER_NAME ?? 'postgresql-mcp',
        version: process.env.MCP_SERVER_VERSION ?? '1.0.0'
      },
      {
        capabilities: {
          tools: {}
        }
      }
    );

    this.setupHandlers();
  }

  private setupHandlers(): void {
    // Handle tool listing
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.tools.getToolDefinitions()
    }));

    // Handle tool execution
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        // Extract client ID from request metadata if available
        const clientId = (request as any).meta?.clientId || 'default';

        const result = await this.tools.handleToolCall(name, args ?? {}, clientId);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2)
            }
          ]
        };
      } catch (error) {
        this.logger.error('Tool call failed', {
          tool: name,
          error: error instanceof Error ? error.message : String(error),
          authentication_method: this.useIAM ? 'IAM' : 'Standard'
        });

        // Handle rate limiting errors with specific status
        if (error instanceof Error && error.message.includes('Rate limit exceeded')) {
          const mcpError = {
            code: -32429,
            message: error.message,
            data: {
              error_type: 'RATE_LIMIT_EXCEEDED',
              details: error.message,
              retry_after: error.message.match(/(\d+) seconds/)?.[1]
            }
          };
          throw mcpError;
        }

        throw error;
      }
    });
  }

  async start(): Promise<void> {
    try {
      this.logger.info('Starting PostgreSQL MCP Server');

      // Initialize database connection
      await this.db.initialize();

      this.logger.info('Database connection initialized', {
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      });

      // Connect to MCP transport
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      this.logger.info('MCP Server started successfully', {
        authentication_method: this.useIAM ? 'IAM' : 'Standard',
        tools_available: this.tools.getToolDefinitions().length,
        security_features: [
          'Advanced SQL injection prevention',
          'Query pattern allowlisting',
          'Rate limiting with configurable windows',
          'Query complexity analysis',
          'Parameter sanitization',
          'Input validation',
          'Comprehensive audit logging'
        ]
      });
    } catch (error) {
      this.logger.error('Failed to start server', {
        error: error instanceof Error ? error.message : String(error),
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      });
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping PostgreSQL MCP Server');

      await this.db.close();

      this.logger.info('Server stopped successfully');
    } catch (error) {
      this.logger.error('Error during server shutdown', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

async function main(): Promise<void> {
  const server = new PostgreSQLMCPServer();

  // Graceful shutdown handlers
  process.on('SIGINT', async () => {
    console.log('\nReceived SIGINT, shutting down gracefully...');
    await server.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\nReceived SIGTERM, shutting down gracefully...');
    await server.stop();
    process.exit(0);
  });

  await server.start();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error('Fatal error:', error);
    process.exit(1);
  });
}
