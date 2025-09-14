#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DatabaseConnection } from './database/connection.js';
import { DatabaseQueries } from './database/queries.js';
import { DatabaseTools } from './tools/database-tools.js';
import { IAMDatabaseConnection } from './database/iam-connection.js';
import { IAMDatabaseQueries } from './database/iam-queries.js';
import { IAMDatabaseTools } from './tools/iam-database-tools.js';
import { SecureDatabaseTools } from './tools/secure-database-tools.js';
import { Logger } from './logging/logger.js';
import { createDatabaseConfig, createConnectionPoolConfig } from './database/config.js';

class SecurePostgreSQLMCPServer {
  private server: Server;
  private logger: Logger;

  // Database components
  private db?: DatabaseConnection;
  private queries?: DatabaseQueries;
  private tools?: DatabaseTools;

  // IAM components
  private iamDb?: IAMDatabaseConnection;
  private iamQueries?: IAMDatabaseQueries;
  private iamTools?: IAMDatabaseTools;

  // Secure tools
  private secureTools?: SecureDatabaseTools;

  private useIAM: boolean;

  constructor() {
    this.logger = new Logger();

    this.useIAM = process.env.USE_IAM_AUTH === 'true';

    this.logger.info('Initializing Secure PostgreSQL MCP Server', {
      authentication_method: this.useIAM ? 'IAM' : 'Standard',
      security_features: [
        'SQL injection prevention',
        'Query pattern validation',
        'Rate limiting',
        'Complexity analysis',
        'Parameter sanitization'
      ]
    });

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    if (this.useIAM) {
      this.iamDb = new IAMDatabaseConnection(dbConfig, poolConfig, this.logger);
      this.iamQueries = new IAMDatabaseQueries(this.iamDb, this.logger);
      this.iamTools = new IAMDatabaseTools(this.iamQueries, this.logger);
      this.secureTools = new SecureDatabaseTools(this.iamQueries, this.logger, true);
    } else {
      this.db = new DatabaseConnection(dbConfig, poolConfig);
      this.queries = new DatabaseQueries(this.db);
      this.tools = new DatabaseTools(this.queries, this.logger);
      this.secureTools = new SecureDatabaseTools(this.queries, this.logger, false);
    }

    this.server = new Server(
      {
        name: process.env.MCP_SERVER_NAME ?? 'postgresql-secure-mcp',
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
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      const standardTools = this.tools?.getToolDefinitions() ?? [];
      const iamTools = this.iamTools?.getToolDefinitions() ?? [];
      const secureTools = this.secureTools?.getToolDefinitions() ?? [];

      return {
        tools: [...standardTools, ...iamTools, ...secureTools]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        let result;

        // Route to appropriate tool handler
        if (name.includes('_secure')) {
          // Secure tools (both IAM and standard)
          result = await this.secureTools!.handleToolCall(name, args ?? {});
        } else if (name.endsWith('_iam') && this.iamTools) {
          // IAM-specific tools
          result = await this.iamTools.handleToolCall(name, args ?? {});
        } else if (this.tools) {
          // Standard tools
          result = await this.tools.handleToolCall(name, args ?? {});
        } else {
          throw new Error(`No handler available for tool: ${name}`);
        }

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
      this.logger.info('Starting Secure PostgreSQL MCP Server');

      // Initialize appropriate database connection
      if (this.useIAM && this.iamDb) {
        await this.iamDb.initialize();
        this.logger.info('IAM-authenticated database connection initialized');
      } else if (this.db) {
        await this.db.initialize();
        this.logger.info('Standard database connection initialized');
      }

      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      this.logger.info('Secure MCP Server started successfully', {
        authentication_method: this.useIAM ? 'IAM' : 'Standard',
        security_features: [
          'Advanced SQL injection prevention',
          'Query pattern allowlisting',
          'Rate limiting with configurable windows',
          'Query complexity analysis',
          'Parameter sanitization',
          'Input validation'
        ]
      });
    } catch (error) {
      this.logger.error('Failed to start secure server', {
        error: error instanceof Error ? error.message : String(error),
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      });
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping Secure PostgreSQL MCP Server');

      if (this.useIAM && this.iamDb) {
        await this.iamDb.close();
      } else if (this.db) {
        await this.db.close();
      }

      this.logger.info('Secure server stopped');
    } catch (error) {
      this.logger.error('Error during secure server shutdown', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

async function main(): Promise<void> {
  const server = new SecurePostgreSQLMCPServer();

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