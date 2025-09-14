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
import { Logger } from './logging/logger.js';
import { createDatabaseConfig, createConnectionPoolConfig } from './database/config.js';

class PostgreSQLMCPServer {
  private server: Server;
  private logger: Logger;

  // Standard authentication components
  private db?: DatabaseConnection;
  private queries?: DatabaseQueries;
  private tools?: DatabaseTools;

  // IAM authentication components
  private iamDb?: IAMDatabaseConnection;
  private iamQueries?: IAMDatabaseQueries;
  private iamTools?: IAMDatabaseTools;

  private useIAM: boolean;

  constructor() {
    this.logger = new Logger();

    // Determine authentication method from environment
    this.useIAM = process.env.USE_IAM_AUTH === 'true';

    this.logger.info('Initializing PostgreSQL MCP Server', {
      authentication_method: this.useIAM ? 'IAM' : 'Standard',
      server_purpose: 'Database optimization and configuration analysis'
    });

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    if (this.useIAM) {
      this.iamDb = new IAMDatabaseConnection(dbConfig, poolConfig, this.logger);
      this.iamQueries = new IAMDatabaseQueries(this.iamDb, this.logger);
      this.iamTools = new IAMDatabaseTools(this.iamQueries, this.logger);
    } else {
      this.db = new DatabaseConnection(dbConfig, poolConfig);
      this.queries = new DatabaseQueries(this.db);
      this.tools = new DatabaseTools(this.queries, this.logger);
    }

    this.server = new Server(
      {
        name: process.env.MCP_SERVER_NAME ?? 'postgresql-optimization-mcp',
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

      return {
        tools: [...standardTools, ...iamTools]
      };
    });

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        let result;

        // Route to appropriate tool handler based on tool name
        if (name.endsWith('_iam') && this.iamTools) {
          result = await this.iamTools.handleToolCall(name, args ?? {});
        } else if (this.tools) {
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

        throw error;
      }
    });
  }

  async start(): Promise<void> {
    try {
      this.logger.info('Starting PostgreSQL MCP Server for optimization analysis');

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

      this.logger.info('MCP Server started and ready for database optimization analysis', {
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
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

      if (this.useIAM && this.iamDb) {
        await this.iamDb.close();
      } else if (this.db) {
        await this.db.close();
      }

      this.logger.info('Server stopped');
    } catch (error) {
      this.logger.error('Error during server shutdown', {
        error: error instanceof Error ? error.message : String(error)
      });
    }
  }
}

async function main(): Promise<void> {
  const server = new PostgreSQLMCPServer();

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