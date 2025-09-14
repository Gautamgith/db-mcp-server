#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DatabaseConnection } from './database/connection.js';
import { DatabaseQueries } from './database/queries.js';
import { DatabaseTools } from './tools/database-tools.js';
import { Logger } from './logging/logger.js';
import { createDatabaseConfig, createConnectionPoolConfig } from './database/config.js';

class PostgreSQLMCPServer {
  private server: Server;
  private db: DatabaseConnection;
  private queries: DatabaseQueries;
  private tools: DatabaseTools;
  private logger: Logger;

  constructor() {
    this.logger = new Logger();

    const dbConfig = createDatabaseConfig();
    const poolConfig = createConnectionPoolConfig();

    this.db = new DatabaseConnection(dbConfig, poolConfig);
    this.queries = new DatabaseQueries(this.db);
    this.tools = new DatabaseTools(this.queries, this.logger);

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
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.tools.getToolDefinitions()
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        const result = await this.tools.handleToolCall(name, args ?? {});
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
          error: error instanceof Error ? error.message : String(error)
        });

        throw error;
      }
    });
  }

  async start(): Promise<void> {
    try {
      this.logger.info('Starting PostgreSQL MCP Server');

      await this.db.initialize();
      this.logger.info('Database connection initialized');

      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      this.logger.info('MCP Server started and ready for connections');
    } catch (error) {
      this.logger.error('Failed to start server', { error: error instanceof Error ? error.message : String(error) });
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping PostgreSQL MCP Server');
      await this.db.close();
      this.logger.info('Server stopped');
    } catch (error) {
      this.logger.error('Error during server shutdown', { error: error instanceof Error ? error.message : String(error) });
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