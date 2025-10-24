#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';

import { DatabaseConnectionManager } from './database/connection-manager.js';
import { UnifiedDatabaseTools } from './tools/database-tools-unified.js';
import { Logger } from './logging/logger.js';

/**
 * Unified PostgreSQL MCP Server
 *
 * Features:
 * - Supports multiple databases with both standard and IAM authentication
 * - Comprehensive security: SQL injection prevention, rate limiting, complexity analysis
 * - Complete toolset: introspection, query execution, security analysis, monitoring
 * - Production-ready: audit logging, error handling, graceful shutdown
 * - OWASP LLM Top 10 compliance
 */
class PostgreSQLMCPServer {
  private server: Server;
  private logger: Logger;
  private connectionManager: DatabaseConnectionManager;
  private tools: UnifiedDatabaseTools;

  constructor() {
    this.logger = new Logger();

    this.logger.info('Initializing PostgreSQL MCP Server', {
      security_features: [
        'SQL injection prevention',
        'Query pattern validation',
        'Rate limiting',
        'Complexity analysis',
        'Audit logging',
        'PII Protection',
        'Excessive Agency Control',
        'Model Theft Protection'
      ]
    });

    // Initialize connection manager
    this.connectionManager = new DatabaseConnectionManager(this.logger);
    this.connectionManager.loadFromEnvironment();

    // Initialize unified tools with all features
    this.tools = new UnifiedDatabaseTools(this.connectionManager, this.logger);

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
          error: error instanceof Error ? error.message : String(error)
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

      // Connect to MCP transport
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      const databases = this.connectionManager.listDatabases();
      const defaultDb = this.connectionManager.getDefaultDatabaseId();

      this.logger.info('MCP Server started successfully', {
        tools_available: this.tools.getToolDefinitions().length,
        databases_configured: databases.length,
        default_database: defaultDb,
        security_features: [
          'Advanced SQL injection prevention',
          'Query pattern allowlisting',
          'Rate limiting with configurable windows',
          'Query complexity analysis',
          'Parameter sanitization',
          'Input validation',
          'PII detection and masking',
          'Excessive agency controls',
          'Model theft protection',
          'Comprehensive audit logging'
        ]
      });
    } catch (error) {
      this.logger.error('Failed to start server', {
        error: error instanceof Error ? error.message : String(error)
      });
      process.exit(1);
    }
  }

  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping PostgreSQL MCP Server');

      await this.connectionManager.closeAll();

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
