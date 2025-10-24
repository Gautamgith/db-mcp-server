#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import http from 'node:http';
import { IncomingMessage, ServerResponse } from 'node:http';

import { DatabaseConnectionManager } from './database/connection-manager.js';
import { UnifiedDatabaseTools } from './tools/database-tools-unified.js';
import { Logger } from './logging/logger.js';
import { loadOAuthConfig, loadHTTPServerConfig, validateOAuthConfig, validateHTTPServerConfig } from './config/oauth-config.js';
import { OAuthMiddleware, AuthError, UserInfo } from './middleware/oauth.js';
import { HealthCheckHandler } from './health/health-check.js';

/**
 * Unified PostgreSQL MCP Server with HTTP/SSE Transport
 *
 * Features:
 * - HTTP-based transport with OAuth 2.0 authentication (EntraID)
 * - Supports multiple databases with both standard and IAM authentication
 * - Comprehensive security: SQL injection prevention, rate limiting, complexity analysis
 * - Complete toolset: introspection, query execution, security analysis, monitoring
 * - Production-ready: audit logging, error handling, graceful shutdown
 * - OWASP LLM Top 10 compliance
 */
class PostgreSQLMCPServer {
  private server: Server;
  private httpServer: http.Server | undefined;
  private logger: Logger;
  private connectionManager: DatabaseConnectionManager;
  private tools: UnifiedDatabaseTools;
  private oauthMiddleware: OAuthMiddleware | undefined;
  private healthCheck: HealthCheckHandler;
  private transports: Map<string, SSEServerTransport>;

  constructor() {
    this.logger = new Logger();
    this.transports = new Map();

    this.logger.info('Initializing PostgreSQL MCP Server', {
      security_features: [
        'OAuth 2.0 authentication',
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

    // Load and validate OAuth configuration
    const oauthConfig = loadOAuthConfig();
    validateOAuthConfig(oauthConfig);

    if (oauthConfig.enabled) {
      this.oauthMiddleware = new OAuthMiddleware(oauthConfig, this.logger);
      this.logger.info('OAuth authentication enabled', {
        issuer: oauthConfig.issuer,
        audience: oauthConfig.audience
      });
    } else {
      this.logger.warn('OAuth authentication disabled - server will accept unauthenticated requests');
    }

    // Initialize connection manager
    this.connectionManager = new DatabaseConnectionManager(this.logger);
    this.connectionManager.loadFromEnvironment();

    // Initialize health check
    this.healthCheck = new HealthCheckHandler(this.connectionManager, this.logger);

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

      // Load HTTP server configuration
      const httpConfig = loadHTTPServerConfig();
      validateHTTPServerConfig(httpConfig);

      // Create HTTP server
      this.httpServer = http.createServer(async (req, res) => {
        await this.handleHTTPRequest(req, res, httpConfig.path);
      });

      // Start listening
      await new Promise<void>((resolve, reject) => {
        this.httpServer!.listen(httpConfig.port, httpConfig.host, () => {
          resolve();
        });
        this.httpServer!.on('error', reject);
      });

      const databases = this.connectionManager.listDatabases();
      const defaultDb = this.connectionManager.getDefaultDatabaseId();

      this.logger.info('HTTP MCP Server started successfully', {
        host: httpConfig.host,
        port: httpConfig.port,
        path: httpConfig.path,
        oauth_enabled: this.oauthMiddleware !== undefined,
        tools_available: this.tools.getToolDefinitions().length,
        databases_configured: databases.length,
        default_database: defaultDb,
        security_features: [
          'OAuth 2.0 authentication (EntraID)',
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

      console.log(`\n🚀 MCP Server running on http://${httpConfig.host}:${httpConfig.port}${httpConfig.path}`);
      console.log(`📊 Health check: http://${httpConfig.host}:${httpConfig.port}/health`);
      console.log(`🔐 OAuth: ${this.oauthMiddleware ? 'Enabled' : 'Disabled'}\n`);

    } catch (error) {
      this.logger.error('Failed to start server', {
        error: error instanceof Error ? error.message : String(error)
      });
      process.exit(1);
    }
  }

  /**
   * Handle incoming HTTP requests
   */
  private async handleHTTPRequest(req: IncomingMessage, res: ServerResponse, mcpPath: string): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    // Health check endpoints
    if (url.pathname === '/health') {
      await this.handleHealthCheck(req, res);
      return;
    }

    if (url.pathname === '/health/live') {
      await this.handleLivenessCheck(req, res);
      return;
    }

    if (url.pathname === '/health/ready') {
      await this.handleReadinessCheck(req, res);
      return;
    }

    // MCP SSE endpoint
    if (url.pathname === mcpPath && req.method === 'GET') {
      await this.handleSSEConnection(req, res);
      return;
    }

    // MCP POST endpoint
    if (url.pathname === '/message' && req.method === 'POST') {
      await this.handleMCPMessage(req, res);
      return;
    }

    // 404 Not Found
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not Found' }));
  }

  /**
   * Validate OAuth token from request
   */
  private async validateOAuthToken(req: IncomingMessage): Promise<UserInfo | null> {
    if (!this.oauthMiddleware) {
      return null; // OAuth disabled
    }

    const authHeader = req.headers.authorization;
    if (!authHeader) {
      throw new AuthError('Missing Authorization header', 'MISSING_AUTHORIZATION');
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new AuthError('Invalid Authorization header format', 'INVALID_AUTHORIZATION_FORMAT');
    }

    const token = parts[1];
    if (!token) {
      throw new AuthError('Empty token', 'EMPTY_TOKEN');
    }

    return await this.oauthMiddleware.validateToken(token);
  }

  /**
   * Handle SSE connection establishment
   */
  private async handleSSEConnection(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      // Validate OAuth token if enabled
      const userInfo = await this.validateOAuthToken(req);

      if (userInfo) {
        this.logger.info('SSE connection authenticated', {
          user_id: userInfo.id,
          client_id: userInfo.clientId
        });
      }

      // Create SSE transport
      const transport = new SSEServerTransport('/message', res);
      const sessionId = transport.sessionId;

      // Store transport
      this.transports.set(sessionId, transport);

      // Connect MCP server to transport
      await this.server.connect(transport);

      // Handle transport close
      transport.onclose = () => {
        this.transports.delete(sessionId);
        this.logger.info('SSE connection closed', { session_id: sessionId });
      };

      // Start SSE stream
      await transport.start();

      this.logger.info('SSE connection established', {
        session_id: sessionId,
        user_id: userInfo?.id
      });

    } catch (error) {
      if (error instanceof AuthError) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: error.code,
          message: error.message
        }));
      } else {
        this.logger.error('Failed to establish SSE connection', {
          error: error instanceof Error ? error.message : String(error)
        });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
      }
    }
  }

  /**
   * Handle MCP POST messages
   */
  private async handleMCPMessage(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      // Validate OAuth token if enabled
      await this.validateOAuthToken(req);

      // Get session ID from query parameter
      const url = new URL(req.url || '/', `http://${req.headers.host}`);
      const sessionId = url.searchParams.get('sessionId');

      if (!sessionId) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Missing sessionId parameter' }));
        return;
      }

      // Get transport for this session
      const transport = this.transports.get(sessionId);
      if (!transport) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
      }

      // Handle the POST message
      await transport.handlePostMessage(req, res);

    } catch (error) {
      if (error instanceof AuthError) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: error.code,
          message: error.message
        }));
      } else {
        this.logger.error('Failed to handle MCP message', {
          error: error instanceof Error ? error.message : String(error)
        });
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
      }
    }
  }

  /**
   * Handle health check request
   */
  private async handleHealthCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      const health = await this.healthCheck.getHealthStatus();
      const statusCode = health.status === 'healthy' ? 200 : health.status === 'degraded' ? 200 : 503;

      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(health, null, 2));
    } catch (error) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Health check failed' }));
    }
  }

  /**
   * Handle liveness check request
   */
  private async handleLivenessCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const liveness = this.healthCheck.getLivenessStatus();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(liveness, null, 2));
  }

  /**
   * Handle readiness check request
   */
  private async handleReadinessCheck(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const readiness = await this.healthCheck.getReadinessStatus();
    const statusCode = readiness.ready ? 200 : 503;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(readiness, null, 2));
  }

  async stop(): Promise<void> {
    try {
      this.logger.info('Stopping PostgreSQL MCP Server');

      // Close all SSE transports
      for (const [sessionId, transport] of this.transports.entries()) {
        try {
          await transport.close();
        } catch (error) {
          this.logger.error('Error closing transport', {
            session_id: sessionId,
            error: error instanceof Error ? error.message : String(error)
          });
        }
      }
      this.transports.clear();

      // Close HTTP server
      if (this.httpServer) {
        await new Promise<void>((resolve) => {
          this.httpServer!.close(() => resolve());
        });
      }

      // Close database connections
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
