import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { DatabaseQueries } from '../database/queries.js';
import { IAMDatabaseQueries } from '../database/iam-queries.js';
import { DatabaseConnectionManager } from '../database/connection-manager.js';
import { Logger } from '../logging/logger.js';
import { QueryValidator } from '../security/query-validator.js';
import { RateLimiter, QueryComplexityAnalyzer } from '../security/rate-limiter.js';
import { AgencyControlSystem } from '../security/agency-control.js';
import { ModelTheftProtectionSystem } from '../security/model-theft-protection.js';
import { PIIProtectionSystem } from '../security/pii-protection.js';
import { MCPError } from '../types/index.js';

/**
 * Unified Database Tools for PostgreSQL MCP Server
 *
 * Supports multiple databases with both standard and IAM authentication
 * Includes all security features:
 * - SQL injection prevention
 * - Query pattern validation
 * - Rate limiting
 * - Complexity analysis
 * - Audit logging
 * - OWASP LLM08: Excessive Agency controls
 * - OWASP LLM10: Model Theft protection
 * - OWASP LLM02/LLM06: PII detection and masking
 */
export class UnifiedDatabaseTools {
  private connectionManager: DatabaseConnectionManager;
  private logger: Logger;
  private queryValidator: QueryValidator;
  private rateLimiter: RateLimiter;
  private complexityAnalyzer: QueryComplexityAnalyzer;
  private agencyControl: AgencyControlSystem;
  private modelTheftProtection: ModelTheftProtectionSystem;
  private piiProtection: PIIProtectionSystem;

  constructor(
    connectionManager: DatabaseConnectionManager,
    logger: Logger
  ) {
    this.connectionManager = connectionManager;
    this.logger = logger;

    this.queryValidator = new QueryValidator(logger);
    this.complexityAnalyzer = new QueryComplexityAnalyzer(logger);

    // Initialize rate limiter with configurable limits
    this.rateLimiter = new RateLimiter({
      maxRequests: parseInt(process.env.RATE_LIMIT_REQUESTS ?? '100', 10),
      windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '60000', 10), // 1 minute
      keyGenerator: (context) => context.clientId || 'default'
    }, logger);

    // Initialize OWASP LLM security systems
    this.agencyControl = new AgencyControlSystem(logger);
    this.modelTheftProtection = new ModelTheftProtectionSystem(logger);
    this.piiProtection = new PIIProtectionSystem(logger);
  }

  getToolDefinitions(): Tool[] {
    return [
      // Database management tools
      {
        name: 'list_databases',
        description: 'List all configured databases and their connection status',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },

      // Basic database introspection tools
      {
        name: 'list_tables',
        description: 'List all tables in the PostgreSQL database',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            },
            schema_name: {
              type: 'string',
              description: 'Schema name (defaults to "public")',
              default: 'public'
            }
          }
        }
      },
      {
        name: 'describe_table',
        description: 'Get detailed schema information for a specific table including columns, indexes, and foreign keys',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            },
            table_name: {
              type: 'string',
              description: 'Name of the table to describe'
            },
            schema_name: {
              type: 'string',
              description: 'Schema name (defaults to "public")',
              default: 'public'
            }
          },
          required: ['table_name']
        }
      },

      // Query execution tools
      {
        name: 'execute_query',
        description: 'Execute a parameterized SELECT query with comprehensive security validation',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            },
            query: {
              type: 'string',
              description: 'SQL SELECT statement with parameter placeholders ($1, $2, etc.)'
            },
            parameters: {
              type: 'array',
              description: 'Parameter values for query placeholders',
              items: {
                type: ['string', 'number', 'boolean', 'null']
              },
              default: []
            },
            limit: {
              type: 'number',
              description: 'Maximum number of rows to return',
              minimum: 1,
              maximum: 1000,
              default: 100
            }
          },
          required: ['query']
        }
      },
      {
        name: 'structured_query',
        description: 'Execute a structured query using predefined secure patterns for common operations',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            },
            pattern_name: {
              type: 'string',
              description: 'Name of the query pattern to use'
            },
            parameters: {
              type: 'object',
              description: 'Parameters for the query pattern'
            },
            limit: {
              type: 'number',
              description: 'Maximum number of rows to return',
              minimum: 1,
              maximum: 1000,
              default: 100
            }
          },
          required: ['pattern_name', 'parameters']
        }
      },

      // Security and analysis tools
      {
        name: 'query_patterns',
        description: 'List all available secure query patterns with their parameters and descriptions',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'analyze_query_complexity',
        description: 'Analyze the complexity of a SQL query without executing it',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'SQL query to analyze'
            }
          },
          required: ['query']
        }
      },
      {
        name: 'validate_query_syntax',
        description: 'Validate SQL query syntax without executing it',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            },
            query: {
              type: 'string',
              description: 'SQL query to validate'
            }
          },
          required: ['query']
        }
      },

      // System and monitoring tools
      {
        name: 'connection_health',
        description: 'Check database connection health and authentication status',
        inputSchema: {
          type: 'object',
          properties: {
            database_id: {
              type: 'string',
              description: 'Database ID (uses default if not specified)'
            }
          }
        }
      },
      {
        name: 'security_status',
        description: 'Get security system status including rate limiting and enabled features',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: 'rate_limit_status',
        description: 'Check current rate limiting status for this client',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
  }

  async handleToolCall(name: string, args: any, clientId?: string, sessionId?: string, userId?: string): Promise<any> {
    const queryId = this.generateQueryId();

    // Rate limiting check
    const rateLimitResult = this.rateLimiter.checkLimit({ clientId });
    if (!rateLimitResult.allowed) {
      throw this.createMCPError(-32429, 'RATE_LIMIT_EXCEEDED',
        `Rate limit exceeded. Try again in ${rateLimitResult.retryAfter} seconds.`, queryId);
    }

    // OWASP LLM08: Agency Control - Assess action risk before execution
    const actionApproval = await this.agencyControl.checkActionAuthorization({
      toolName: name,
      parameters: args,
      userId,
      sessionId,
      timestamp: new Date()
    });

    if (actionApproval.status === 'rejected') {
      this.logger.error('Action rejected by agency control', {
        tool: name,
        risk_level: actionApproval.assessedRisk.level,
        risk_score: actionApproval.assessedRisk.score,
        reason: actionApproval.reason
      }, queryId);

      throw this.createMCPError(-32403, 'ACTION_REJECTED',
        `${actionApproval.reason} (Risk: ${actionApproval.assessedRisk.level}, Score: ${actionApproval.assessedRisk.score})`, queryId);
    }

    try {
      this.logger.info(`Tool called: ${name}`, {
        args: this.sanitizeArgsForLogging(args),
        rate_limit_remaining: rateLimitResult.remaining,
        risk_assessment: {
          level: actionApproval.assessedRisk.level,
          score: actionApproval.assessedRisk.score,
          approval_status: actionApproval.status
        }
      }, queryId);

      switch (name) {
        case 'list_databases':
          return await this.handleListDatabases(queryId);

        case 'list_tables':
          return await this.handleListTables(args, queryId);

        case 'describe_table':
          return await this.handleDescribeTable(args, queryId);

        case 'execute_query':
          return await this.handleExecuteQuery(args, queryId, sessionId, userId);

        case 'structured_query':
          return await this.handleStructuredQuery(args, queryId, sessionId, userId);

        case 'query_patterns':
          return await this.handleQueryPatterns(queryId);

        case 'analyze_query_complexity':
          return await this.handleAnalyzeComplexity(args, queryId);

        case 'validate_query_syntax':
          return await this.handleValidateQuerySyntax(args, queryId);

        case 'connection_health':
          return await this.handleConnectionHealth(args, queryId);

        case 'security_status':
          return await this.handleSecurityStatus(queryId);

        case 'rate_limit_status':
          return await this.handleRateLimitStatus(queryId);

        default:
          throw this.createMCPError(-32002, 'UNKNOWN_TOOL', `Unknown tool: ${name}`, queryId);
      }
    } catch (error) {
      this.logger.error(`Tool execution failed: ${name}`, {
        error: error instanceof Error ? error.message : String(error),
        args: this.sanitizeArgsForLogging(args)
      }, queryId);
      throw error;
    }
  }

  // === Database Management ===

  private async handleListDatabases(queryId: string): Promise<any> {
    try {
      const databases = this.connectionManager.listDatabases();
      const defaultDatabaseId = this.connectionManager.getDefaultDatabaseId();

      this.logger.info('Databases listed successfully', {
        count: databases.length,
        default_database: defaultDatabaseId
      }, queryId);

      return {
        databases: databases.map(db => ({
          id: db.id,
          name: db.name,
          description: db.description,
          host: db.host,
          port: db.port,
          database: db.database,
          user: db.user,
          authentication_method: db.useIAM ? 'IAM' : 'Standard',
          enabled: db.enabled,
          connected: db.connected,
          is_default: db.id === defaultDatabaseId
        })),
        default_database_id: defaultDatabaseId,
        total_count: databases.length,
        connected_count: databases.filter(db => db.connected).length
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR',
        `Failed to list databases: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  // === Basic Database Introspection ===

  private async handleListTables(args: any, queryId: string): Promise<any> {
    const { database_id, schema_name = 'public' } = args;

    try {
      const queries = await this.connectionManager.getQueries(database_id);
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      const tables = await queries.listTables(schema_name);

      this.logger.info('Tables listed successfully', {
        database_id: database?.id,
        schema: schema_name,
        count: tables.length
      }, queryId);

      return {
        tables,
        database_id: database?.id,
        database_name: database?.name,
        schema_name,
        count: tables.length,
        authentication_method: database?.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR',
        `Failed to list tables: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleDescribeTable(args: any, queryId: string): Promise<any> {
    const { database_id, table_name, schema_name = 'public' } = args;

    if (!table_name || typeof table_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'table_name is required and must be a string', queryId);
    }

    try {
      const queries = await this.connectionManager.getQueries(database_id);
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      const tableSchema = await queries.describeTable(table_name, schema_name);

      this.logger.info('Table described successfully', {
        database_id: database?.id,
        table: table_name,
        schema: schema_name,
        columns: tableSchema.columns.length
      }, queryId);

      return {
        table_info: tableSchema,
        database_id: database?.id,
        database_name: database?.name,
        authentication_method: database?.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR',
        `Failed to describe table: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  // === Query Execution ===

  private async handleExecuteQuery(args: any, queryId: string, sessionId?: string, userId?: string): Promise<any> {
    const { database_id, query, parameters = [], limit = 100 } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'query is required and must be a string', queryId);
    }

    if (!Array.isArray(parameters)) {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'parameters must be an array', queryId);
    }

    // Query size validation
    const sizeCheck = this.complexityAnalyzer.validateQuerySize(query);
    if (!sizeCheck.allowed) {
      throw this.createMCPError(-32002, 'QUERY_TOO_LARGE', sizeCheck.error!, queryId);
    }

    // Security validation
    const validation = this.queryValidator.validateRawQuery(query);
    if (!validation.isValid) {
      throw this.createMCPError(-32002, 'SQL_INJECTION_RISK',
        `Query security validation failed: ${validation.errors.join(', ')}`, queryId);
    }

    // Complexity analysis
    const complexity = this.complexityAnalyzer.analyzeComplexity(query);
    if (!complexity.allowed) {
      throw this.createMCPError(-32002, 'QUERY_TOO_COMPLEX',
        `Query complexity score ${complexity.score} exceeds maximum ${complexity.maxScore}. Factors: ${complexity.factors.join(', ')}`, queryId);
    }

    // OWASP LLM10: Model Theft Protection - Detect extraction patterns
    if (sessionId) {
      const extractionAnalysis = await this.modelTheftProtection.analyzeForExtraction(
        query,
        sessionId,
        userId
      );

      if (extractionAnalysis.isAttempt && extractionAnalysis.confidence >= 80) {
        this.logger.error('Potential model theft/data extraction detected', {
          session_id: sessionId,
          confidence: extractionAnalysis.confidence,
          patterns: extractionAnalysis.patterns,
          action: extractionAnalysis.recommendedAction
        }, queryId);

        throw this.createMCPError(-32403, 'EXTRACTION_BLOCKED',
          `Query blocked: Potential data extraction attempt detected (${extractionAnalysis.confidence}% confidence). Patterns: ${extractionAnalysis.patterns.join(', ')}`, queryId);
      }

      if (extractionAnalysis.isAttempt && extractionAnalysis.confidence >= 50) {
        this.logger.warn('Suspicious query pattern detected', {
          session_id: sessionId,
          confidence: extractionAnalysis.confidence,
          patterns: extractionAnalysis.patterns
        }, queryId);
      }
    }

    try {
      const queries = await this.connectionManager.getQueries(database_id);
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      const result = await queries.executeSelect({
        query: validation.sanitizedQuery!,
        parameters,
        limit
      });

      // OWASP LLM02/LLM06: PII Protection - Mask sensitive data in output
      const maskedOutput = this.piiProtection.maskPII(result.rows);

      if (maskedOutput.piiDetected) {
        this.logger.warn('PII detected and masked in query results', {
          database_id: database?.id,
          masked_count: maskedOutput.maskedCount,
          pii_types: maskedOutput.types
        }, queryId);
      }

      this.logger.info('Query executed successfully', {
        database_id: database?.id,
        query_length: query.length,
        parameter_count: parameters.length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms,
        complexity_score: complexity.score,
        pii_masked: maskedOutput.piiDetected
      }, queryId);

      return {
        ...result,
        rows: maskedOutput.data,
        database_id: database?.id,
        database_name: database?.name,
        security_validated: true,
        complexity_score: complexity.score,
        authentication_method: database?.useIAM ? 'IAM' : 'Standard',
        pii_protection: {
          applied: maskedOutput.piiDetected,
          masked_count: maskedOutput.maskedCount,
          types: maskedOutput.types
        }
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'EXECUTION_ERROR',
        `Query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleStructuredQuery(args: any, queryId: string, sessionId?: string, userId?: string): Promise<any> {
    const { database_id, pattern_name, parameters, limit = 100 } = args;

    if (!pattern_name || typeof pattern_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'pattern_name is required and must be a string', queryId);
    }

    if (!parameters || typeof parameters !== 'object') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'parameters is required and must be an object', queryId);
    }

    // Validate structured query
    const validation = this.queryValidator.validateStructuredQuery(pattern_name, parameters);
    if (!validation.isValid) {
      throw this.createMCPError(-32002, 'VALIDATION_ERROR',
        `Query validation failed: ${validation.errors.join(', ')}`, queryId);
    }

    const query = validation.sanitizedQuery!;

    // Add limit if required by pattern
    const pattern = this.queryValidator.getPattern(pattern_name);
    const finalQuery = pattern?.requiresExplicitLimit ? `${query} LIMIT ${limit}` : query;

    // OWASP LLM10: Model Theft Protection - Track structured queries too
    if (sessionId) {
      const extractionAnalysis = await this.modelTheftProtection.analyzeForExtraction(
        finalQuery,
        sessionId,
        userId
      );

      if (extractionAnalysis.isAttempt && extractionAnalysis.confidence >= 80) {
        this.logger.error('Potential model theft/data extraction detected in structured query', {
          session_id: sessionId,
          pattern: pattern_name,
          confidence: extractionAnalysis.confidence,
          patterns: extractionAnalysis.patterns
        }, queryId);

        throw this.createMCPError(-32403, 'EXTRACTION_BLOCKED',
          `Query blocked: Potential data extraction attempt detected (${extractionAnalysis.confidence}% confidence)`, queryId);
      }
    }

    try {
      const queries = await this.connectionManager.getQueries(database_id);
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      const result = await queries.executeSelect({
        query: finalQuery,
        parameters: validation.sanitizedParams || [],
        limit
      });

      // OWASP LLM02/LLM06: PII Protection - Mask sensitive data
      const maskedOutput = this.piiProtection.maskPII(result.rows);

      if (maskedOutput.piiDetected) {
        this.logger.warn('PII detected and masked in structured query results', {
          database_id: database?.id,
          pattern: pattern_name,
          masked_count: maskedOutput.maskedCount,
          pii_types: maskedOutput.types
        }, queryId);
      }

      this.logger.info('Structured query executed successfully', {
        database_id: database?.id,
        pattern_name,
        parameter_count: Object.keys(parameters).length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms,
        pii_masked: maskedOutput.piiDetected
      }, queryId);

      return {
        ...result,
        rows: maskedOutput.data,
        database_id: database?.id,
        database_name: database?.name,
        query_pattern: pattern_name,
        security_validated: true,
        authentication_method: database?.useIAM ? 'IAM' : 'Standard',
        pii_protection: {
          applied: maskedOutput.piiDetected,
          masked_count: maskedOutput.maskedCount,
          types: maskedOutput.types
        }
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'EXECUTION_ERROR',
        `Structured query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  // === Security and Analysis ===

  private async handleQueryPatterns(queryId: string): Promise<any> {
    const patterns = this.queryValidator.getAvailablePatterns();

    this.logger.info('Query patterns retrieved', {
      pattern_count: patterns.length
    }, queryId);

    return {
      patterns: patterns.map(p => ({
        name: p.name,
        description: p.description,
        parameters: p.parameters,
        max_rows: p.maxRows,
        requires_explicit_limit: p.requiresExplicitLimit
      })),
      total_patterns: patterns.length,
      security_features: [
        'Input validation',
        'SQL injection protection',
        'Parameter sanitization',
        'Query complexity analysis',
        'Rate limiting'
      ]
    };
  }

  private async handleAnalyzeComplexity(args: any, queryId: string): Promise<any> {
    const { query } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'query is required and must be a string', queryId);
    }

    const sizeCheck = this.complexityAnalyzer.validateQuerySize(query);
    const complexity = this.complexityAnalyzer.analyzeComplexity(query);
    const validation = this.queryValidator.validateRawQuery(query);

    this.logger.info('Query complexity analyzed', {
      query_length: query.length,
      complexity_score: complexity.score,
      validation_passed: validation.isValid
    }, queryId);

    return {
      size_analysis: sizeCheck,
      complexity_analysis: complexity,
      security_validation: {
        is_valid: validation.isValid,
        errors: validation.errors
      },
      recommendations: this.generateSecurityRecommendations(complexity, validation)
    };
  }

  private async handleValidateQuerySyntax(args: any, queryId: string): Promise<any> {
    const { database_id, query } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'query is required and must be a string', queryId);
    }

    try {
      const queries = await this.connectionManager.getQueries(database_id);
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      const isValid = await queries.validateQuery(query);

      this.logger.info('Query syntax validated', {
        database_id: database?.id,
        query_length: query.length,
        is_valid: isValid
      }, queryId);

      return {
        is_valid: isValid,
        database_id: database?.id,
        database_name: database?.name,
        query_length: query.length,
        message: isValid ? 'Query syntax is valid' : 'Query syntax is invalid'
      };
    } catch (error) {
      return {
        is_valid: false,
        query_length: query.length,
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // === System and Monitoring ===

  private async handleConnectionHealth(args: any, queryId: string): Promise<any> {
    const { database_id } = args;

    try {
      const database = this.connectionManager.getDatabase(database_id || this.connectionManager.getDefaultDatabaseId()!);

      if (!database) {
        throw new Error('No database specified and no default configured');
      }

      // Check connection health
      const connectionInfo = await this.connectionManager.checkConnection(database.id);

      this.logger.info('Connection health checked', {
        database_id: database.id,
        authentication: database.useIAM ? 'IAM' : 'Standard',
        connected: connectionInfo.connected
      }, queryId);

      return {
        database_id: database.id,
        database_name: database.name,
        host: database.host,
        port: database.port,
        database: database.database,
        user: database.user,
        authentication_method: database.useIAM ? 'IAM' : 'Standard',
        connected: connectionInfo.connected,
        status: connectionInfo.connected ? 'healthy' : 'unhealthy',
        last_checked: connectionInfo.lastChecked,
        error: connectionInfo.error
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'CONNECTION_ERROR',
        `Failed to check connection health: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleSecurityStatus(queryId: string): Promise<any> {
    const rateLimitStats = this.rateLimiter.getStats();
    const patterns = this.queryValidator.getAvailablePatterns();
    const piiStats = this.piiProtection.getPatternStats();

    return {
      rate_limiting: {
        active_windows: rateLimitStats.totalWindows,
        max_requests_per_window: parseInt(process.env.RATE_LIMIT_REQUESTS ?? '100', 10),
        window_duration_ms: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '60000', 10)
      },
      query_patterns: {
        available_patterns: patterns.length,
        pattern_names: patterns.map(p => p.name)
      },
      complexity_limits: {
        max_query_size: parseInt(process.env.MAX_QUERY_SIZE ?? '10000', 10),
        max_complexity_score: parseInt(process.env.MAX_QUERY_COMPLEXITY_SCORE ?? '20', 10)
      },
      agency_control: {
        enabled: true,
        auto_approve_threshold: 'LOW',
        require_review_threshold: 'HIGH'
      },
      model_theft_protection: {
        enabled: true,
        tracking_sessions: true,
        block_threshold: 80,
        warn_threshold: 50
      },
      pii_protection: {
        enabled: piiStats.enabled,
        total_patterns: piiStats.totalPatterns,
        patterns_by_severity: piiStats.bySeverity
      },
      owasp_compliance: [
        'LLM01: Prompt Injection Protection',
        'LLM02: Insecure Output Handling (PII Masking)',
        'LLM04: Model Denial of Service',
        'LLM06: Sensitive Information Disclosure (PII)',
        'LLM08: Excessive Agency Control',
        'LLM10: Model Theft Prevention'
      ],
      security_features_enabled: [
        'SQL injection prevention',
        'Query pattern validation',
        'Complexity analysis',
        'Rate limiting',
        'Parameter sanitization',
        'Input validation',
        'PII detection and masking',
        'Excessive agency controls',
        'Model theft detection'
      ]
    };
  }

  private async handleRateLimitStatus(queryId: string): Promise<any> {
    const stats = this.rateLimiter.getStats();

    return {
      total_active_windows: stats.totalWindows,
      max_requests_per_window: parseInt(process.env.RATE_LIMIT_REQUESTS ?? '100', 10),
      window_duration_ms: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '60000', 10),
      message: 'Rate limiting is active and monitoring requests'
    };
  }

  // === Helper Methods ===

  private generateSecurityRecommendations(complexity: any, validation: any): string[] {
    const recommendations: string[] = [];

    if (complexity.score > 15) {
      recommendations.push('Consider simplifying the query by reducing JOINs or subqueries');
    }

    if (complexity.factors.includes('window function(s)')) {
      recommendations.push('Window functions can be expensive - consider if they are necessary');
    }

    if (!validation.isValid) {
      recommendations.push('Use parameterized queries to avoid SQL injection risks');
    }

    if (recommendations.length === 0) {
      recommendations.push('Query appears to follow security best practices');
    }

    return recommendations;
  }

  private sanitizeArgsForLogging(args: any): any {
    if (!args || typeof args !== 'object') {
      return args;
    }

    const sanitized = { ...args };

    // Remove or redact sensitive information
    if (sanitized.query) {
      sanitized.query = sanitized.query.substring(0, 100) + '...';
    }

    if (sanitized.parameters && Array.isArray(sanitized.parameters)) {
      sanitized.parameters = sanitized.parameters.map(() => '[REDACTED]');
    }

    return sanitized;
  }

  private createMCPError(code: number, errorType: string, message: string, queryId?: string): MCPError {
    return {
      code: code as any,
      message,
      data: {
        error_type: errorType,
        details: message,
        query_id: queryId ?? undefined
      }
    };
  }

  private generateQueryId(): string {
    return `q_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
