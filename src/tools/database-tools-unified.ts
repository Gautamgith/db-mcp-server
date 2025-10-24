import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { DatabaseQueries } from '../database/queries.js';
import { IAMDatabaseQueries } from '../database/iam-queries.js';
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
 * Supports both standard and IAM authentication
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
  private queries: DatabaseQueries | IAMDatabaseQueries;
  private logger: Logger;
  private queryValidator: QueryValidator;
  private rateLimiter: RateLimiter;
  private complexityAnalyzer: QueryComplexityAnalyzer;
  private agencyControl: AgencyControlSystem;
  private modelTheftProtection: ModelTheftProtectionSystem;
  private piiProtection: PIIProtectionSystem;
  private useIAM: boolean;

  constructor(
    queries: DatabaseQueries | IAMDatabaseQueries,
    logger: Logger,
    useIAM: boolean = false
  ) {
    this.queries = queries;
    this.logger = logger;
    this.useIAM = useIAM;

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
      // Basic database introspection tools
      {
        name: 'list_tables',
        description: 'List all tables in the PostgreSQL database',
        inputSchema: {
          type: 'object',
          properties: {
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
          properties: {}
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
        authentication: this.useIAM ? 'IAM' : 'Standard',
        risk_assessment: {
          level: actionApproval.assessedRisk.level,
          score: actionApproval.assessedRisk.score,
          approval_status: actionApproval.status
        }
      }, queryId);

      switch (name) {
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
          return await this.handleConnectionHealth(queryId);

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

  // === Basic Database Introspection ===

  private async handleListTables(args: any, queryId: string): Promise<any> {
    const schemaName = args.schema_name ?? 'public';

    try {
      const tables = await this.queries.listTables(schemaName);

      this.logger.info('Tables listed successfully', {
        schema: schemaName,
        count: tables.length
      }, queryId);

      return {
        tables,
        schema_name: schemaName,
        count: tables.length,
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR',
        `Failed to list tables: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleDescribeTable(args: any, queryId: string): Promise<any> {
    const { table_name, schema_name = 'public' } = args;

    if (!table_name || typeof table_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'table_name is required and must be a string', queryId);
    }

    try {
      const tableSchema = await this.queries.describeTable(table_name, schema_name);

      this.logger.info('Table described successfully', {
        table: table_name,
        schema: schema_name,
        columns: tableSchema.columns.length
      }, queryId);

      return {
        table_info: tableSchema,
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR',
        `Failed to describe table: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  // === Query Execution ===

  private async handleExecuteQuery(args: any, queryId: string, sessionId?: string, userId?: string): Promise<any> {
    const { query, parameters = [], limit = 100 } = args;

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
      const result = await this.queries.executeSelect({
        query: validation.sanitizedQuery!,
        parameters,
        limit
      });

      // OWASP LLM02/LLM06: PII Protection - Mask sensitive data in output
      const maskedOutput = this.piiProtection.maskPII(result.rows);

      if (maskedOutput.piiDetected) {
        this.logger.warn('PII detected and masked in query results', {
          masked_count: maskedOutput.maskedCount,
          pii_types: maskedOutput.types
        }, queryId);
      }

      this.logger.info('Query executed successfully', {
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
        security_validated: true,
        complexity_score: complexity.score,
        authentication_method: this.useIAM ? 'IAM' : 'Standard',
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
    const { pattern_name, parameters, limit = 100 } = args;

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
      const result = await this.queries.executeSelect({
        query: finalQuery,
        parameters: validation.sanitizedParams || [],
        limit
      });

      // OWASP LLM02/LLM06: PII Protection - Mask sensitive data
      const maskedOutput = this.piiProtection.maskPII(result.rows);

      if (maskedOutput.piiDetected) {
        this.logger.warn('PII detected and masked in structured query results', {
          pattern: pattern_name,
          masked_count: maskedOutput.maskedCount,
          pii_types: maskedOutput.types
        }, queryId);
      }

      this.logger.info('Structured query executed successfully', {
        pattern_name,
        parameter_count: Object.keys(parameters).length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms,
        pii_masked: maskedOutput.piiDetected
      }, queryId);

      return {
        ...result,
        rows: maskedOutput.data,
        query_pattern: pattern_name,
        security_validated: true,
        authentication_method: this.useIAM ? 'IAM' : 'Standard',
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
    const { query } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR',
        'query is required and must be a string', queryId);
    }

    try {
      const isValid = await this.queries.validateQuery(query);

      this.logger.info('Query syntax validated', {
        query_length: query.length,
        is_valid: isValid
      }, queryId);

      return {
        is_valid: isValid,
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

  private async handleConnectionHealth(queryId: string): Promise<any> {
    try {
      let health: any = {
        authentication_method: this.useIAM ? 'IAM' : 'Standard',
        status: 'healthy'
      };

      // Get IAM-specific health info if available
      if (this.useIAM && 'getConnectionHealth' in this.queries) {
        const iamQueries = this.queries as IAMDatabaseQueries;
        const iamHealth = await iamQueries.getConnectionHealth();
        health = { ...health, ...iamHealth };
      }

      this.logger.info('Connection health checked', {
        authentication: this.useIAM ? 'IAM' : 'Standard',
        status: health.status
      }, queryId);

      return health;
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
      authentication_method: this.useIAM ? 'IAM' : 'Standard',
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
