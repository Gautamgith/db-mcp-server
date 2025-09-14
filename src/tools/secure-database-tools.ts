import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { DatabaseQueries } from '../database/queries.js';
import { IAMDatabaseQueries } from '../database/iam-queries.js';
import { Logger } from '../logging/logger.js';
import { QueryValidator, QueryPattern } from '../security/query-validator.js';
import { RateLimiter, QueryComplexityAnalyzer } from '../security/rate-limiter.js';
import { MCPError } from '../types/index.js';

export class SecureDatabaseTools {
  private queries: DatabaseQueries | IAMDatabaseQueries;
  private logger: Logger;
  private queryValidator: QueryValidator;
  private rateLimiter: RateLimiter;
  private complexityAnalyzer: QueryComplexityAnalyzer;
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
  }

  getToolDefinitions(): Tool[] {
    const suffix = this.useIAM ? '_secure_iam' : '_secure';

    return [
      {
        name: `structured_query${suffix}`,
        description: 'Execute a structured query using predefined secure patterns',
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
      {
        name: `validated_query${suffix}`,
        description: 'Execute a raw SELECT query with advanced security validation',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'SQL SELECT statement'
            },
            parameters: {
              type: 'array',
              description: 'Parameter values for query placeholders',
              items: {
                type: ['string', 'number', 'boolean', 'null']
              }
            },
            limit: {
              type: 'number',
              description: 'Maximum number of rows to return',
              minimum: 1,
              maximum: 1000,
              default: 100
            },
            bypass_complexity_check: {
              type: 'boolean',
              description: 'Bypass query complexity validation (use with caution)',
              default: false
            }
          },
          required: ['query']
        }
      },
      {
        name: `query_patterns${suffix}`,
        description: 'List all available secure query patterns',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      },
      {
        name: `analyze_query_complexity${suffix}`,
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
        name: `security_status${suffix}`,
        description: 'Get security system status and rate limiting information',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
  }

  async handleToolCall(name: string, args: any, clientId?: string): Promise<any> {
    const queryId = this.generateQueryId();

    // Rate limiting check
    const rateLimitResult = this.rateLimiter.checkLimit({ clientId });
    if (!rateLimitResult.allowed) {
      throw this.createMCPError(-32429, 'RATE_LIMIT_EXCEEDED',
        `Rate limit exceeded. Try again in ${rateLimitResult.retryAfter} seconds.`, queryId);
    }

    try {
      this.logger.info(`Secure tool called: ${name}`, {
        args: this.sanitizeArgsForLogging(args),
        rate_limit_remaining: rateLimitResult.remaining
      }, queryId);

      const suffix = this.useIAM ? '_secure_iam' : '_secure';

      switch (name) {
        case `structured_query${suffix}`:
          return await this.handleStructuredQuery(args, queryId);

        case `validated_query${suffix}`:
          return await this.handleValidatedQuery(args, queryId);

        case `query_patterns${suffix}`:
          return await this.handleQueryPatterns(queryId);

        case `analyze_query_complexity${suffix}`:
          return await this.handleAnalyzeComplexity(args, queryId);

        case `security_status${suffix}`:
          return await this.handleSecurityStatus(queryId);

        default:
          throw this.createMCPError(-32002, 'UNKNOWN_TOOL', `Unknown secure tool: ${name}`, queryId);
      }
    } catch (error) {
      this.logger.error(`Secure tool execution failed: ${name}`, {
        error: error instanceof Error ? error.message : String(error),
        args: this.sanitizeArgsForLogging(args)
      }, queryId);
      throw error;
    }
  }

  private async handleStructuredQuery(args: any, queryId: string): Promise<any> {
    const { pattern_name, parameters, limit = 100 } = args;

    if (!pattern_name || typeof pattern_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'pattern_name is required and must be a string', queryId);
    }

    if (!parameters || typeof parameters !== 'object') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'parameters is required and must be an object', queryId);
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

    try {
      const result = await this.queries.executeSelect({
        query: finalQuery,
        parameters: validation.sanitizedParams || [],
        limit
      });

      this.logger.info('Structured query executed successfully', {
        pattern_name,
        parameter_count: Object.keys(parameters).length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms
      }, queryId);

      return {
        ...result,
        query_pattern: pattern_name,
        security_validated: true,
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'EXECUTION_ERROR',
        `Structured query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleValidatedQuery(args: any, queryId: string): Promise<any> {
    const { query, parameters = [], limit = 100, bypass_complexity_check = false } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'query is required and must be a string', queryId);
    }

    // Query size validation
    const sizeCheck = this.complexityAnalyzer.validateQuerySize(query);
    if (!sizeCheck.allowed) {
      throw this.createMCPError(-32002, 'QUERY_TOO_LARGE', sizeCheck.error!, queryId);
    }

    // Raw query validation
    const validation = this.queryValidator.validateRawQuery(query);
    if (!validation.isValid) {
      throw this.createMCPError(-32002, 'SQL_INJECTION_RISK',
        `Query security validation failed: ${validation.errors.join(', ')}`, queryId);
    }

    // Complexity analysis
    if (!bypass_complexity_check) {
      const complexity = this.complexityAnalyzer.analyzeComplexity(query);
      if (!complexity.allowed) {
        throw this.createMCPError(-32002, 'QUERY_TOO_COMPLEX',
          `Query complexity score ${complexity.score} exceeds maximum ${complexity.maxScore}. Factors: ${complexity.factors.join(', ')}`, queryId);
      }
    }

    try {
      const result = await this.queries.executeSelect({
        query: validation.sanitizedQuery!,
        parameters,
        limit
      });

      this.logger.info('Validated query executed successfully', {
        query_length: query.length,
        parameter_count: parameters.length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms,
        bypassed_complexity_check: bypass_complexity_check
      }, queryId);

      return {
        ...result,
        security_validated: true,
        complexity_bypassed: bypass_complexity_check,
        authentication_method: this.useIAM ? 'IAM' : 'Standard'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'EXECUTION_ERROR',
        `Validated query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

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
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'query is required and must be a string', queryId);
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

  private async handleSecurityStatus(queryId: string): Promise<any> {
    const rateLimitStats = this.rateLimiter.getStats();
    const patterns = this.queryValidator.getAvailablePatterns();

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
      authentication_method: this.useIAM ? 'IAM' : 'Standard',
      security_features_enabled: [
        'SQL injection prevention',
        'Query pattern validation',
        'Complexity analysis',
        'Rate limiting',
        'Parameter sanitization',
        'Input validation'
      ]
    };
  }

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
    return `secure_q_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}