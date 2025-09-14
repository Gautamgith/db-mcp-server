import { Logger } from '../logging/logger.js';

export interface QueryPattern {
  name: string;
  description: string;
  template: string;
  parameters: QueryParameter[];
  maxRows?: number;
  requiresExplicitLimit?: boolean;
}

export interface QueryParameter {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'array';
  required: boolean;
  validation?: {
    minLength?: number;
    maxLength?: number;
    min?: number;
    max?: number;
    pattern?: string;
    allowedValues?: (string | number | boolean)[];
  };
}

export interface ValidationResult {
  isValid: boolean;
  errors: string[];
  sanitizedQuery?: string | undefined;
  sanitizedParams?: unknown[] | undefined;
}

export class QueryValidator {
  private logger: Logger;
  private allowedPatterns: Map<string, QueryPattern> = new Map();

  constructor(logger: Logger) {
    this.logger = logger;
    this.initializeAllowedPatterns();
  }

  private initializeAllowedPatterns(): void {
    const patterns: QueryPattern[] = [
      {
        name: 'select_all_from_table',
        description: 'Select all columns from a specific table',
        template: 'SELECT * FROM {schema}.{table}',
        parameters: [
          { name: 'schema', type: 'string', required: false, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } }
        ],
        maxRows: 1000,
        requiresExplicitLimit: true
      },
      {
        name: 'select_columns_from_table',
        description: 'Select specific columns from a table',
        template: 'SELECT {columns} FROM {schema}.{table}',
        parameters: [
          { name: 'columns', type: 'array', required: true, validation: { maxLength: 50 } },
          { name: 'schema', type: 'string', required: false, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } }
        ],
        maxRows: 1000,
        requiresExplicitLimit: true
      },
      {
        name: 'select_with_where',
        description: 'Select with WHERE clause using parameterized conditions',
        template: 'SELECT {columns} FROM {schema}.{table} WHERE {column} {operator} $1',
        parameters: [
          { name: 'columns', type: 'array', required: true, validation: { maxLength: 50 } },
          { name: 'schema', type: 'string', required: false, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'column', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'operator', type: 'string', required: true, validation: { allowedValues: ['=', '!=', '<', '>', '<=', '>=', 'LIKE', 'ILIKE', 'IN'] } },
          { name: 'value', type: 'string', required: true }
        ],
        maxRows: 500
      },
      {
        name: 'count_table_rows',
        description: 'Count rows in a table',
        template: 'SELECT COUNT(*) as row_count FROM {schema}.{table}',
        parameters: [
          { name: 'schema', type: 'string', required: false, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } }
        ],
        maxRows: 1
      },
      {
        name: 'join_two_tables',
        description: 'Inner join between two tables',
        template: 'SELECT {select_columns} FROM {table1} t1 INNER JOIN {table2} t2 ON t1.{join_column1} = t2.{join_column2}',
        parameters: [
          { name: 'select_columns', type: 'array', required: true, validation: { maxLength: 20 } },
          { name: 'table1', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table2', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'join_column1', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'join_column2', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } }
        ],
        maxRows: 1000,
        requiresExplicitLimit: true
      },
      {
        name: 'aggregate_with_group_by',
        description: 'Aggregation query with GROUP BY',
        template: 'SELECT {group_columns}, {aggregate_function}({aggregate_column}) as {alias} FROM {schema}.{table} GROUP BY {group_columns}',
        parameters: [
          { name: 'group_columns', type: 'array', required: true, validation: { maxLength: 10 } },
          { name: 'aggregate_function', type: 'string', required: true, validation: { allowedValues: ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX'] } },
          { name: 'aggregate_column', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'alias', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'schema', type: 'string', required: false, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } },
          { name: 'table', type: 'string', required: true, validation: { pattern: '^[a-zA-Z][a-zA-Z0-9_]*$', maxLength: 63 } }
        ],
        maxRows: 100
      }
    ];

    for (const pattern of patterns) {
      this.allowedPatterns.set(pattern.name, pattern);
    }

    this.logger.info('Query patterns initialized', {
      pattern_count: patterns.length,
      patterns: patterns.map(p => p.name)
    });
  }

  validateStructuredQuery(patternName: string, params: Record<string, unknown>): ValidationResult {
    const pattern = this.allowedPatterns.get(patternName);

    if (!pattern) {
      return {
        isValid: false,
        errors: [`Unknown query pattern: ${patternName}`]
      };
    }

    const errors: string[] = [];

    // Validate all required parameters are present
    const requiredParams = pattern.parameters.filter(p => p.required);
    for (const param of requiredParams) {
      if (!(param.name in params) || params[param.name] === null || params[param.name] === undefined) {
        errors.push(`Required parameter '${param.name}' is missing`);
      }
    }

    // Validate each parameter
    const sanitizedParams: Record<string, unknown> = {};
    for (const param of pattern.parameters) {
      if (param.name in params) {
        const validationResult = this.validateParameter(param, params[param.name]);
        if (!validationResult.isValid) {
          errors.push(...validationResult.errors);
        } else {
          sanitizedParams[param.name] = validationResult.sanitizedValue;
        }
      } else if (!param.required) {
        // Set default values for optional parameters
        sanitizedParams[param.name] = param.name === 'schema' ? 'public' : null;
      }
    }

    if (errors.length > 0) {
      return { isValid: false, errors };
    }

    try {
      const sanitizedQuery = this.buildQuery(pattern, sanitizedParams);
      return {
        isValid: true,
        errors: [],
        sanitizedQuery,
        sanitizedParams: []
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [`Failed to build query: ${error instanceof Error ? error.message : String(error)}`]
      };
    }
  }

  private validateParameter(param: QueryParameter, value: unknown): { isValid: boolean; errors: string[]; sanitizedValue?: unknown } {
    const errors: string[] = [];

    // Type validation
    if (!this.validateParameterType(param.type, value)) {
      errors.push(`Parameter '${param.name}' must be of type ${param.type}`);
      return { isValid: false, errors };
    }

    let sanitizedValue = value;

    // Additional validation based on parameter type and rules
    if (param.validation) {
      const validation = param.validation;

      if (param.type === 'string' && typeof value === 'string') {
        if (validation.minLength && value.length < validation.minLength) {
          errors.push(`Parameter '${param.name}' must be at least ${validation.minLength} characters`);
        }
        if (validation.maxLength && value.length > validation.maxLength) {
          errors.push(`Parameter '${param.name}' must be at most ${validation.maxLength} characters`);
        }
        if (validation.pattern && !new RegExp(validation.pattern).test(value)) {
          errors.push(`Parameter '${param.name}' does not match required pattern`);
        }
        if (validation.allowedValues && !validation.allowedValues.includes(value)) {
          errors.push(`Parameter '${param.name}' must be one of: ${validation.allowedValues.join(', ')}`);
        }

        // Sanitize string by removing potentially dangerous characters
        sanitizedValue = this.sanitizeString(value);
      }

      if (param.type === 'number' && typeof value === 'number') {
        if (validation.min !== undefined && value < validation.min) {
          errors.push(`Parameter '${param.name}' must be at least ${validation.min}`);
        }
        if (validation.max !== undefined && value > validation.max) {
          errors.push(`Parameter '${param.name}' must be at most ${validation.max}`);
        }
      }

      if (param.type === 'array' && Array.isArray(value)) {
        if (validation.maxLength && value.length > validation.maxLength) {
          errors.push(`Parameter '${param.name}' array must have at most ${validation.maxLength} items`);
        }

        // Sanitize array elements if they are strings
        sanitizedValue = value.map(item =>
          typeof item === 'string' ? this.sanitizeString(item) : item
        );
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedValue
    };
  }

  private validateParameterType(expectedType: string, value: unknown): boolean {
    switch (expectedType) {
      case 'string':
        return typeof value === 'string';
      case 'number':
        return typeof value === 'number' && !isNaN(value);
      case 'boolean':
        return typeof value === 'boolean';
      case 'array':
        return Array.isArray(value);
      default:
        return false;
    }
  }

  private sanitizeString(value: string): string {
    // Remove or escape potentially dangerous SQL characters
    return value
      .replace(/[;'"\\]/g, '') // Remove semicolons, quotes, backslashes
      .replace(/--/g, '') // Remove SQL comments
      .replace(/\/\*/g, '') // Remove SQL block comment start
      .replace(/\*\//g, '') // Remove SQL block comment end
      .trim();
  }

  private buildQuery(pattern: QueryPattern, params: Record<string, unknown>): string {
    let query = pattern.template;

    // Replace template placeholders
    for (const [key, value] of Object.entries(params)) {
      if (value !== null && value !== undefined) {
        let replacementValue: string;

        if (Array.isArray(value)) {
          // Handle array parameters (e.g., column lists)
          replacementValue = value.map(item => this.sanitizeString(String(item))).join(', ');
        } else {
          replacementValue = this.sanitizeString(String(value));
        }

        query = query.replace(new RegExp(`\\{${key}\\}`, 'g'), replacementValue);
      }
    }

    // Remove any remaining template placeholders for optional parameters
    query = query.replace(/\{[^}]+\}\./g, ''); // Remove optional schema references
    query = query.replace(/\{[^}]+\}/g, ''); // Remove any remaining placeholders

    // Clean up any resulting syntax issues
    query = query.replace(/\s+/g, ' ').trim();

    return query;
  }

  validateRawQuery(query: string): ValidationResult {
    const errors: string[] = [];

    // Basic SQL injection pattern detection
    const suspiciousPatterns = [
      /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|TRUNCATE)/i,
      /UNION\s+SELECT/i,
      /--/,
      /\/\*[\s\S]*\*\//,
      /'[^']*'[^']*'/,
      /"\s*(OR|AND)\s*"/i,
      /'\s*(OR|AND)\s*'/i
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(query)) {
        errors.push('Query contains potentially dangerous SQL patterns');
        break;
      }
    }

    // Ensure query is read-only (starts with SELECT or WITH)
    const trimmedQuery = query.trim().toUpperCase();
    if (!trimmedQuery.startsWith('SELECT') && !trimmedQuery.startsWith('WITH')) {
      errors.push('Only SELECT queries are allowed');
    }

    // Check for multiple statements
    if (query.includes(';') && !query.trim().endsWith(';')) {
      errors.push('Multiple SQL statements are not allowed');
    }

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedQuery: errors.length === 0 ? query : undefined
    };
  }

  getAvailablePatterns(): QueryPattern[] {
    return Array.from(this.allowedPatterns.values());
  }

  getPattern(name: string): QueryPattern | undefined {
    return this.allowedPatterns.get(name);
  }
}