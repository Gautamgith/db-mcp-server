import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { DatabaseQueries } from '../database/queries.js';
import { Logger } from '../logging/logger.js';
import { MCPError } from '../types/index.js';

export class DatabaseTools {
  private queries: DatabaseQueries;
  private logger: Logger;

  constructor(queries: DatabaseQueries, logger: Logger) {
    this.queries = queries;
    this.logger = logger;
  }

  getToolDefinitions(): Tool[] {
    return [
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
        description: 'Get detailed schema information for a specific table',
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
      {
        name: 'execute_select',
        description: 'Execute a parameterized SELECT query with safety checks',
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
              }
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
      }
    ];
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const queryId = this.generateQueryId();

    try {
      this.logger.info(`Tool called: ${name}`, { args }, queryId);

      switch (name) {
        case 'list_tables':
          return await this.handleListTables(args, queryId);

        case 'describe_table':
          return await this.handleDescribeTable(args, queryId);

        case 'execute_select':
          return await this.handleExecuteSelect(args, queryId);

        default:
          throw this.createMCPError(-32002, 'UNKNOWN_TOOL', `Unknown tool: ${name}`, queryId);
      }
    } catch (error) {
      this.logger.error(`Tool execution failed: ${name}`, { error: error instanceof Error ? error.message : String(error), args }, queryId);
      throw error;
    }
  }

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
        count: tables.length
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR', `Failed to list tables: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleDescribeTable(args: any, queryId: string): Promise<any> {
    const { table_name, schema_name = 'public' } = args;

    if (!table_name || typeof table_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'table_name is required and must be a string', queryId);
    }

    try {
      const tableSchema = await this.queries.describeTable(table_name, schema_name);

      this.logger.info('Table described successfully', {
        table: table_name,
        schema: schema_name,
        columns: tableSchema.columns.length
      }, queryId);

      return {
        table_info: tableSchema
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR', `Failed to describe table: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleExecuteSelect(args: any, queryId: string): Promise<any> {
    const { query, parameters = [], limit = 100 } = args;

    if (!query || typeof query !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'query is required and must be a string', queryId);
    }

    if (!Array.isArray(parameters)) {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'parameters must be an array', queryId);
    }

    if (typeof limit !== 'number' || limit < 1 || limit > 1000) {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'limit must be a number between 1 and 1000', queryId);
    }

    try {
      const result = await this.queries.executeSelect({ query, parameters, limit });

      this.logger.info('Query executed successfully', {
        sanitized_query: this.logger.sanitizeQuery(query),
        parameter_count: parameters.length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms
      }, queryId);

      return result;
    } catch (error) {
      throw this.createMCPError(-32000, 'DATABASE_ERROR', `Query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
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