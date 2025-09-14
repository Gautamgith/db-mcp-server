import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { IAMDatabaseQueries } from '../database/iam-queries.js';
import { Logger } from '../logging/logger.js';
import { MCPError } from '../types/index.js';

export class IAMDatabaseTools {
  private queries: IAMDatabaseQueries;
  private logger: Logger;

  constructor(queries: IAMDatabaseQueries, logger: Logger) {
    this.queries = queries;
    this.logger = logger;
  }

  getToolDefinitions(): Tool[] {
    return [
      {
        name: 'list_tables_iam',
        description: 'List all tables in the PostgreSQL database using IAM authentication',
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
        name: 'describe_table_iam',
        description: 'Get detailed schema information for a specific table using IAM authentication',
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
        name: 'execute_select_iam',
        description: 'Execute a parameterized SELECT query with IAM authentication and safety checks',
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
      },
      {
        name: 'connection_health_iam',
        description: 'Check the health of the IAM-authenticated database connection',
        inputSchema: {
          type: 'object',
          properties: {}
        }
      }
    ];
  }

  async handleToolCall(name: string, args: any): Promise<any> {
    const queryId = this.generateQueryId();

    try {
      this.logger.info(`IAM tool called: ${name}`, { args }, queryId);

      switch (name) {
        case 'list_tables_iam':
          return await this.handleListTables(args, queryId);

        case 'describe_table_iam':
          return await this.handleDescribeTable(args, queryId);

        case 'execute_select_iam':
          return await this.handleExecuteSelect(args, queryId);

        case 'connection_health_iam':
          return await this.handleConnectionHealth(queryId);

        default:
          throw this.createMCPError(-32002, 'UNKNOWN_TOOL', `Unknown IAM tool: ${name}`, queryId);
      }
    } catch (error) {
      this.logger.error(`IAM tool execution failed: ${name}`, {
        error: error instanceof Error ? error.message : String(error),
        args
      }, queryId);
      throw error;
    }
  }

  private async handleListTables(args: any, queryId: string): Promise<any> {
    const schemaName = args.schema_name ?? 'public';

    try {
      const tables = await this.queries.listTables(schemaName);

      this.logger.info('IAM tables listed successfully', {
        schema: schemaName,
        count: tables.length
      }, queryId);

      return {
        tables,
        schema_name: schemaName,
        count: tables.length,
        authentication_method: 'IAM',
        connection_health: await this.queries.getConnectionHealth()
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'IAM_DATABASE_ERROR', `Failed to list tables with IAM auth: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleDescribeTable(args: any, queryId: string): Promise<any> {
    const { table_name, schema_name = 'public' } = args;

    if (!table_name || typeof table_name !== 'string') {
      throw this.createMCPError(-32003, 'PARAMETER_ERROR', 'table_name is required and must be a string', queryId);
    }

    try {
      const tableSchema = await this.queries.describeTable(table_name, schema_name);

      this.logger.info('IAM table described successfully', {
        table: table_name,
        schema: schema_name,
        columns: tableSchema.columns.length
      }, queryId);

      return {
        table_info: tableSchema,
        authentication_method: 'IAM',
        connection_health: await this.queries.getConnectionHealth()
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'IAM_DATABASE_ERROR', `Failed to describe table with IAM auth: ${error instanceof Error ? error.message : String(error)}`, queryId);
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

      this.logger.info('IAM query executed successfully', {
        parameter_count: parameters.length,
        row_count: result.row_count,
        execution_time: result.execution_time_ms
      }, queryId);

      return {
        ...result,
        authentication_method: 'IAM',
        connection_health: await this.queries.getConnectionHealth()
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'IAM_DATABASE_ERROR', `IAM query execution failed: ${error instanceof Error ? error.message : String(error)}`, queryId);
    }
  }

  private async handleConnectionHealth(queryId: string): Promise<any> {
    try {
      const health = await this.queries.getConnectionHealth();

      this.logger.info('IAM connection health checked', {
        is_connected: health.is_connected,
        token_expires_in_minutes: health.token_expires_in_ms ? Math.round(health.token_expires_in_ms / 60000) : null
      }, queryId);

      return {
        connection_health: health,
        authentication_method: 'IAM',
        status: health.is_connected ? 'healthy' : 'disconnected'
      };
    } catch (error) {
      throw this.createMCPError(-32000, 'IAM_CONNECTION_ERROR', `Failed to check IAM connection health: ${error instanceof Error ? error.message : String(error)}`, queryId);
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
    return `iam_tool_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}