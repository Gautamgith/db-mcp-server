import { IAMDatabaseConnection } from './iam-connection.js';
import { TableInfo, TableSchema, ColumnInfo, QueryResult, QueryParameters } from '../types/index.js';
import { Logger } from '../logging/logger.js';

export class IAMDatabaseQueries {
  private db: IAMDatabaseConnection;
  private logger: Logger;

  constructor(db: IAMDatabaseConnection, logger: Logger) {
    this.db = db;
    this.logger = logger;
  }

  async listTables(schemaName: string = 'public'): Promise<TableInfo[]> {
    const queryId = this.generateQueryId();

    this.logger.debug('Listing tables with IAM auth', { schema: schemaName }, queryId);

    const query = `
      SELECT
        table_name,
        table_schema as schema_name,
        table_type
      FROM information_schema.tables
      WHERE table_schema = $1
      AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `;

    try {
      const result = await this.db.query<TableInfo>(query, [schemaName]);

      this.logger.info('Tables listed successfully with IAM auth', {
        schema: schemaName,
        count: result.rows.length,
        auth_info: this.db.getAuthInfo()
      }, queryId);

      return result.rows;
    } catch (error) {
      this.logger.error('Failed to list tables with IAM auth', {
        schema: schemaName,
        error: error instanceof Error ? error.message : String(error),
        auth_info: this.db.getAuthInfo()
      }, queryId);
      throw error;
    }
  }

  async describeTable(tableName: string, schemaName: string = 'public'): Promise<TableSchema> {
    const queryId = this.generateQueryId();

    this.logger.debug('Describing table with IAM auth', {
      table: tableName,
      schema: schemaName
    }, queryId);

    const columnsQuery = `
      SELECT
        c.column_name,
        c.data_type,
        c.is_nullable::boolean,
        c.column_default,
        CASE
          WHEN pk.column_name IS NOT NULL THEN true
          ELSE false
        END as is_primary_key
      FROM information_schema.columns c
      LEFT JOIN (
        SELECT ku.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage ku
          ON tc.constraint_name = ku.constraint_name
        WHERE tc.constraint_type = 'PRIMARY KEY'
          AND tc.table_name = $1
          AND tc.table_schema = $2
      ) pk ON c.column_name = pk.column_name
      WHERE c.table_name = $1
        AND c.table_schema = $2
      ORDER BY c.ordinal_position
    `;

    const indexesQuery = `
      SELECT
        indexname as index_name,
        array_agg(attname) as column_names,
        indexdef LIKE '%UNIQUE%' as is_unique,
        indexdef LIKE '%pkey%' as is_primary
      FROM pg_indexes i
      JOIN pg_class t ON t.relname = i.tablename
      JOIN pg_namespace n ON n.oid = t.relnamespace
      JOIN pg_index idx ON idx.indrelid = t.oid
      JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(idx.indkey)
      WHERE i.tablename = $1
        AND n.nspname = $2
      GROUP BY i.indexname, i.indexdef
    `;

    const foreignKeysQuery = `
      SELECT
        tc.constraint_name,
        kcu.column_name,
        ccu.table_name AS referenced_table,
        ccu.column_name AS referenced_column
      FROM information_schema.table_constraints AS tc
      JOIN information_schema.key_column_usage AS kcu
        ON tc.constraint_name = kcu.constraint_name
      JOIN information_schema.constraint_column_usage AS ccu
        ON ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_name = $1
        AND tc.table_schema = $2
    `;

    try {
      const [columnsResult, indexesResult, foreignKeysResult] = await Promise.all([
        this.db.query<ColumnInfo>(columnsQuery, [tableName, schemaName]),
        this.db.query(indexesQuery, [tableName, schemaName]),
        this.db.query(foreignKeysQuery, [tableName, schemaName])
      ]);

      const tableSchema: TableSchema = {
        table_name: tableName,
        schema_name: schemaName,
        columns: columnsResult.rows,
        indexes: indexesResult.rows,
        foreign_keys: foreignKeysResult.rows
      };

      this.logger.info('Table described successfully with IAM auth', {
        table: tableName,
        schema: schemaName,
        columns: columnsResult.rows.length,
        indexes: indexesResult.rows.length,
        foreign_keys: foreignKeysResult.rows.length,
        auth_info: this.db.getAuthInfo()
      }, queryId);

      return tableSchema;
    } catch (error) {
      this.logger.error('Failed to describe table with IAM auth', {
        table: tableName,
        schema: schemaName,
        error: error instanceof Error ? error.message : String(error),
        auth_info: this.db.getAuthInfo()
      }, queryId);
      throw error;
    }
  }

  async executeSelect(params: QueryParameters): Promise<QueryResult> {
    const queryId = this.generateQueryId();
    const { query, parameters = [], limit = 100 } = params;

    this.logger.debug('Executing SELECT with IAM auth', {
      sanitized_query: this.sanitizeQuery(query),
      parameter_count: parameters.length,
      limit
    }, queryId);

    if (!this.isSelectQuery(query)) {
      throw new Error('Only SELECT queries are allowed');
    }

    const limitedQuery = this.addLimitToQuery(query, limit);

    try {
      const start = Date.now();
      const result = await this.db.query(limitedQuery, parameters);
      const executionTime = Date.now() - start;

      const queryResult: QueryResult = {
        rows: result.rows,
        row_count: result.rowCount,
        execution_time_ms: executionTime
      };

      this.logger.info('SELECT query executed successfully with IAM auth', {
        sanitized_query: this.sanitizeQuery(query),
        parameter_count: parameters.length,
        row_count: result.rowCount,
        execution_time_ms: executionTime,
        auth_info: this.db.getAuthInfo()
      }, queryId);

      return queryResult;
    } catch (error) {
      this.logger.error('Failed to execute SELECT with IAM auth', {
        sanitized_query: this.sanitizeQuery(query),
        parameter_count: parameters.length,
        error: error instanceof Error ? error.message : String(error),
        auth_info: this.db.getAuthInfo()
      }, queryId);
      throw error;
    }
  }

  private isSelectQuery(query: string): boolean {
    const trimmedQuery = query.trim().toLowerCase();
    return trimmedQuery.startsWith('select') || trimmedQuery.startsWith('with');
  }

  private addLimitToQuery(query: string, limit: number): string {
    const trimmedQuery = query.trim();

    if (trimmedQuery.toLowerCase().includes('limit')) {
      return trimmedQuery;
    }

    if (trimmedQuery.endsWith(';')) {
      return `${trimmedQuery.slice(0, -1)} LIMIT ${limit};`;
    }

    return `${trimmedQuery} LIMIT ${limit}`;
  }

  private sanitizeQuery(query: string): string {
    return query.replace(/\$\d+/g, '?').replace(/'/g, '***');
  }

  async validateQuery(query: string): Promise<boolean> {
    const queryId = this.generateQueryId();

    try {
      const explainQuery = `EXPLAIN ${query}`;
      await this.db.query(explainQuery);

      this.logger.debug('Query validation successful with IAM auth', {
        sanitized_query: this.sanitizeQuery(query)
      }, queryId);

      return true;
    } catch (error) {
      this.logger.warn('Query validation failed with IAM auth', {
        sanitized_query: this.sanitizeQuery(query),
        error: error instanceof Error ? error.message : String(error)
      }, queryId);

      return false;
    }
  }

  async getConnectionHealth(): Promise<{
    is_connected: boolean;
    token_expires_in_ms: number | null;
    reconnect_attempts: number;
    last_activity: string;
  }> {
    const authInfo = this.db.getAuthInfo();

    return {
      is_connected: this.db.isConnected(),
      token_expires_in_ms: authInfo.token_info?.expires_at
        ? authInfo.token_info.expires_at.getTime() - Date.now()
        : null,
      reconnect_attempts: authInfo.reconnect_attempts,
      last_activity: new Date().toISOString()
    };
  }

  private generateQueryId(): string {
    return `iam_q_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}