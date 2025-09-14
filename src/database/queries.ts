import { DatabaseConnection } from './connection.js';
import { TableInfo, TableSchema, ColumnInfo, QueryResult, QueryParameters } from '../types/index.js';

export class DatabaseQueries {
  private db: DatabaseConnection;

  constructor(db: DatabaseConnection) {
    this.db = db;
  }

  async listTables(schemaName: string = 'public'): Promise<TableInfo[]> {
    const query = `
      SELECT
        table_name,
        table_schema as schema_name,
        table_type
      FROM information_schema.tables
      WHERE table_schema = $1
      ORDER BY table_name
    `;

    const result = await this.db.query<TableInfo>(query, [schemaName]);
    return result.rows;
  }

  async describeTable(tableName: string, schemaName: string = 'public'): Promise<TableSchema> {
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
        i.indexname as index_name,
        array_agg(a.attname ORDER BY a.attnum) as column_names,
        i.indexdef LIKE '%UNIQUE%' as is_unique,
        c.contype = 'p' as is_primary
      FROM pg_indexes i
      JOIN pg_class t ON t.relname = i.tablename
      JOIN pg_namespace n ON n.oid = t.relnamespace
      LEFT JOIN pg_attribute a ON a.attrelid = t.oid
      LEFT JOIN pg_constraint c ON c.conrelid = t.oid AND c.contype IN ('p', 'u')
      WHERE i.tablename = $1
        AND n.nspname = $2
        AND a.attname = ANY(string_to_array(replace(substring(i.indexdef from '\\((.*)\\)'), ' ', ''), ','))
      GROUP BY i.indexname, i.indexdef, c.contype
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

    const [columnsResult, indexesResult, foreignKeysResult] = await Promise.all([
      this.db.query<ColumnInfo>(columnsQuery, [tableName, schemaName]),
      this.db.query(indexesQuery, [tableName, schemaName]),
      this.db.query(foreignKeysQuery, [tableName, schemaName])
    ]);

    return {
      table_name: tableName,
      schema_name: schemaName,
      columns: columnsResult.rows,
      indexes: indexesResult.rows,
      foreign_keys: foreignKeysResult.rows
    };
  }

  async executeSelect(params: QueryParameters): Promise<QueryResult> {
    const { query, parameters = [], limit = 100 } = params;

    if (!this.isSelectQuery(query)) {
      throw new Error('Only SELECT queries are allowed');
    }

    const limitedQuery = this.addLimitToQuery(query, limit);
    const start = Date.now();

    const result = await this.db.query(limitedQuery, parameters);
    const executionTime = Date.now() - start;

    return {
      rows: result.rows,
      row_count: result.rowCount,
      execution_time_ms: executionTime
    };
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

  async validateQuery(query: string): Promise<boolean> {
    try {
      const explainQuery = `EXPLAIN ${query}`;
      await this.db.query(explainQuery);
      return true;
    } catch (error) {
      return false;
    }
  }
}