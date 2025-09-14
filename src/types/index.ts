export interface DatabaseConfig {
  host: string;
  port: number;
  database: string;
  user: string;
  region: string;
}

export interface TableInfo {
  table_name: string;
  schema_name: string;
  table_type: string;
}

export interface ColumnInfo {
  column_name: string;
  data_type: string;
  is_nullable: boolean;
  column_default: string | null;
  is_primary_key: boolean;
}

export interface TableSchema {
  table_name: string;
  schema_name: string;
  columns: ColumnInfo[];
  indexes: IndexInfo[];
  foreign_keys: ForeignKeyInfo[];
}

export interface IndexInfo {
  index_name: string;
  column_names: string[];
  is_unique: boolean;
  is_primary: boolean;
}

export interface ForeignKeyInfo {
  constraint_name: string;
  column_name: string;
  referenced_table: string;
  referenced_column: string;
}

export interface QueryResult {
  rows: Record<string, unknown>[];
  row_count: number;
  execution_time_ms: number;
}

export interface QueryParameters {
  query: string;
  parameters?: unknown[];
  limit?: number;
}

export interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  context?: Record<string, unknown> | undefined;
  query_id?: string | undefined;
}

export interface IAMTokenInfo {
  token: string;
  expires_at: Date;
  generated_at: Date;
}

export interface ConnectionPoolConfig {
  max: number;
  min: number;
  idle_timeout_ms: number;
  connection_timeout_ms: number;
}

export type MCPErrorCode = -32000 | -32001 | -32002 | -32003 | -32004;

export interface MCPError {
  code: MCPErrorCode;
  message: string;
  data?: {
    error_type: string;
    details: string;
    query_id?: string | undefined;
  };
}