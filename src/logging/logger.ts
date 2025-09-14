import { LogEntry } from '../types/index.js';

export class Logger {
  private logLevel: string;
  private logFormat: string;

  constructor() {
    this.logLevel = process.env.LOG_LEVEL ?? 'info';
    this.logFormat = process.env.LOG_FORMAT ?? 'json';
  }

  private shouldLog(level: string): boolean {
    const levels = { debug: 0, info: 1, warn: 2, error: 3 };
    return levels[level as keyof typeof levels] >= levels[this.logLevel as keyof typeof levels];
  }

  private formatMessage(entry: LogEntry): string {
    if (this.logFormat === 'json') {
      return JSON.stringify(entry);
    }

    const context = entry.context ? ` ${JSON.stringify(entry.context)}` : '';
    const queryId = entry.query_id ? ` [${entry.query_id}]` : '';
    return `${entry.timestamp} [${entry.level.toUpperCase()}]${queryId} ${entry.message}${context}`;
  }

  private log(level: LogEntry['level'], message: string, context?: Record<string, unknown>, queryId?: string): void {
    if (!this.shouldLog(level)) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
      query_id: queryId
    };

    const formattedMessage = this.formatMessage(entry);

    switch (level) {
      case 'error':
        console.error(formattedMessage);
        break;
      case 'warn':
        console.warn(formattedMessage);
        break;
      case 'info':
        console.info(formattedMessage);
        break;
      case 'debug':
        console.debug(formattedMessage);
        break;
    }
  }

  debug(message: string, context?: Record<string, unknown>, queryId?: string): void {
    this.log('debug', message, context, queryId);
  }

  info(message: string, context?: Record<string, unknown>, queryId?: string): void {
    this.log('info', message, context, queryId);
  }

  warn(message: string, context?: Record<string, unknown>, queryId?: string): void {
    this.log('warn', message, context, queryId);
  }

  error(message: string, context?: Record<string, unknown>, queryId?: string): void {
    this.log('error', message, context, queryId);
  }

  sanitizeQuery(query: string): string {
    return query.replace(/\$\d+/g, '?');
  }

  sanitizeParameters(params: unknown[]): string {
    return params.map(() => '[REDACTED]').join(', ');
  }
}