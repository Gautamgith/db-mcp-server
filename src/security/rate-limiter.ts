import { Logger } from '../logging/logger.js';

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  keyGenerator?: (context: any) => string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetTime: number;
  retryAfter?: number;
}

interface RequestWindow {
  count: number;
  resetTime: number;
}

export class RateLimiter {
  private logger: Logger;
  private windows: Map<string, RequestWindow> = new Map();
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;

    // Clean up expired windows every minute
    setInterval(() => this.cleanup(), 60000);
  }

  checkLimit(context: any = {}): RateLimitResult {
    const key = this.config.keyGenerator ? this.config.keyGenerator(context) : 'default';
    const now = Date.now();
    const windowStart = Math.floor(now / this.config.windowMs) * this.config.windowMs;
    const resetTime = windowStart + this.config.windowMs;

    let window = this.windows.get(key);

    // Create new window or reset if expired
    if (!window || window.resetTime <= now) {
      window = {
        count: 0,
        resetTime
      };
      this.windows.set(key, window);
    }

    const allowed = window.count < this.config.maxRequests;

    if (allowed) {
      window.count++;
    }

    const result: RateLimitResult = {
      allowed,
      remaining: Math.max(0, this.config.maxRequests - window.count),
      resetTime: window.resetTime
    };

    if (!allowed) {
      result.retryAfter = Math.ceil((window.resetTime - now) / 1000);

      this.logger.warn('Rate limit exceeded', {
        key,
        current_count: window.count,
        max_requests: this.config.maxRequests,
        window_ms: this.config.windowMs,
        retry_after_seconds: result.retryAfter
      });
    } else {
      this.logger.debug('Rate limit check passed', {
        key,
        current_count: window.count,
        remaining: result.remaining
      });
    }

    return result;
  }

  private cleanup(): void {
    const now = Date.now();
    const expiredKeys: string[] = [];

    for (const [key, window] of this.windows.entries()) {
      if (window.resetTime <= now) {
        expiredKeys.push(key);
      }
    }

    for (const key of expiredKeys) {
      this.windows.delete(key);
    }

    if (expiredKeys.length > 0) {
      this.logger.debug('Cleaned up expired rate limit windows', {
        cleaned_count: expiredKeys.length,
        remaining_windows: this.windows.size
      });
    }
  }

  reset(key?: string): void {
    if (key) {
      this.windows.delete(key);
      this.logger.info('Reset rate limit for key', { key });
    } else {
      this.windows.clear();
      this.logger.info('Reset all rate limits');
    }
  }

  getStats(): { totalWindows: number; activeKeys: string[] } {
    return {
      totalWindows: this.windows.size,
      activeKeys: Array.from(this.windows.keys())
    };
  }
}

export class QueryComplexityAnalyzer {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  analyzeComplexity(query: string): {
    score: number;
    factors: string[];
    allowed: boolean;
    maxScore: number;
  } {
    const factors: string[] = [];
    let score = 1; // Base score

    const upperQuery = query.toUpperCase();

    // Join complexity
    const joinCount = (upperQuery.match(/\bJOIN\b/g) || []).length;
    if (joinCount > 0) {
      score += joinCount * 2;
      factors.push(`${joinCount} JOIN(s)`);
    }

    // Subquery complexity
    const subqueryCount = (upperQuery.match(/\bSELECT\b/g) || []).length - 1;
    if (subqueryCount > 0) {
      score += subqueryCount * 3;
      factors.push(`${subqueryCount} subquery(ies)`);
    }

    // Function complexity
    const functions = ['COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'STRING_AGG', 'ARRAY_AGG'];
    for (const func of functions) {
      const count = (upperQuery.match(new RegExp(`\\b${func}\\b`, 'g')) || []).length;
      if (count > 0) {
        score += count * 1;
        factors.push(`${count} ${func} function(s)`);
      }
    }

    // Window function complexity
    if (upperQuery.includes('OVER(')) {
      const windowCount = (upperQuery.match(/OVER\(/g) || []).length;
      score += windowCount * 4;
      factors.push(`${windowCount} window function(s)`);
    }

    // DISTINCT complexity
    if (upperQuery.includes('DISTINCT')) {
      score += 2;
      factors.push('DISTINCT clause');
    }

    // ORDER BY complexity
    if (upperQuery.includes('ORDER BY')) {
      score += 1;
      factors.push('ORDER BY clause');
    }

    // GROUP BY complexity
    if (upperQuery.includes('GROUP BY')) {
      score += 2;
      factors.push('GROUP BY clause');
    }

    // HAVING complexity
    if (upperQuery.includes('HAVING')) {
      score += 2;
      factors.push('HAVING clause');
    }

    // CTE (Common Table Expression) complexity
    if (upperQuery.includes('WITH')) {
      const cteCount = (upperQuery.match(/\bWITH\b/g) || []).length;
      score += cteCount * 3;
      factors.push(`${cteCount} CTE(s)`);
    }

    const maxScore = parseInt(process.env.MAX_QUERY_COMPLEXITY_SCORE ?? '20', 10);
    const allowed = score <= maxScore;

    this.logger.debug('Query complexity analyzed', {
      query_length: query.length,
      complexity_score: score,
      max_allowed_score: maxScore,
      factors,
      allowed
    });

    return {
      score,
      factors,
      allowed,
      maxScore
    };
  }

  validateQuerySize(query: string): { allowed: boolean; size: number; maxSize: number; error?: string | undefined } {
    const size = query.length;
    const maxSize = parseInt(process.env.MAX_QUERY_SIZE ?? '10000', 10);

    const allowed = size <= maxSize;

    if (!allowed) {
      this.logger.warn('Query size limit exceeded', {
        query_size: size,
        max_allowed_size: maxSize
      });
    }

    return {
      allowed,
      size,
      maxSize,
      error: allowed ? undefined : `Query size ${size} exceeds maximum allowed size ${maxSize}`
    };
  }
}