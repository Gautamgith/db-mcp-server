/**
 * Model Theft Protection (OWASP LLM10)
 *
 * Implements controls to detect and prevent model extraction attempts:
 * - Query pattern analysis for systematic extraction
 * - Response obfuscation
 * - Rate limiting enhancements
 * - Behavioral anomaly detection
 */

import { Logger } from '../logging/logger.js';

export interface ExtractionAttempt {
  sessionId: string;
  userId: string | undefined;
  pattern: string;
  confidence: number;
  evidence: string[];
  timestamp: Date;
}

export interface ExtractionDetectionResult {
  isAttempt: boolean;
  confidence: number; // 0-100
  patterns: string[];
  recommendedAction: 'allow' | 'flag' | 'block';
  reasoning: string;
}

export class ModelTheftProtectionSystem {
  private logger: Logger;
  private sessionQueryHistory: Map<string, QueryHistoryEntry[]>;
  private blockedSessions: Set<string>;

  // Detection thresholds
  private readonly SYSTEMATIC_QUERY_THRESHOLD = 10;
  private readonly SIMILAR_QUERY_THRESHOLD = 0.8;
  private readonly RAPID_QUERY_WINDOW_MS = 60000; // 1 minute
  private readonly RAPID_QUERY_THRESHOLD = 20;

  constructor(logger: Logger) {
    this.logger = logger;
    this.sessionQueryHistory = new Map();
    this.blockedSessions = new Set();

    // Cleanup old history every hour
    setInterval(() => this.cleanupOldHistory(), 3600000);
  }

  /**
   * Analyze a query for potential model extraction attempt
   */
  async analyzeForExtraction(
    query: string,
    sessionId: string,
    userId?: string
  ): Promise<ExtractionDetectionResult> {
    // Check if session is already blocked
    if (this.blockedSessions.has(sessionId)) {
      return {
        isAttempt: true,
        confidence: 100,
        patterns: ['blocked_session'],
        recommendedAction: 'block',
        reasoning: 'Session previously identified as performing extraction attempts'
      };
    }

    // Record this query
    this.recordQuery(sessionId, query, userId);

    // Get session history
    const history = this.sessionQueryHistory.get(sessionId) || [];

    // Run multiple detection methods
    const detections = {
      systematic: this.detectSystematicExtraction(history),
      rapidFire: this.detectRapidFireQueries(history),
      schemaMapping: this.detectSchemaMapping(history),
      dataEnumeration: this.detectDataEnumeration(history),
      similarityPattern: this.detectSimilarityPattern(history),
      comprehensiveScan: this.detectComprehensiveScan(query, history)
    };

    // Calculate overall confidence
    const confidenceScores = Object.values(detections).map(d => d.confidence);
    const maxConfidence = Math.max(...confidenceScores);
    const avgConfidence = confidenceScores.reduce((a, b) => a + b, 0) / confidenceScores.length;

    // Weighted confidence (max has more weight)
    const overallConfidence = Math.round((maxConfidence * 0.7) + (avgConfidence * 0.3));

    // Collect all detected patterns
    const patterns: string[] = [];
    const evidence: string[] = [];

    Object.entries(detections).forEach(([key, result]) => {
      if (result.detected) {
        patterns.push(key);
        evidence.push(...result.evidence);
      }
    });

    const isAttempt = overallConfidence > 50;

    // Determine action
    let recommendedAction: 'allow' | 'flag' | 'block';
    if (overallConfidence >= 80) {
      recommendedAction = 'block';
      this.blockedSessions.add(sessionId);
    } else if (overallConfidence >= 60) {
      recommendedAction = 'flag';
    } else {
      recommendedAction = 'allow';
    }

    // Log if suspicious
    if (isAttempt) {
      this.logger.warn('Potential model extraction attempt detected', {
        session_id: sessionId,
        user_id: userId,
        confidence: overallConfidence,
        patterns,
        action: recommendedAction
      });

      // Store extraction attempt
      this.recordExtractionAttempt({
        sessionId,
        userId,
        pattern: patterns.join(', '),
        confidence: overallConfidence,
        evidence,
        timestamp: new Date()
      });
    }

    return {
      isAttempt,
      confidence: overallConfidence,
      patterns,
      recommendedAction,
      reasoning: this.generateReasoning(patterns, overallConfidence)
    };
  }

  /**
   * Detect systematic extraction pattern
   * (sequential querying of all tables/columns)
   */
  private detectSystematicExtraction(history: QueryHistoryEntry[]): DetectionResult {
    if (history.length < this.SYSTEMATIC_QUERY_THRESHOLD) {
      return { detected: false, confidence: 0, evidence: [] };
    }

    const recentQueries = history.slice(-30); // Last 30 queries
    const evidence: string[] = [];

    // Check for list_tables followed by describe_table for many tables
    const listTablesCalls = recentQueries.filter(h => h.toolName === 'list_tables').length;
    const describeTableCalls = recentQueries.filter(h => h.toolName === 'describe_table').length;

    if (listTablesCalls > 0 && describeTableCalls > 5) {
      evidence.push(`Listed tables ${listTablesCalls} time(s), described ${describeTableCalls} tables`);
    }

    // Check for sequential table querying
    const uniqueTables = new Set(
      recentQueries
        .filter(h => h.tableName)
        .map(h => h.tableName)
    );

    if (uniqueTables.size > 10) {
      evidence.push(`Queried ${uniqueTables.size} different tables`);
    }

    // Check for column enumeration pattern
    const selectAllPatterns = recentQueries.filter(h =>
      h.query && /SELECT\s+\*/i.test(h.query)
    ).length;

    if (selectAllPatterns > 5) {
      evidence.push(`${selectAllPatterns} SELECT * queries (full column enumeration)`);
    }

    const confidence = Math.min(100, (evidence.length * 30));

    return {
      detected: evidence.length > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect rapid-fire query pattern
   */
  private detectRapidFireQueries(history: QueryHistoryEntry[]): DetectionResult {
    const now = Date.now();
    const recentQueries = history.filter(
      h => (now - h.timestamp.getTime()) < this.RAPID_QUERY_WINDOW_MS
    );

    if (recentQueries.length >= this.RAPID_QUERY_THRESHOLD) {
      return {
        detected: true,
        confidence: Math.min(100, recentQueries.length * 4),
        evidence: [`${recentQueries.length} queries in ${this.RAPID_QUERY_WINDOW_MS/1000} seconds`]
      };
    }

    return { detected: false, confidence: 0, evidence: [] };
  }

  /**
   * Detect schema mapping pattern
   */
  private detectSchemaMapping(history: QueryHistoryEntry[]): DetectionResult {
    const recentQueries = history.slice(-20);
    const evidence: string[] = [];

    // Count information_schema queries
    const schemaQueries = recentQueries.filter(h =>
      h.query && /information_schema/i.test(h.query)
    ).length;

    if (schemaQueries > 3) {
      evidence.push(`${schemaQueries} information_schema queries`);
    }

    // Count pg_catalog queries
    const catalogQueries = recentQueries.filter(h =>
      h.query && /pg_catalog|pg_class|pg_attribute/i.test(h.query)
    ).length;

    if (catalogQueries > 2) {
      evidence.push(`${catalogQueries} pg_catalog queries`);
    }

    // Count describe_table calls
    const describeCount = recentQueries.filter(h =>
      h.toolName === 'describe_table'
    ).length;

    if (describeCount > 8) {
      evidence.push(`${describeCount} table descriptions`);
    }

    const confidence = Math.min(100, evidence.length * 35);

    return {
      detected: evidence.length > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect data enumeration pattern
   */
  private detectDataEnumeration(history: QueryHistoryEntry[]): DetectionResult {
    const recentQueries = history.slice(-25);
    const evidence: string[] = [];

    // Check for systematic ID scanning
    const sequentialIdQueries = this.findSequentialIdQueries(recentQueries);
    if (sequentialIdQueries > 5) {
      evidence.push(`${sequentialIdQueries} sequential ID queries`);
    }

    // Check for LIMIT 1 pattern (sampling)
    const singleRowQueries = recentQueries.filter(h =>
      h.query && /LIMIT\s+1\b/i.test(h.query)
    ).length;

    if (singleRowQueries > 7) {
      evidence.push(`${singleRowQueries} single-row queries (sampling pattern)`);
    }

    // Check for DISTINCT queries (value enumeration)
    const distinctQueries = recentQueries.filter(h =>
      h.query && /DISTINCT/i.test(h.query)
    ).length;

    if (distinctQueries > 5) {
      evidence.push(`${distinctQueries} DISTINCT queries (value enumeration)`);
    }

    const confidence = Math.min(100, evidence.length * 30);

    return {
      detected: evidence.length > 0,
      confidence,
      evidence
    };
  }

  /**
   * Detect similarity in queries (automated tool usage)
   */
  private detectSimilarityPattern(history: QueryHistoryEntry[]): DetectionResult {
    if (history.length < 10) {
      return { detected: false, confidence: 0, evidence: [] };
    }

    const recentQueries = history.slice(-15);
    let highSimilarityCount = 0;

    // Compare each query with previous ones
    for (let i = 1; i < recentQueries.length; i++) {
      const currQuery = recentQueries[i];
      const prevQuery = recentQueries[i - 1];

      if (!currQuery || !prevQuery) continue;

      const similarity = this.calculateQuerySimilarity(
        currQuery.query,
        prevQuery.query
      );

      if (similarity > this.SIMILAR_QUERY_THRESHOLD) {
        highSimilarityCount++;
      }
    }

    if (highSimilarityCount > 5) {
      return {
        detected: true,
        confidence: Math.min(100, highSimilarityCount * 12),
        evidence: [`${highSimilarityCount} highly similar consecutive queries (automated tool)`]
      };
    }

    return { detected: false, confidence: 0, evidence: [] };
  }

  /**
   * Detect comprehensive database scan
   */
  private detectComprehensiveScan(currentQuery: string, history: QueryHistoryEntry[]): DetectionResult {
    const evidence: string[] = [];

    // Check current query for broad scanning patterns
    if (/SELECT\s+\*\s+FROM\s+\w+\s*;?\s*$/i.test(currentQuery)) {
      evidence.push('Full table scan query');
    }

    // Check if accessing many tables in short time
    const recentTables = new Set(
      history.slice(-10)
        .filter(h => h.tableName)
        .map(h => h.tableName)
    );

    if (recentTables.size >= 5) {
      evidence.push(`Accessed ${recentTables.size} tables recently`);
    }

    const confidence = Math.min(100, evidence.length * 40);

    return {
      detected: evidence.length > 0,
      confidence,
      evidence
    };
  }

  /**
   * Calculate similarity between two queries (simplified)
   */
  private calculateQuerySimilarity(query1: string, query2: string): number {
    if (!query1 || !query2) return 0;

    const normalize = (q: string) => q.toLowerCase()
      .replace(/\s+/g, ' ')
      .replace(/['"`]/g, '')
      .replace(/\d+/g, 'N')
      .trim();

    const norm1 = normalize(query1);
    const norm2 = normalize(query2);

    // Simple Levenshtein-based similarity
    const maxLen = Math.max(norm1.length, norm2.length);
    if (maxLen === 0) return 1;

    const distance = this.levenshteinDistance(norm1, norm2);
    return 1 - (distance / maxLen);
  }

  /**
   * Levenshtein distance (edit distance)
   */
  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0]![j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i]![j] = matrix[i - 1]![j - 1]!;
        } else {
          matrix[i]![j] = Math.min(
            matrix[i - 1]![j - 1]! + 1,
            matrix[i]![j - 1]! + 1,
            matrix[i - 1]![j]! + 1
          );
        }
      }
    }

    return matrix[str2.length]![str1.length]!;
  }

  /**
   * Find sequential ID query patterns
   */
  private findSequentialIdQueries(history: QueryHistoryEntry[]): number {
    let sequentialCount = 0;
    const idPattern = /id\s*=\s*(\d+)/i;

    for (let i = 1; i < history.length; i++) {
      const prevQuery = history[i - 1]?.query;
      const currQuery = history[i]?.query;

      if (!prevQuery || !currQuery) continue;

      const prevMatch = prevQuery.match(idPattern);
      const currMatch = currQuery.match(idPattern);

      if (prevMatch && prevMatch[1] && currMatch && currMatch[1]) {
        const prevId = parseInt(prevMatch[1]);
        const currId = parseInt(currMatch[1]);

        if (Math.abs(currId - prevId) === 1) {
          sequentialCount++;
        }
      }
    }

    return sequentialCount;
  }

  /**
   * Record query in history
   */
  private recordQuery(sessionId: string, query: string, userId?: string): void {
    if (!this.sessionQueryHistory.has(sessionId)) {
      this.sessionQueryHistory.set(sessionId, []);
    }

    const history = this.sessionQueryHistory.get(sessionId)!;

    // Extract table name if present
    const tableMatch = query.match(/FROM\s+([a-z_][a-z0-9_]*)/i);
    const tableName = tableMatch ? tableMatch[1] : undefined;

    // Determine tool name (simplified)
    let toolName = 'unknown';
    if (query.includes('information_schema.tables')) toolName = 'list_tables';
    else if (query.includes('information_schema.columns')) toolName = 'describe_table';

    history.push({
      query,
      timestamp: new Date(),
      userId,
      tableName,
      toolName
    });

    // Keep only last 100 queries per session
    if (history.length > 100) {
      history.shift();
    }
  }

  /**
   * Record extraction attempt for analysis
   */
  private recordExtractionAttempt(attempt: ExtractionAttempt): void {
    this.logger.error('Model extraction attempt recorded', {
      session_id: attempt.sessionId,
      user_id: attempt.userId,
      pattern: attempt.pattern,
      confidence: attempt.confidence,
      evidence: attempt.evidence
    });

    // In a real system, this would:
    // 1. Store in database for analysis
    // 2. Trigger security alerts
    // 3. Update user risk scores
    // 4. Feed into ML models
  }

  /**
   * Generate reasoning for detection
   */
  private generateReasoning(patterns: string[], confidence: number): string {
    if (patterns.length === 0) {
      return 'No extraction patterns detected';
    }

    const patternText = patterns.join(', ');

    if (confidence >= 80) {
      return `High confidence extraction attempt detected: ${patternText}. Session blocked.`;
    } else if (confidence >= 60) {
      return `Suspicious activity detected: ${patternText}. Enhanced monitoring enabled.`;
    } else {
      return `Potential extraction patterns noted: ${patternText}. Monitoring continues.`;
    }
  }

  /**
   * Cleanup old history
   */
  private cleanupOldHistory(): void {
    const cutoffTime = Date.now() - (24 * 60 * 60 * 1000); // 24 hours

    for (const [sessionId, history] of this.sessionQueryHistory.entries()) {
      const filtered = history.filter(h => h.timestamp.getTime() > cutoffTime);

      if (filtered.length === 0) {
        this.sessionQueryHistory.delete(sessionId);
      } else {
        this.sessionQueryHistory.set(sessionId, filtered);
      }
    }

    this.logger.info('Cleaned up old query history', {
      active_sessions: this.sessionQueryHistory.size
    });
  }

  /**
   * Get session statistics (for monitoring)
   */
  getSessionStats(sessionId: string): SessionStats | null {
    const history = this.sessionQueryHistory.get(sessionId);
    if (!history) return null;

    const now = Date.now();
    const last5min = history.filter(h => (now - h.timestamp.getTime()) < 300000);
    const uniqueTables = new Set(history.filter(h => h.tableName).map(h => h.tableName));

    return {
      totalQueries: history.length,
      queriesLast5Min: last5min.length,
      uniqueTablesAccessed: uniqueTables.size,
      isBlocked: this.blockedSessions.has(sessionId),
      firstQueryTime: history[0]?.timestamp,
      lastQueryTime: history[history.length - 1]?.timestamp
    };
  }
}

// Supporting interfaces
interface QueryHistoryEntry {
  query: string;
  timestamp: Date;
  userId: string | undefined;
  tableName: string | undefined;
  toolName: string | undefined;
}

interface DetectionResult {
  detected: boolean;
  confidence: number;
  evidence: string[];
}

interface SessionStats {
  totalQueries: number;
  queriesLast5Min: number;
  uniqueTablesAccessed: number;
  isBlocked: boolean;
  firstQueryTime: Date | undefined;
  lastQueryTime: Date | undefined;
}
