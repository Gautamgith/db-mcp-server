/**
 * Excessive Agency Control (OWASP LLM08)
 *
 * Implements controls to prevent autonomous actions without proper oversight:
 * - Action approval workflows
 * - Risk assessment for operations
 * - Human-in-the-loop for high-risk operations
 * - Audit trail for all decisions
 */

import { Logger } from '../logging/logger.js';

export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum ApprovalStatus {
  APPROVED = 'approved',
  REJECTED = 'rejected',
  PENDING = 'pending',
  AUTO_APPROVED = 'auto_approved'
}

export interface ActionRequest {
  toolName: string;
  parameters: any;
  userId: string | undefined;
  sessionId: string | undefined;
  timestamp: Date;
}

export interface RiskAssessment {
  level: RiskLevel;
  score: number;
  factors: string[];
  requiresApproval: boolean;
  requiresHumanReview: boolean;
  reasoning: string;
}

export interface ApprovalDecision {
  status: ApprovalStatus;
  assessedRisk: RiskAssessment;
  approver?: string;
  timestamp: Date;
  reason?: string;
}

export class AgencyControlSystem {
  private logger: Logger;
  private pendingApprovals: Map<string, ActionRequest>;

  // Configuration
  private readonly AUTO_APPROVE_THRESHOLD = RiskLevel.LOW;
  private readonly REQUIRE_REVIEW_THRESHOLD = RiskLevel.HIGH;

  constructor(logger: Logger) {
    this.logger = logger;
    this.pendingApprovals = new Map();
  }

  /**
   * Assess the risk level of a proposed action
   */
  assessActionRisk(action: ActionRequest): RiskAssessment {
    const factors: string[] = [];
    let riskScore = 0;

    // Factor 1: Tool type risk (0-30 points)
    const toolRisk = this.assessToolRisk(action.toolName);
    riskScore += toolRisk.score;
    if (toolRisk.score > 0) {
      factors.push(toolRisk.reason);
    }

    // Factor 2: Query complexity risk (0-20 points)
    if (action.parameters.query) {
      const complexityRisk = this.assessQueryComplexity(action.parameters.query);
      riskScore += complexityRisk.score;
      if (complexityRisk.score > 0) {
        factors.push(complexityRisk.reason);
      }
    }

    // Factor 3: Data scope risk (0-25 points)
    const scopeRisk = this.assessDataScope(action.parameters);
    riskScore += scopeRisk.score;
    if (scopeRisk.score > 0) {
      factors.push(scopeRisk.reason);
    }

    // Factor 4: Pattern-based risk (0-15 points)
    const patternRisk = this.assessPatternRisk(action.parameters);
    riskScore += patternRisk.score;
    if (patternRisk.score > 0) {
      factors.push(patternRisk.reason);
    }

    // Factor 5: Historical behavior (0-10 points)
    const historyRisk = this.assessHistoricalRisk(action.userId, action.sessionId);
    riskScore += historyRisk.score;
    if (historyRisk.score > 0) {
      factors.push(historyRisk.reason);
    }

    // Determine risk level based on score
    let level: RiskLevel;
    if (riskScore < 20) {
      level = RiskLevel.LOW;
    } else if (riskScore < 40) {
      level = RiskLevel.MEDIUM;
    } else if (riskScore < 70) {
      level = RiskLevel.HIGH;
    } else {
      level = RiskLevel.CRITICAL;
    }

    const requiresApproval = riskScore >= 40; // HIGH or CRITICAL
    const requiresHumanReview = riskScore >= 70; // CRITICAL only

    return {
      level,
      score: riskScore,
      factors,
      requiresApproval,
      requiresHumanReview,
      reasoning: this.generateRiskReasoning(level, factors)
    };
  }

  /**
   * Check if an action should be allowed to proceed
   */
  async checkActionAuthorization(action: ActionRequest): Promise<ApprovalDecision> {
    const assessment = this.assessActionRisk(action);

    this.logger.info('Action risk assessed', {
      tool: action.toolName,
      risk_level: assessment.level,
      risk_score: assessment.score,
      requires_approval: assessment.requiresApproval
    });

    // Auto-approve low-risk actions
    if (assessment.level === RiskLevel.LOW) {
      return {
        status: ApprovalStatus.AUTO_APPROVED,
        assessedRisk: assessment,
        timestamp: new Date(),
        reason: 'Low risk action auto-approved'
      };
    }

    // Medium-risk: log and proceed with monitoring
    if (assessment.level === RiskLevel.MEDIUM) {
      this.logger.warn('Medium risk action proceeding with monitoring', {
        tool: action.toolName,
        factors: assessment.factors
      });

      return {
        status: ApprovalStatus.AUTO_APPROVED,
        assessedRisk: assessment,
        timestamp: new Date(),
        reason: 'Medium risk action approved with enhanced monitoring'
      };
    }

    // High/Critical risk: require manual approval
    if (assessment.requiresApproval) {
      const approvalId = this.generateApprovalId(action);
      this.pendingApprovals.set(approvalId, action);

      this.logger.error('High/Critical risk action requires approval', {
        approval_id: approvalId,
        tool: action.toolName,
        risk_level: assessment.level,
        risk_score: assessment.score,
        factors: assessment.factors
      });

      // In a real system, this would notify administrators
      // For now, we reject high-risk actions
      return {
        status: ApprovalStatus.REJECTED,
        assessedRisk: assessment,
        timestamp: new Date(),
        reason: `Action rejected due to ${assessment.level} risk level. Manual approval required.`
      };
    }

    return {
      status: ApprovalStatus.APPROVED,
      assessedRisk: assessment,
      timestamp: new Date()
    };
  }

  /**
   * Assess risk based on tool type
   */
  private assessToolRisk(toolName: string): { score: number; reason: string } {
    // Introspection tools are low risk
    if (toolName === 'list_tables' || toolName === 'describe_table') {
      return { score: 5, reason: 'Database introspection tool' };
    }

    // Pattern-based queries are medium-low risk
    if (toolName === 'structured_query' || toolName === 'query_patterns') {
      return { score: 10, reason: 'Structured query with pre-defined patterns' };
    }

    // Free-form queries are higher risk
    if (toolName === 'execute_query') {
      return { score: 20, reason: 'Free-form query execution' };
    }

    // Analysis tools are low risk (read-only)
    if (toolName.includes('analyze') || toolName.includes('validate')) {
      return { score: 5, reason: 'Analysis tool (no data modification)' };
    }

    return { score: 15, reason: 'Standard tool execution' };
  }

  /**
   * Assess risk based on query complexity
   */
  private assessQueryComplexity(query: string): { score: number; reason: string } {
    if (!query) return { score: 0, reason: '' };

    let score = 0;
    const reasons: string[] = [];

    // Check for multiple JOINs
    const joinCount = (query.match(/\bJOIN\b/gi) || []).length;
    if (joinCount > 3) {
      score += 10;
      reasons.push(`${joinCount} JOIN operations`);
    } else if (joinCount > 0) {
      score += 5;
      reasons.push(`${joinCount} JOIN operation(s)`);
    }

    // Check for subqueries
    const subqueryCount = (query.match(/\bSELECT\b/gi) || []).length - 1;
    if (subqueryCount > 2) {
      score += 10;
      reasons.push(`${subqueryCount} subqueries`);
    } else if (subqueryCount > 0) {
      score += 5;
      reasons.push(`${subqueryCount} subquery(ies)`);
    }

    // Check for window functions (high complexity)
    if (/OVER\s*\(/i.test(query)) {
      score += 8;
      reasons.push('Window functions detected');
    }

    // Check for CTEs
    const cteCount = (query.match(/\bWITH\b/gi) || []).length;
    if (cteCount > 0) {
      score += 5;
      reasons.push(`${cteCount} CTE(s)`);
    }

    return { score, reason: reasons.join(', ') || '' };
  }

  /**
   * Assess risk based on data scope
   */
  private assessDataScope(parameters: any): { score: number; reason: string } {
    let score = 0;
    const reasons: string[] = [];

    // Check for SELECT *
    if (parameters.query && /SELECT\s+\*/i.test(parameters.query)) {
      score += 10;
      reasons.push('SELECT * (all columns)');
    }

    // Check for no WHERE clause (full table scan)
    if (parameters.query &&
        /SELECT/i.test(parameters.query) &&
        !/WHERE/i.test(parameters.query) &&
        !/LIMIT/i.test(parameters.query)) {
      score += 15;
      reasons.push('No WHERE clause (full table scan)');
    }

    // Check for large limit values
    const limit = parameters.limit || 100;
    if (limit > 500) {
      score += 10;
      reasons.push(`Large result limit (${limit} rows)`);
    } else if (limit > 200) {
      score += 5;
      reasons.push(`Medium result limit (${limit} rows)`);
    }

    // Check for multiple table access
    if (parameters.query) {
      const fromMatches = parameters.query.match(/FROM\s+([a-z_][a-z0-9_]*)/gi);
      if (fromMatches && fromMatches.length > 3) {
        score += 10;
        reasons.push(`Multiple tables accessed (${fromMatches.length})`);
      }
    }

    return { score, reason: reasons.join(', ') || '' };
  }

  /**
   * Assess risk based on query patterns
   */
  private assessPatternRisk(parameters: any): { score: number; reason: string } {
    if (!parameters.query) return { score: 0, reason: '' };

    let score = 0;
    const reasons: string[] = [];

    const query = parameters.query.toLowerCase();

    // Check for sensitive column names
    const sensitiveColumns = ['password', 'ssn', 'credit_card', 'api_key', 'secret', 'token'];
    for (const col of sensitiveColumns) {
      if (query.includes(col)) {
        score += 15;
        reasons.push(`Potential sensitive column: ${col}`);
        break; // Only count once
      }
    }

    // Check for system tables
    if (query.includes('pg_') || query.includes('information_schema')) {
      score += 10;
      reasons.push('System table access');
    }

    // Check for UNION (potential for injection)
    if (query.includes('union')) {
      score += 10;
      reasons.push('UNION operation detected');
    }

    return { score, reason: reasons.join(', ') || '' };
  }

  /**
   * Assess risk based on historical behavior
   */
  private assessHistoricalRisk(userId?: string, sessionId?: string): { score: number; reason: string } {
    // In a real system, this would check:
    // - Previous failed attempts
    // - Unusual query patterns
    // - Time-of-day anomalies
    // - Geographic anomalies

    // For now, return baseline
    return { score: 0, reason: '' };
  }

  /**
   * Generate human-readable risk reasoning
   */
  private generateRiskReasoning(level: RiskLevel, factors: string[]): string {
    const factorText = factors.length > 0
      ? `Risk factors: ${factors.join('; ')}`
      : 'No significant risk factors detected';

    switch (level) {
      case RiskLevel.LOW:
        return `Low risk operation. ${factorText}`;
      case RiskLevel.MEDIUM:
        return `Medium risk operation requiring monitoring. ${factorText}`;
      case RiskLevel.HIGH:
        return `High risk operation requiring approval. ${factorText}`;
      case RiskLevel.CRITICAL:
        return `Critical risk operation requiring immediate review. ${factorText}`;
    }
  }

  /**
   * Generate unique approval ID
   */
  private generateApprovalId(action: ActionRequest): string {
    return `approval_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get pending approvals (for admin dashboard)
   */
  getPendingApprovals(): Map<string, ActionRequest> {
    return new Map(this.pendingApprovals);
  }

  /**
   * Manually approve an action (would be called by admin)
   */
  approveAction(approvalId: string, approver: string): boolean {
    if (this.pendingApprovals.has(approvalId)) {
      this.pendingApprovals.delete(approvalId);
      this.logger.info('Action manually approved', {
        approval_id: approvalId,
        approver
      });
      return true;
    }
    return false;
  }

  /**
   * Manually reject an action
   */
  rejectAction(approvalId: string, approver: string, reason: string): boolean {
    if (this.pendingApprovals.has(approvalId)) {
      this.pendingApprovals.delete(approvalId);
      this.logger.info('Action manually rejected', {
        approval_id: approvalId,
        approver,
        reason
      });
      return true;
    }
    return false;
  }
}
