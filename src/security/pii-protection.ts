/**
 * PII Protection System (OWASP LLM02 & LLM06)
 *
 * Implements detection and masking of Personally Identifiable Information:
 * - Email addresses
 * - Phone numbers
 * - SSN / Tax IDs
 * - Credit card numbers
 * - IP addresses
 * - Postal addresses
 * - Names (when configured)
 */

import { Logger } from '../logging/logger.js';

export interface PIIPattern {
  name: string;
  pattern: RegExp;
  replacement: string | ((match: string) => string);
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface PIIDetectionResult {
  found: boolean;
  types: string[];
  count: number;
  locations: PIILocation[];
}

export interface PIILocation {
  type: string;
  value: string; // Partially masked for logging
  column: string | undefined;
  row: number | undefined;
}

export interface MaskedOutput {
  data: any;
  piiDetected: boolean;
  maskedCount: number;
  types: string[];
}

export class PIIProtectionSystem {
  private logger: Logger;
  private patterns: PIIPattern[];
  private enabled: boolean;

  constructor(logger: Logger) {
    this.logger = logger;
    this.enabled = true;
    this.patterns = this.initializePatterns();
  }

  /**
   * Initialize PII detection patterns
   */
  private initializePatterns(): PIIPattern[] {
    return [
      // Email addresses
      {
        name: 'email',
        pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        replacement: (match) => this.maskEmail(match),
        severity: 'medium'
      },

      // US Social Security Numbers
      {
        name: 'ssn',
        pattern: /\b\d{3}-?\d{2}-?\d{4}\b/g,
        replacement: '***-**-****',
        severity: 'critical'
      },

      // Credit Card Numbers (basic pattern)
      {
        name: 'credit_card',
        pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
        replacement: '****-****-****-****',
        severity: 'critical'
      },

      // US Phone Numbers
      {
        name: 'phone_us',
        pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
        replacement: '***-***-****',
        severity: 'medium'
      },

      // IPv4 Addresses
      {
        name: 'ipv4',
        pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
        replacement: '***.***.***.***',
        severity: 'low'
      },

      // IPv6 Addresses
      {
        name: 'ipv6',
        pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
        replacement: '****:****:****:****:****:****:****:****',
        severity: 'low'
      },

      // API Keys / Tokens (generic pattern)
      {
        name: 'api_key',
        pattern: /\b[A-Za-z0-9_-]{32,}\b/g,
        replacement: (match) => '*'.repeat(Math.min(match.length, 40)),
        severity: 'critical'
      },

      // AWS Access Keys
      {
        name: 'aws_key',
        pattern: /\b(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
        replacement: 'AKIA****************',
        severity: 'critical'
      },

      // Generic Secrets/Passwords in JSON/URLs
      {
        name: 'password_field',
        pattern: /(password|passwd|pwd|secret|token|apikey)["']?\s*[:=]\s*["']([^"']+)["']/gi,
        replacement: (match) => {
          return match.replace(/["']([^"']+)["']$/, '"********"');
        },
        severity: 'critical'
      },

      // JWT Tokens
      {
        name: 'jwt_token',
        pattern: /\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b/g,
        replacement: 'eyJ****.****.****',
        severity: 'critical'
      },

      // US Postal Code
      {
        name: 'postal_code_us',
        pattern: /\b\d{5}(?:-\d{4})?\b/g,
        replacement: '*****',
        severity: 'low'
      },

      // Date of Birth patterns
      {
        name: 'date_of_birth',
        pattern: /\b(0?[1-9]|1[0-2])[/-](0?[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b/g,
        replacement: '**/**/****',
        severity: 'high'
      }
    ];
  }

  /**
   * Detect and mask PII in output data
   */
  maskPII(data: any): MaskedOutput {
    if (!this.enabled) {
      return {
        data,
        piiDetected: false,
        maskedCount: 0,
        types: []
      };
    }

    const detection = this.detectPII(data);

    if (!detection.found) {
      return {
        data,
        piiDetected: false,
        maskedCount: 0,
        types: []
      };
    }

    // Log PII detection
    this.logger.warn('PII detected in output, applying masking', {
      types: detection.types,
      count: detection.count,
      locations: detection.locations.map(l => ({
        type: l.type,
        column: l.column,
        row: l.row
      }))
    });

    // Apply masking
    const maskedData = this.applyMasking(data);

    return {
      data: maskedData,
      piiDetected: true,
      maskedCount: detection.count,
      types: detection.types
    };
  }

  /**
   * Detect PII in data structure
   */
  private detectPII(data: any): PIIDetectionResult {
    const locations: PIILocation[] = [];
    const typesFound = new Set<string>();

    this.detectPIIRecursive(data, locations, typesFound);

    return {
      found: locations.length > 0,
      types: Array.from(typesFound),
      count: locations.length,
      locations
    };
  }

  /**
   * Recursively detect PII in nested structures
   */
  private detectPIIRecursive(
    data: any,
    locations: PIILocation[],
    typesFound: Set<string>,
    column?: string,
    row?: number
  ): void {
    if (data === null || data === undefined) {
      return;
    }

    if (typeof data === 'string') {
      // Check string against all patterns
      for (const pattern of this.patterns) {
        const matches = data.match(pattern.pattern);
        if (matches) {
          for (const match of matches) {
            typesFound.add(pattern.name);
            locations.push({
              type: pattern.name,
              value: this.partiallyMask(match),
              column,
              row
            });
          }
        }
      }
    } else if (Array.isArray(data)) {
      // Process array elements
      data.forEach((item, index) => {
        this.detectPIIRecursive(item, locations, typesFound, column, index);
      });
    } else if (typeof data === 'object') {
      // Process object properties
      for (const [key, value] of Object.entries(data)) {
        this.detectPIIRecursive(value, locations, typesFound, key, row);
      }
    }
  }

  /**
   * Apply masking to data structure
   */
  private applyMasking(data: any): any {
    if (data === null || data === undefined) {
      return data;
    }

    if (typeof data === 'string') {
      return this.maskString(data);
    } else if (Array.isArray(data)) {
      return data.map(item => this.applyMasking(item));
    } else if (typeof data === 'object') {
      const masked: any = {};
      for (const [key, value] of Object.entries(data)) {
        masked[key] = this.applyMasking(value);
      }
      return masked;
    }

    return data;
  }

  /**
   * Mask PII in a string
   */
  private maskString(str: string): string {
    let masked = str;

    for (const pattern of this.patterns) {
      if (typeof pattern.replacement === 'function') {
        masked = masked.replace(pattern.pattern, pattern.replacement);
      } else {
        masked = masked.replace(pattern.pattern, pattern.replacement);
      }
    }

    return masked;
  }

  /**
   * Mask email address (show first char and domain)
   */
  private maskEmail(email: string): string {
    const parts = email.split('@');
    if (parts.length !== 2) return '***@***.***';

    const username = parts[0];
    const domain = parts[1];

    if (!username || !domain) return '***@***.***';

    const maskedUsername = username.length > 0
      ? username[0] + '*'.repeat(Math.min(username.length - 1, 5))
      : '***';

    const domainParts = domain.split('.');
    if (domainParts.length < 2) return `${maskedUsername}@***.***`;

    const maskedDomain = domainParts
      .map((part, index) => {
        if (index === domainParts.length - 1) {
          // Keep TLD
          return part;
        } else if (index === 0) {
          // Mask domain name
          return part[0] + '*'.repeat(Math.min(part.length - 1, 3));
        } else {
          return part;
        }
      })
      .join('.');

    return `${maskedUsername}@${maskedDomain}`;
  }

  /**
   * Partially mask value for logging (show pattern, hide data)
   */
  private partiallyMask(value: string): string {
    if (value.length <= 4) {
      return '***';
    }

    return value.substring(0, 2) + '***' + value.substring(value.length - 2);
  }

  /**
   * Check if a string contains PII
   */
  containsPII(str: string): boolean {
    return this.patterns.some(pattern => pattern.pattern.test(str));
  }

  /**
   * Get PII types found in string
   */
  getPIITypes(str: string): string[] {
    const types: string[] = [];

    for (const pattern of this.patterns) {
      if (pattern.pattern.test(str)) {
        types.push(pattern.name);
      }
    }

    return types;
  }

  /**
   * Enable/disable PII protection
   */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    this.logger.info('PII protection status changed', { enabled });
  }

  /**
   * Add custom PII pattern
   */
  addCustomPattern(pattern: PIIPattern): void {
    this.patterns.push(pattern);
    this.logger.info('Custom PII pattern added', {
      name: pattern.name,
      severity: pattern.severity
    });
  }

  /**
   * Get statistics about configured patterns
   */
  getPatternStats(): PatternStats {
    const bySeverity = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0
    };

    for (const pattern of this.patterns) {
      bySeverity[pattern.severity]++;
    }

    return {
      totalPatterns: this.patterns.length,
      bySeverity,
      enabled: this.enabled
    };
  }
}

interface PatternStats {
  totalPatterns: number;
  bySeverity: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  enabled: boolean;
}
