/**
 * OAuth 2.0 Middleware for EntraID Authentication
 *
 * Validates JWT tokens from Microsoft EntraID (Azure AD)
 * Implements comprehensive security checks including signature verification,
 * issuer validation, audience validation, and expiration checks
 */

import jwt, { JwtPayload } from 'jsonwebtoken';
import jwksClient, { JwksClient } from 'jwks-rsa';
import { OAuthConfig } from '../config/oauth-config.js';
import { Logger } from '../logging/logger.js';

/**
 * Custom error class for authentication errors
 */
export class AuthError extends Error {
  constructor(message: string, public code: string = 'AUTH_ERROR') {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Token claims interface
 */
export interface TokenClaims extends JwtPayload {
  sub: string;           // Subject (user ID)
  iss: string;           // Issuer
  aud: string | string[]; // Audience
  exp: number;           // Expiration time
  nbf?: number;          // Not before
  iat?: number;          // Issued at
  azp?: string;          // Authorized party (client ID)
  appid?: string;        // Application ID (v1 tokens)
  scp?: string;          // Scopes (space-separated)
  roles?: string[];      // Roles
  email?: string;        // User email
  name?: string;         // User name
  ver?: string;          // Token version
}

/**
 * User information extracted from token
 */
export interface UserInfo {
  id: string;
  clientId: string;
  scopes: string[];
  email: string | undefined;
  name: string | undefined;
}

/**
 * OAuth middleware for token validation
 */
export class OAuthMiddleware {
  private jwksClient: JwksClient;
  private config: OAuthConfig;
  private logger: Logger;
  private keyCache: Map<string, string>;

  constructor(config: OAuthConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
    this.keyCache = new Map();

    // Initialize JWKS client with security settings
    this.jwksClient = jwksClient({
      jwksUri: config.jwksUri,
      cache: true,
      cacheMaxEntries: 5,
      cacheMaxAge: 86400000, // 24 hours
      rateLimit: true,
      jwksRequestsPerMinute: 10,
      timeout: 5000
    });
  }

  /**
   * Validate OAuth token from request
   */
  async validateToken(token: string): Promise<UserInfo> {
    try {
      // 1. Decode token without verification to get header
      const decoded = jwt.decode(token, { complete: true });
      if (!decoded || typeof decoded === 'string') {
        throw new AuthError('Invalid token format', 'INVALID_TOKEN_FORMAT');
      }

      // 2. Get signing key from JWKS
      const kid = decoded.header.kid;
      if (!kid) {
        throw new AuthError('Token missing key ID (kid)', 'MISSING_KEY_ID');
      }

      const publicKey = await this.getSigningKey(kid);

      // 3. Verify token signature and claims
      const claims = jwt.verify(token, publicKey, {
        algorithms: [this.config.tokenAlgorithm as jwt.Algorithm],
        issuer: this.config.issuer,
        audience: this.config.audience,
        clockTolerance: this.config.clockTolerance
      }) as TokenClaims;

      // 4. Additional validation
      this.validateClaims(claims);

      // 5. Extract user information
      const userInfo = this.extractUserInfo(claims);

      // 6. Log successful authentication
      this.logger.info('Token validation succeeded', {
        user_id: userInfo.id,
        client_id: userInfo.clientId,
        scopes: userInfo.scopes,
        token_exp: claims.exp
      });

      return userInfo;

    } catch (error) {
      this.handleValidationError(error);
      throw error; // TypeScript needs this
    }
  }

  /**
   * Get signing key from JWKS endpoint
   */
  private async getSigningKey(kid: string): Promise<string> {
    // Check cache first
    if (this.keyCache.has(kid)) {
      return this.keyCache.get(kid)!;
    }

    try {
      const key = await this.jwksClient.getSigningKey(kid);
      const publicKey = key.getPublicKey();

      // Cache the key
      this.keyCache.set(kid, publicKey);

      return publicKey;
    } catch (error) {
      this.logger.error('Failed to fetch signing key', {
        kid,
        error: error instanceof Error ? error.message : String(error)
      });
      throw new AuthError('Failed to fetch signing key', 'JWKS_ERROR');
    }
  }

  /**
   * Validate token claims
   */
  private validateClaims(claims: TokenClaims): void {
    // Check required claims exist
    if (!claims.sub) {
      throw new AuthError('Missing subject claim', 'MISSING_SUBJECT');
    }

    if (!claims.exp) {
      throw new AuthError('Missing expiration claim', 'MISSING_EXPIRATION');
    }

    // Validate token version (prefer v2.0 tokens)
    if (claims.ver && claims.ver !== '2.0' && claims.ver !== '1.0') {
      throw new AuthError('Invalid token version', 'INVALID_TOKEN_VERSION');
    }

    // Validate scopes or roles exist
    const scopes = this.parseScopes(claims);
    if (scopes.length === 0) {
      this.logger.warn('Token has no scopes or roles', {
        user_id: claims.sub,
        client_id: claims.azp || claims.appid
      });
      // Don't fail - some use cases may not require scopes
    }
  }

  /**
   * Parse scopes from token claims
   */
  private parseScopes(claims: TokenClaims): string[] {
    const scopes: string[] = [];

    // Parse scp claim (space-separated scopes)
    if (claims.scp) {
      scopes.push(...claims.scp.split(' ').filter(s => s.length > 0));
    }

    // Parse roles claim (array)
    if (claims.roles && Array.isArray(claims.roles)) {
      scopes.push(...claims.roles);
    }

    return scopes;
  }

  /**
   * Extract user information from claims
   */
  private extractUserInfo(claims: TokenClaims): UserInfo {
    return {
      id: claims.sub,
      clientId: claims.azp || claims.appid || 'unknown',
      scopes: this.parseScopes(claims),
      email: claims.email,
      name: claims.name
    };
  }

  /**
   * Handle validation errors
   */
  private handleValidationError(error: any): never {
    if (error instanceof jwt.TokenExpiredError) {
      this.logger.warn('Token expired', {
        expired_at: error.expiredAt
      });
      throw new AuthError('Access token has expired', 'TOKEN_EXPIRED');
    }

    if (error instanceof jwt.JsonWebTokenError) {
      this.logger.warn('Invalid token', {
        error: error.message
      });
      throw new AuthError('Invalid access token', 'INVALID_TOKEN');
    }

    if (error instanceof AuthError) {
      this.logger.warn('Authentication failed', {
        error: error.message,
        code: error.code
      });
      throw error;
    }

    // Unknown error
    this.logger.error('Unexpected authentication error', {
      error: error instanceof Error ? error.message : String(error)
    });
    throw new AuthError('Authentication failed', 'UNKNOWN_ERROR');
  }
}

/**
 * Authorization middleware for scope-based access control
 */
export class AuthorizationMiddleware {
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
  }

  /**
   * Check if user has required scope
   */
  hasScope(userInfo: UserInfo, requiredScopes: string | string[]): boolean {
    const scopes = Array.isArray(requiredScopes) ? requiredScopes : [requiredScopes];

    const hasRequiredScope = scopes.some(scope =>
      userInfo.scopes.includes(scope)
    );

    if (!hasRequiredScope) {
      this.logger.warn('Insufficient permissions', {
        user_id: userInfo.id,
        required_scopes: scopes,
        actual_scopes: userInfo.scopes
      });
    }

    return hasRequiredScope;
  }

  /**
   * Check if user has all required scopes
   */
  hasAllScopes(userInfo: UserInfo, requiredScopes: string[]): boolean {
    const hasAll = requiredScopes.every(scope =>
      userInfo.scopes.includes(scope)
    );

    if (!hasAll) {
      this.logger.warn('Missing required scopes', {
        user_id: userInfo.id,
        required_scopes: requiredScopes,
        actual_scopes: userInfo.scopes,
        missing_scopes: requiredScopes.filter(s => !userInfo.scopes.includes(s))
      });
    }

    return hasAll;
  }

  /**
   * Get authorization error for MCP
   */
  createAuthorizationError(requiredScopes: string[]): Error {
    const error = new Error('Insufficient permissions for this operation');
    (error as any).code = -32403;
    (error as any).data = {
      error_type: 'INSUFFICIENT_PERMISSIONS',
      required_scopes: requiredScopes,
      hint: 'Request access to the required scopes from your administrator'
    };
    return error;
  }
}
