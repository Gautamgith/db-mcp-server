# Security Review: OAuth 2.0 Implementation with EntraID

**Document Version**: 1.0
**Date**: 2025-10-24
**Status**: Review
**Prepared for**: PostgreSQL MCP Server OAuth Authentication

---

## Executive Summary

This document reviews the security implications of implementing OAuth 2.0 authentication with Microsoft EntraID (Azure AD) for the PostgreSQL MCP Server. The implementation adds network-based authentication to the existing multi-layer security architecture.

### Security Objectives
- **Authentication**: Verify AI client identity via OAuth 2.0 tokens
- **Authorization**: Control access based on token claims and scopes
- **Confidentiality**: Protect data in transit with TLS
- **Integrity**: Prevent token tampering and replay attacks
- **Auditability**: Log all authentication and authorization events

---

## 1. Current Security Model

### 1.1 Transport Security

**Current State**: Stdio Transport
- **Authentication**: None (OS-level process trust)
- **Encryption**: None (local process pipes)
- **Attack Surface**: Local machine only
- **Trust Model**: Implicit - client spawns server process

**Threat Model**:
- ✅ **Protected**: Network-based attacks (no network exposure)
- ❌ **Vulnerable**: Local privilege escalation, process injection
- ⚠️ **Limited**: No authentication, authorization, or audit trail for transport layer

### 1.2 Database Security (Unchanged)

**Current Implementation**: Multi-layer security already in place
- **IAM Authentication**: AWS RDS IAM authentication for database connections
- **SQL Injection Prevention**: Query validation, parameterization, allowlisting
- **Rate Limiting**: Per-client request throttling (100 req/min default)
- **Query Complexity Analysis**: Prevents expensive queries (score < 20)
- **PII Protection**: 12 pattern types, automatic masking
- **Agency Control**: 5-factor risk assessment (0-100 scale)
- **Model Theft Protection**: 6 detection methods for data extraction

**Security Strengths**:
- Comprehensive OWASP LLM Top 10 compliance
- Defense in depth across multiple layers
- Extensive audit logging

### 1.3 Current Vulnerabilities

**With Stdio Transport**:
1. **No Network Security**: Not designed for network exposure
2. **No Authentication**: Any process on the same machine can connect
3. **No Authorization**: Binary access (all or nothing)
4. **No Audit Trail**: Cannot track which client made which request
5. **Limited Scalability**: Single client per server instance

---

## 2. Target Security Model

### 2.1 OAuth 2.0 Authentication Flow

**Implementation**: OpenID Connect (OIDC) with EntraID

```
┌─────────────────┐                                    ┌─────────────────┐
│   AI Client     │                                    │  EntraID        │
│                 │                                    │  (Azure AD)     │
└────────┬────────┘                                    └────────┬────────┘
         │                                                      │
         │ 1. Request Access Token                             │
         │    (client_credentials flow)                        │
         ├─────────────────────────────────────────────────────►│
         │                                                      │
         │ 2. Validate Client Credentials                      │
         │    - Client ID + Client Secret                      │
         │    - Scope: api://{app-id}/.default                 │
         │                                                      │
         │ 3. Return JWT Access Token                          │
         │◄─────────────────────────────────────────────────────┤
         │    { aud, iss, sub, exp, scope, ... }               │
         │                                                      │
         ▼                                                      │
┌─────────────────┐                                            │
│   AI Client     │                                            │
│  (With Token)   │                                            │
└────────┬────────┘                                            │
         │                                                      │
         │ 4. MCP Request + Bearer Token                       │
         │    Authorization: Bearer {jwt_token}                │
         ├─────────────────────────────────►┌─────────────────┐│
         │                                   │  MCP Server     ││
         │                                   │  (EC2)          ││
         │                                   └────────┬────────┘│
         │                                            │         │
         │                                   5. Validate Token  │
         │                                      - Fetch JWKS   │
         │                                      ├───────────────►
         │                                      │               │
         │                                      │ 6. Return     │
         │                                      │    Public Keys│
         │                                      ◄───────────────┤
         │                                      │               │
         │                                      - Verify        │
         │                                        Signature     │
         │                                      - Check aud,    │
         │                                        iss, exp      │
         │                                      - Validate      │
         │                                        scope         │
         │                                            │         │
         │ 7. MCP Response (if valid)                │         │
         │◄───────────────────────────────────────────┤         │
         │                                                      │
```

### 2.2 Token Validation Process

**Security Checks** (in order):

1. **Token Format Validation**
   - Valid JWT structure (header.payload.signature)
   - Base64URL encoded
   - Not empty or malformed

2. **Signature Verification**
   - Fetch public keys from JWKS endpoint
   - Verify token signed by EntraID private key
   - Prevent token forgery

3. **Issuer Validation**
   - `iss` claim matches `https://login.microsoftonline.com/{tenant-id}/v2.0`
   - Prevents tokens from other identity providers

4. **Audience Validation**
   - `aud` claim matches `api://{application-id}`
   - Prevents token reuse for other applications

5. **Expiration Check**
   - `exp` claim > current time
   - Prevents expired token usage
   - Default: 1 hour lifetime

6. **Not Before Check**
   - `nbf` claim <= current time
   - Prevents premature token usage

7. **Scope Validation**
   - `scp` or `roles` claim contains required scope
   - Example: `database.read`, `database.write`

**Implementation**:
```typescript
async validateToken(token: string): Promise<TokenClaims> {
  // 1. Decode without verification
  const decoded = jwt.decode(token, { complete: true });
  if (!decoded) throw new AuthError('Invalid token format');

  // 2. Get signing key from JWKS
  const kid = decoded.header.kid;
  const signingKey = await this.getSigningKey(kid);

  // 3. Verify signature and claims
  const claims = jwt.verify(token, signingKey, {
    algorithms: ['RS256'],
    issuer: this.config.issuer,
    audience: this.config.audience,
    clockTolerance: 60 // 60 second clock skew tolerance
  }) as TokenClaims;

  // 4. Validate required scopes
  if (!this.hasRequiredScope(claims)) {
    throw new AuthError('Insufficient permissions');
  }

  return claims;
}
```

### 2.3 Security Features

#### 2.3.1 Token Security

| Feature | Implementation | Security Benefit |
|---------|----------------|------------------|
| **Short-lived tokens** | 1 hour expiration | Limits token theft impact |
| **Signature verification** | RS256 algorithm | Prevents token forgery |
| **Audience validation** | Application-specific `aud` | Prevents token reuse |
| **HTTPS only** | TLS 1.2+ | Prevents token interception |
| **No token storage** | Stateless validation | Reduces attack surface |
| **JWKS caching** | 24 hour cache + refresh | Performance + security |

#### 2.3.2 Transport Security

| Feature | Implementation | Security Benefit |
|---------|----------------|------------------|
| **TLS 1.2+** | Load balancer termination | Encryption in transit |
| **Certificate validation** | AWS Certificate Manager | Prevents MITM attacks |
| **Private network** | AWS VPC | Network isolation |
| **Security groups** | Port 3000 allowlist | Firewall protection |

#### 2.3.3 Authorization Model

**Scope-Based Access Control**:

```typescript
// Define permission scopes
const SCOPES = {
  READ: 'database.read',      // SELECT queries only
  WRITE: 'database.write',    // INSERT, UPDATE, DELETE
  ADMIN: 'database.admin',    // Schema changes, DROP
  INTROSPECT: 'database.introspect'  // Schema inspection
};

// Tool-to-scope mapping
const TOOL_PERMISSIONS = {
  'execute_query': ['database.read', 'database.write'],
  'list_tables': ['database.introspect'],
  'get_table_schema': ['database.introspect'],
  'create_table': ['database.admin'],
  'drop_table': ['database.admin']
};
```

**Role-Based Access Control** (optional future enhancement):
- Map EntraID roles to database permissions
- Use `roles` claim from token
- Example: `DBA`, `Developer`, `Analyst`

---

## 3. Security Analysis

### 3.1 Threat Model

#### 3.1.1 Authentication Threats

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Token theft** | Medium | High | HTTPS only, short-lived tokens, token binding (future) |
| **Token replay** | Medium | High | Short expiration, optional nonce validation |
| **Token forgery** | Low | Critical | RS256 signature verification, JWKS validation |
| **Phishing attacks** | Low | Medium | EntraID MFA enforcement, client authentication |
| **Credential stuffing** | Low | Medium | EntraID brute force protection, account lockout |

#### 3.1.2 Authorization Threats

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Privilege escalation** | Medium | High | Scope validation, least privilege principle |
| **Scope manipulation** | Low | High | Server-side scope validation (not client-provided) |
| **Token scope confusion** | Low | Medium | Strict audience validation |
| **Unauthorized access** | Medium | High | Multi-layer authorization (OAuth + existing controls) |

#### 3.1.3 Network Threats

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **Man-in-the-Middle** | Low | Critical | TLS 1.2+, certificate validation |
| **Eavesdropping** | Low | Critical | End-to-end encryption (TLS) |
| **DoS attacks** | Medium | Medium | Rate limiting (existing), WAF (future), connection limits |
| **DDoS attacks** | Low | High | AWS Shield, CloudFront (future) |

#### 3.1.4 Application Threats

| Threat | Likelihood | Impact | Mitigation |
|--------|-----------|--------|------------|
| **SQL injection** | Low | Critical | Existing multi-layer prevention (parameterization, validation, allowlisting) |
| **Data exfiltration** | Medium | High | Existing model theft protection (6 detection methods) |
| **PII exposure** | Medium | High | Existing PII protection (12 patterns, auto-masking) |
| **Excessive agency** | Medium | Medium | Existing agency control (5-factor risk assessment) |

### 3.2 OWASP LLM Top 10 Compliance

#### Enhanced Protections with OAuth

| OWASP Risk | Current Protection | OAuth Enhancement |
|------------|-------------------|-------------------|
| **LLM01: Prompt Injection** | Input validation, parameterization | User identity tracking for audit |
| **LLM02: Insecure Output** | PII masking (12 patterns) | User-specific masking policies |
| **LLM03: Training Data Poisoning** | N/A (no training) | N/A |
| **LLM04: Model DoS** | Rate limiting, complexity analysis | Per-user rate limits |
| **LLM05: Supply Chain** | Dependency scanning | N/A |
| **LLM06: Sensitive Info Disclosure** | PII protection, query validation | User-level access control |
| **LLM07: Insecure Plugin Design** | Input validation, sandboxing | Scope-based tool access |
| **LLM08: Excessive Agency** | 5-factor risk assessment | User identity for approval workflows |
| **LLM09: Overreliance** | N/A (human decision) | N/A |
| **LLM10: Model Theft** | 6 detection methods | User tracking for pattern analysis |

**New Security Capabilities**:
- **User Attribution**: Every action tied to authenticated user
- **Granular Permissions**: Scope-based access control per tool
- **Audit Trail Enhancement**: User identity in all logs
- **Per-User Rate Limiting**: Replace session-based with user-based limits

### 3.3 Security Best Practices

#### 3.3.1 Token Management

✅ **DO**:
- Validate every token on every request
- Use short-lived tokens (1 hour max)
- Implement token expiration checks with clock skew tolerance
- Cache JWKS keys with TTL (24 hours)
- Log all token validation failures
- Use HTTPS only for token transmission
- Implement graceful handling of expired tokens

❌ **DON'T**:
- Store tokens server-side
- Accept tokens without signature verification
- Skip audience or issuer validation
- Use symmetric algorithms (HS256)
- Extend token expiration server-side
- Accept tokens over HTTP
- Trust client-provided claims without validation

#### 3.3.2 Error Handling

**Security-Safe Error Messages**:

```typescript
// ❌ BAD - Reveals internal details
throw new Error('Token signature verification failed using key kid=abc123');

// ✅ GOOD - Generic but actionable
throw new AuthError('Invalid or expired token', {
  code: 'INVALID_TOKEN',
  hint: 'Please obtain a new access token'
});
```

**Error Response Codes**:
- `401 Unauthorized`: Missing or invalid token
- `403 Forbidden`: Valid token, insufficient permissions
- `429 Too Many Requests`: Rate limit exceeded

#### 3.3.3 Logging and Monitoring

**Security Event Logging**:

```typescript
// Authentication events
logger.info('Token validation succeeded', {
  user_id: claims.sub,
  client_id: claims.azp,
  scopes: claims.scp,
  token_exp: claims.exp
});

logger.warn('Token validation failed', {
  error: 'expired_token',
  token_exp: claims.exp,
  current_time: Date.now(),
  client_ip: req.ip
});

// Authorization events
logger.warn('Insufficient permissions', {
  user_id: claims.sub,
  requested_tool: 'create_table',
  required_scope: 'database.admin',
  actual_scopes: claims.scp
});
```

**CloudWatch Alarms**:
- Authentication failure rate > 10/min
- 401/403 response rate > 5%
- Token validation latency > 100ms
- JWKS fetch failures

---

## 4. Implementation Security Requirements

### 4.1 EntraID Application Configuration

**Required Settings**:

1. **Application Type**: Web API
2. **Redirect URIs**: None (server-to-server)
3. **Implicit Flow**: Disabled
4. **ID Tokens**: Disabled
5. **Access Tokens**: Enabled
6. **Client Authentication**: Required (client secret or certificate)
7. **Token Version**: v2.0
8. **Supported Account Types**: Single tenant (recommended)

**Recommended Settings**:

1. **Multi-Factor Authentication**: Enforce for client registration
2. **Conditional Access**: Require managed devices
3. **Certificate-Based Authentication**: Use instead of client secret (more secure)
4. **Token Lifetime**: 1 hour (default)
5. **Refresh Token Rotation**: Enabled

### 4.2 OAuth Middleware Implementation

**Security Requirements**:

```typescript
export class OAuthMiddleware {
  private jwksClient: JwksClient;
  private config: OAuthConfig;
  private logger: Logger;

  constructor(config: OAuthConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;

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

  async authenticate(req: Request, res: Response, next: NextFunction) {
    try {
      // 1. Extract token from Authorization header
      const token = this.extractToken(req);
      if (!token) {
        throw new AuthError('Missing authorization token');
      }

      // 2. Validate token
      const claims = await this.validateToken(token);

      // 3. Attach claims to request
      req.user = {
        id: claims.sub,
        clientId: claims.azp || claims.appid,
        scopes: this.parseScopes(claims),
        email: claims.email,
        name: claims.name
      };

      // 4. Log successful authentication
      this.logger.info('Authentication successful', {
        user_id: req.user.id,
        client_id: req.user.clientId,
        scopes: req.user.scopes
      });

      next();
    } catch (error) {
      this.handleAuthError(error, req, res);
    }
  }

  private extractToken(req: Request): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader) return null;

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      throw new AuthError('Invalid authorization header format');
    }

    return parts[1];
  }

  private async validateToken(token: string): Promise<TokenClaims> {
    // Decode token header to get key ID
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded || !decoded.header.kid) {
      throw new AuthError('Invalid token format');
    }

    // Get public key from JWKS
    const key = await this.jwksClient.getSigningKey(decoded.header.kid);
    const publicKey = key.getPublicKey();

    // Verify token signature and claims
    const claims = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: this.config.issuer,
      audience: this.config.audience,
      clockTolerance: 60
    }) as TokenClaims;

    // Additional validation
    this.validateClaims(claims);

    return claims;
  }

  private validateClaims(claims: TokenClaims): void {
    // Check required claims exist
    if (!claims.sub) throw new AuthError('Missing subject claim');
    if (!claims.exp) throw new AuthError('Missing expiration claim');

    // Validate token version (v2.0 tokens only)
    if (claims.ver !== '2.0') {
      throw new AuthError('Invalid token version');
    }

    // Validate scopes (at least one required)
    const scopes = this.parseScopes(claims);
    if (scopes.length === 0) {
      throw new AuthError('No scopes granted');
    }
  }

  private handleAuthError(error: any, req: Request, res: Response): void {
    this.logger.warn('Authentication failed', {
      error: error.message,
      path: req.path,
      ip: req.ip
    });

    if (error instanceof jwt.TokenExpiredError) {
      res.status(401).json({
        error: 'token_expired',
        message: 'Access token has expired',
        hint: 'Please obtain a new access token'
      });
    } else if (error instanceof jwt.JsonWebTokenError) {
      res.status(401).json({
        error: 'invalid_token',
        message: 'Invalid access token'
      });
    } else if (error instanceof AuthError) {
      res.status(401).json({
        error: 'authentication_failed',
        message: error.message
      });
    } else {
      res.status(500).json({
        error: 'internal_error',
        message: 'An unexpected error occurred'
      });
    }
  }
}
```

### 4.3 Authorization Middleware

**Scope-Based Authorization**:

```typescript
export class AuthorizationMiddleware {
  constructor(private logger: Logger) {}

  requireScope(requiredScopes: string | string[]) {
    return (req: Request, res: Response, next: NextFunction) => {
      if (!req.user) {
        return res.status(401).json({
          error: 'unauthorized',
          message: 'Authentication required'
        });
      }

      const scopes = Array.isArray(requiredScopes)
        ? requiredScopes
        : [requiredScopes];

      const hasScope = scopes.some(scope =>
        req.user.scopes.includes(scope)
      );

      if (!hasScope) {
        this.logger.warn('Insufficient permissions', {
          user_id: req.user.id,
          required_scopes: scopes,
          actual_scopes: req.user.scopes
        });

        return res.status(403).json({
          error: 'insufficient_permissions',
          message: 'Insufficient permissions for this operation',
          required_scopes: scopes
        });
      }

      next();
    };
  }
}
```

---

## 5. Security Testing Requirements

### 5.1 Authentication Testing

**Test Cases**:

1. ✅ Valid token with correct audience → Allow
2. ✅ Valid token with wrong audience → Deny (401)
3. ✅ Expired token → Deny (401)
4. ✅ Token not yet valid (nbf in future) → Deny (401)
5. ✅ Invalid signature → Deny (401)
6. ✅ Missing token → Deny (401)
7. ✅ Malformed token → Deny (401)
8. ✅ Token from different issuer → Deny (401)
9. ✅ Tampered token (modified claims) → Deny (401)
10. ✅ Non-Bearer authorization → Deny (401)

### 5.2 Authorization Testing

**Test Cases**:

1. ✅ Token with required scope → Allow
2. ✅ Token without required scope → Deny (403)
3. ✅ Token with empty scope → Deny (403)
4. ✅ Token with partial scope match → Deny (403)
5. ✅ Admin scope accessing read-only tool → Allow
6. ✅ Read scope accessing write tool → Deny (403)

### 5.3 Security Testing

**Penetration Testing**:
- Token replay attacks
- Token forgery attempts
- MITM attacks (test TLS enforcement)
- Scope manipulation attempts
- Race conditions in token validation

**Load Testing**:
- 1000 concurrent authenticated clients
- Token validation latency under load
- JWKS cache performance
- Rate limiting effectiveness

---

## 6. Security Monitoring

### 6.1 Metrics to Track

**Authentication Metrics**:
- Successful authentications per minute
- Failed authentications per minute
- Token expiration rate
- JWKS fetch latency
- Token validation latency

**Authorization Metrics**:
- Permission denied count (403)
- Scope violation attempts
- Tool access patterns per user

**Security Metrics**:
- Invalid token attempts
- Signature verification failures
- Audience validation failures
- Rate limit violations per user

### 6.2 CloudWatch Alarms

**Critical Alarms**:
- Authentication failure rate > 20/min (potential attack)
- JWKS fetch failures > 5/min (service disruption)
- Token validation errors > 10/min
- 401 response rate > 10%

**Warning Alarms**:
- Token validation latency > 100ms
- JWKS cache miss rate > 20%
- Scope violation attempts > 5/min per user

### 6.3 Audit Logging

**Required Log Fields**:
```typescript
{
  timestamp: '2025-10-24T12:34:56Z',
  event_type: 'authentication' | 'authorization' | 'tool_execution',
  user_id: 'sub-claim-from-token',
  client_id: 'azp-claim-from-token',
  action: 'execute_query',
  resource: 'database:prod',
  result: 'success' | 'denied' | 'error',
  scopes: ['database.read', 'database.write'],
  ip_address: '10.0.1.45',
  user_agent: 'MCP-Client/1.0'
}
```

---

## 7. Compliance Considerations

### 7.1 Data Protection

**GDPR / Privacy Compliance**:
- User identity logging (PII) - ensure compliance with data retention policies
- Token claims may contain PII (email, name) - handle appropriately
- Audit logs contain user activity - secure storage required
- Right to erasure - implement user data deletion procedures

### 7.2 Access Control

**Principle of Least Privilege**:
- Clients request minimum required scopes
- Separate read/write/admin permissions
- Regular scope audit and review

### 7.3 Audit Requirements

**Audit Trail**:
- All authentication attempts (success/failure)
- All authorization decisions
- All tool executions with user attribution
- Token validation failures
- Configuration changes

**Retention**:
- Security logs: 90 days minimum
- Audit logs: 1 year minimum (compliance)
- Sensitive data: Follow organizational policies

---

## 8. Security Recommendations

### 8.1 High Priority

1. ✅ **Enforce HTTPS only** - No HTTP fallback
2. ✅ **Validate all token claims** - Audience, issuer, expiration
3. ✅ **Implement scope-based authorization** - Granular permissions
4. ✅ **Short-lived tokens** - 1 hour maximum
5. ✅ **Comprehensive logging** - All auth events

### 8.2 Medium Priority

1. **Certificate-based client auth** - More secure than client secrets
2. **Per-user rate limiting** - Replace session-based limits
3. **Token binding** - Bind tokens to TLS connection
4. **WAF integration** - AWS WAF for additional protection
5. **Security headers** - HSTS, CSP, X-Frame-Options

### 8.3 Future Enhancements

1. **Role-based access control** - Map EntraID roles to permissions
2. **Dynamic authorization** - Real-time permission updates
3. **Token revocation** - Implement token blocklist
4. **Mutual TLS** - Client certificate authentication
5. **Zero Trust Architecture** - Continuous verification

---

## Approval

**Reviewed By**: _________________
**Date**: _________________
**Status**: [ ] Approved [ ] Approved with Changes [ ] Rejected
**Security Level**: [ ] Low [ ] Medium [ ] High [ ] Critical

**Comments**:

---

**Document End**
