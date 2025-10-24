# Architecture Review: Transport Migration to Streamable HTTP

**Document Version**: 1.0
**Date**: 2025-10-24
**Status**: Review
**Prepared for**: PostgreSQL MCP Server Transport Migration

---

## Executive Summary

This document reviews the architectural changes required to migrate the PostgreSQL MCP Server from **StdioServerTransport** (local process execution model) to **Streamable HTTP** (network-based model) to support the correct deployment architecture where the MCP server runs on an EC2 instance and AI clients connect from other instances in the same private network.

### Key Changes
- **Transport Protocol**: Stdio → Streamable HTTP
- **Communication Model**: Local process pipes → Network HTTP/SSE
- **Authentication**: OS-level process trust → OAuth 2.0 (EntraID)
- **Deployment Model**: Local CLI tool → Network service on EC2

---

## 1. Current Architecture

### 1.1 Transport Layer

**Current Implementation**: `src/index.ts:120`
```typescript
const transport = new StdioServerTransport();
await this.server.connect(transport);
```

**Communication Model**:
```
┌─────────────────────┐    stdin/stdout    ┌─────────────────────┐
│   AI Client/Tool    │ ◄───────────────► │    MCP Server       │
│   (Same Process)    │    OS Pipes        │  (Child Process)    │
└─────────────────────┘                    └─────────────────────┘
```

**Assumptions**:
- Client and server run on the same machine
- Communication via stdin/stdout pipes
- Process-level isolation for security
- Server launched as child process by client
- No network communication required
- OS-level trust model

### 1.2 Security Model

**Authentication**: None required (process-level trust)
- Client spawns server process
- Communication via inherited file descriptors
- OS provides isolation between processes

**Authorization**: Implicit
- If client can spawn process, it has full access
- No token-based authentication
- No session management

### 1.3 Deployment Model

**Current Deployment Assumption**:
- MCP server deployed as a CLI tool
- Installed on client machine
- Launched on-demand by AI client
- Short-lived processes (per-request or per-session)

**Configuration**: Local environment variables
- `.env` file on client machine
- Environment variables in client's shell

### 1.4 Files Assuming Local Process Execution

| File | Line(s) | Assumption | Impact |
|------|---------|------------|--------|
| `src/index.ts` | 120 | `StdioServerTransport` | Core transport |
| `README.md` | Multiple | Local installation instructions | Documentation |
| `package.json` | 7 | `"bin"` entry for CLI usage | Installation |
| `docs/DEPLOYMENT.md` | Multiple | Local execution model | Documentation |
| `infrastructure/terraform/user_data.sh` | TBD | May assume process spawning | Deployment |

---

## 2. Target Architecture

### 2.1 Transport Layer

**Target Implementation**:
```typescript
import { StreamableHTTPTransport } from '@modelcontextprotocol/sdk/server/http.js';

const transport = new StreamableHTTPTransport({
  port: process.env.MCP_SERVER_PORT || 3000,
  host: process.env.MCP_SERVER_HOST || '0.0.0.0',
  path: '/mcp',
  oauth: {
    issuer: process.env.OAUTH_ISSUER,
    audience: process.env.OAUTH_AUDIENCE,
    jwksUri: process.env.OAUTH_JWKS_URI
  }
});
```

**Communication Model**:
```
┌─────────────────────┐   HTTPS + OAuth    ┌─────────────────────┐   IAM Auth   ┌──────────────┐
│  AI Client/Tool     │ ◄───────────────► │  MCP Server (EC2)   │ ◄─────────► │  PostgreSQL  │
│  (Instance A)       │  Streamable HTTP   │  (Instance B)       │              │  RDS         │
│  Private Network    │  + EntraID Token   │  Private Network    │              │              │
└─────────────────────┘                    └─────────────────────┘              └──────────────┘
```

**Network Communication**:
- HTTP/1.1 or HTTP/2 with Server-Sent Events (SSE)
- Request/Response for tool calls
- SSE for streaming responses and server-initiated messages
- TLS 1.2+ for encryption (HTTPS)

### 2.2 Security Model

**Authentication**: OAuth 2.0 (EntraID/Azure AD)
- JWT token-based authentication
- Token validation on every request
- Token refresh mechanism
- Audience and scope validation

**Authorization**: Token claims-based
- User identity from token claims
- Role-based access control (RBAC) possible
- Scope-based permissions
- Session tracking via token

**Transport Security**:
- TLS 1.2+ encryption (HTTPS)
- Certificate-based server authentication
- Private network isolation (AWS VPC)

### 2.3 Deployment Model

**Target Deployment**:
- MCP server as long-running HTTP service on EC2
- Systemd service for process management
- Always-on availability
- Multiple concurrent client connections
- Load balancer ready (future)

**Configuration**: Environment variables on EC2
- Environment variables via systemd service
- AWS Parameter Store for secrets
- EntraID OAuth configuration

### 2.4 Network Architecture

**AWS VPC Setup**:
```
┌────────────────────────────────────────────────────────────────┐
│ AWS VPC (Private Network)                                      │
│                                                                 │
│  ┌─────────────────────┐          ┌─────────────────────┐     │
│  │  AI Client Instance │  HTTPS   │  MCP Server EC2     │     │
│  │  (Private Subnet)   │ ───────► │  (Private Subnet)   │     │
│  │                     │  Port    │  Port: 3000         │     │
│  └─────────────────────┘  3000    │  Security Group:    │     │
│                                    │  - Allow 3000 from  │     │
│                                    │    client SG        │     │
│                                    └─────────┬───────────┘     │
│                                              │ IAM Auth        │
│                                              ▼                 │
│                                    ┌─────────────────────┐     │
│                                    │  PostgreSQL RDS     │     │
│                                    │  (Private Subnet)   │     │
│                                    └─────────────────────┘     │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
         │
         │ HTTPS (Internet Gateway)
         ▼
┌─────────────────────┐
│  EntraID / Azure AD │
│  (Token Validation) │
└─────────────────────┘
```

---

## 3. Implementation Impact Analysis

### 3.1 Code Changes Required

#### Core Server (`src/index.ts`)

**Current**:
```typescript
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

async start(): Promise<void> {
  const transport = new StdioServerTransport();
  await this.server.connect(transport);
}
```

**Target**:
```typescript
import { StreamableHTTPTransport } from '@modelcontextprotocol/sdk/server/http.js';
import { OAuthMiddleware } from './middleware/oauth.js';

async start(): Promise<void> {
  const oauthMiddleware = new OAuthMiddleware({
    issuer: process.env.OAUTH_ISSUER!,
    audience: process.env.OAUTH_AUDIENCE!,
    jwksUri: process.env.OAUTH_JWKS_URI!
  });

  const transport = new StreamableHTTPTransport({
    port: parseInt(process.env.MCP_SERVER_PORT || '3000', 10),
    host: process.env.MCP_SERVER_HOST || '0.0.0.0',
    path: '/mcp',
    middleware: [oauthMiddleware.authenticate.bind(oauthMiddleware)]
  });

  await this.server.connect(transport);

  this.logger.info('HTTP server started', {
    port: process.env.MCP_SERVER_PORT || '3000',
    host: process.env.MCP_SERVER_HOST || '0.0.0.0'
  });
}
```

**Impact**: Moderate - Core transport initialization logic changes, but MCP SDK abstracts most complexity

#### New Files Required

1. **`src/middleware/oauth.ts`** - OAuth token validation middleware
2. **`src/transport/http-transport.ts`** - HTTP transport wrapper (if needed)
3. **`src/config/oauth-config.ts`** - OAuth configuration management
4. **`src/health/health-check.ts`** - Health check endpoint handler

#### Dependencies Required

```json
{
  "dependencies": {
    "@azure/identity": "^4.0.0",
    "express": "^4.18.0",
    "jsonwebtoken": "^9.0.0",
    "jwks-rsa": "^3.0.0"
  }
}
```

### 3.2 Configuration Changes

#### Environment Variables

**New Variables**:
```bash
# HTTP Server Configuration
MCP_SERVER_PORT=3000
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PATH=/mcp

# OAuth Configuration (EntraID)
OAUTH_ENABLED=true
OAUTH_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
OAUTH_AUDIENCE=api://{application-id}
OAUTH_JWKS_URI=https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys
OAUTH_TOKEN_ALGORITHM=RS256

# EntraID Application
ENTRAID_TENANT_ID=your-tenant-id
ENTRAID_CLIENT_ID=your-client-id
ENTRAID_SCOPE=api://{application-id}/.default

# TLS Configuration (if terminating TLS at application)
TLS_ENABLED=false  # Use ALB/NLB for TLS termination
TLS_CERT_PATH=/path/to/cert.pem
TLS_KEY_PATH=/path/to/key.pem
```

**Removed Variables**:
- Any CLI-specific configuration

**Unchanged Variables**:
- Database configuration (DATABASE_CONFIGS, DEFAULT_DATABASE_ID)
- Security settings (RATE_LIMIT_*, MAX_QUERY_*)
- Logging configuration (LOG_LEVEL, LOG_FORMAT)
- Connection pool settings

### 3.3 Deployment Changes

#### Infrastructure (`infrastructure/terraform/`)

**New Resources**:
1. **Security Group Rules**: Allow port 3000 from client security group
2. **Application Load Balancer** (optional, future): For multiple instances
3. **Target Group**: Health check on `/health` endpoint
4. **CloudWatch Alarms**: HTTP service monitoring

**Modified Resources**:
1. **EC2 User Data**: Start as systemd service instead of CLI
2. **IAM Role**: Add permissions for Systems Manager (parameter store)

#### Systemd Service (`infrastructure/systemd/mcp-server.service`)

**New File**:
```ini
[Unit]
Description=PostgreSQL MCP Server
After=network.target

[Service]
Type=simple
User=mcp-server
WorkingDirectory=/opt/mcp-server
EnvironmentFile=/etc/mcp-server/config.env
ExecStart=/usr/bin/node /opt/mcp-server/dist/index.js
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

### 3.4 Documentation Changes

| Document | Changes Required |
|----------|------------------|
| `README.md` | Update from "CLI tool" to "HTTP service", add OAuth setup |
| `docs/DEPLOYMENT.md` | Complete rewrite for EC2 service deployment |
| `docs/CONFIGURATION.md` | Add OAuth configuration section |
| `docs/SETUP.md` | Add EntraID application registration steps |
| `docs/SECURITY.md` | Add OAuth security model documentation |
| `package.json` | Remove `"bin"` entry, update description |

---

## 4. Risks and Mitigations

### 4.1 Technical Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| MCP SDK HTTP transport issues | High | Low | Test thoroughly, report issues to Anthropic |
| OAuth token validation failures | High | Medium | Implement robust error handling, logging |
| Network connectivity issues | High | Low | Health checks, CloudWatch alarms |
| Performance degradation | Medium | Low | Load testing, connection pooling |
| EntraID configuration errors | Medium | Medium | Detailed setup documentation, validation script |

### 4.2 Security Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Token theft/replay | High | Low | Short-lived tokens, HTTPS only, token binding |
| Unauthorized access | High | Low | Proper audience/scope validation, RBAC |
| Man-in-the-middle attacks | High | Low | TLS 1.2+, certificate pinning (optional) |
| DoS attacks | Medium | Medium | Rate limiting (already implemented), WAF |

### 4.3 Operational Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| Configuration mistakes | Medium | High | Validation scripts, testing environment |
| Monitoring gaps | Low | Medium | Comprehensive CloudWatch alarms, logging |
| Service startup failures | Medium | Medium | Systemd restart policy, health checks |

---

## 5. Success Criteria

### 5.1 Functional Requirements

- ✅ MCP server runs as HTTP service on EC2
- ✅ AI clients can connect from different instances
- ✅ OAuth authentication via EntraID works
- ✅ All existing MCP tools function identically
- ✅ Database connections (IAM and standard) work unchanged
- ✅ Health check endpoint provides service status

### 5.2 Non-Functional Requirements

- **Performance**: Response time < 200ms (p95)
- **Availability**: Service runs continuously with systemd
- **Security**: No authentication bypass, all requests validated
- **Scalability**: Support 100+ concurrent client connections
- **Observability**: All requests logged, metrics in CloudWatch

### 5.3 Documentation Requirements

- All documentation updated to reflect HTTP transport
- EntraID setup guide created
- Troubleshooting guide for common issues

---

## 6. Implementation Timeline

| Phase | Duration | Dependencies |
|-------|----------|--------------|
| Architecture Review | 1 day | ✅ Complete |
| Security Review | 1 day | Architecture Review |
| Implementation | 3-4 days | Security Review |
| Testing | 2-3 days | Implementation |
| Deployment Setup | 1-2 days | Testing |
| Documentation | 1-2 days | Parallel with implementation |
| **Total** | **9-13 days** | |

---

## 7. Open Questions

1. **Load Balancing**: Do we need ALB for multiple MCP server instances?
   - **Recommendation**: Not initially, add when scaling needed

2. **TLS Termination**: Application-level or load balancer?
   - **Recommendation**: Load balancer (ALB) for easier cert management

3. **Token Refresh**: Client-side or server-side token refresh?
   - **Recommendation**: Client-side, server validates tokens only

4. **Health Check Endpoint**: What should it check?
   - **Recommendation**: Database connectivity, service health

5. **Metrics**: What additional metrics needed for HTTP transport?
   - **Recommendation**: Request count, latency, error rate, concurrent connections

---

## 8. Recommendations

### 8.1 Implementation Priority

**High Priority**:
1. OAuth middleware implementation
2. Streamable HTTP transport integration
3. Health check endpoint
4. Deployment configuration updates

**Medium Priority**:
1. Load balancer setup (future scaling)
2. Additional monitoring/metrics
3. Client configuration documentation

**Low Priority**:
1. Client SDK for easier integration
2. Rate limiting per-token (vs per-session)

### 8.2 Architecture Decisions

1. **Use EntraID**: Aligns with enterprise requirements, proven OAuth provider
2. **TLS at Load Balancer**: Simpler certificate management
3. **Stateless Server**: No session storage, token-based authentication only
4. **Health Checks**: Essential for production reliability
5. **HTTP-Only Transport**: Remove stdio transport entirely

---

## Approval

**Reviewed By**: _________________
**Date**: _________________
**Status**: [ ] Approved [ ] Approved with Changes [ ] Rejected
**Comments**:

---

**Document End**
