# Local Process Execution Assumptions Review

**Document Version**: 1.0
**Date**: 2025-10-24
**Status**: Review
**Purpose**: Identify all places in the project where local process execution is assumed

---

## Executive Summary

This document catalogs all locations in the PostgreSQL MCP Server codebase where local process execution (Stdio transport) is assumed, along with recommendations for updates to support network-based HTTP transport.

---

## 1. Code Files

### 1.1 Core Server Implementation

**File**: `src/index.ts:120`

**Current Code**:
```typescript
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

async start(): Promise<void> {
  const transport = new StdioServerTransport();
  await this.server.connect(transport);
}
```

**Assumption**: Direct stdin/stdout communication

**Action Required**: ✅ Replace with StreamableHTTPTransport
- Remove StdioServerTransport import
- Add StreamableHTTPTransport import
- Implement OAuth middleware integration
- Add HTTP server configuration

**Priority**: **CRITICAL** - Core functionality

---

### 1.2 Package Configuration

**File**: `package.json`

**Current Configuration**:
```json
{
  "description": "MCP server for PostgreSQL with IAM authentication",
  "scripts": {
    "dev": "tsx src/index.ts",
    "start": "node dist/index.js"
  }
}
```

**Assumptions**:
- CLI tool model (no port configuration)
- Direct process execution via `tsx` or `node`
- No HTTP server-specific scripts

**Action Required**: ✅ Update package.json
- Update description to "HTTP service" instead of "MCP server"
- Scripts remain the same (still run via node, but as HTTP server)
- No `"bin"` entry needed (not a CLI tool)

**Priority**: **LOW** - Documentation clarity

---

## 2. Documentation Files

### 2.1 README.md

**Sections with Local Execution Assumptions**:

#### Section: "Quick Start" (Lines 34-104)

**Current Text**:
```markdown
### Installation
npm install
npm run build

### Usage
#### Standard Mode (Local Development)
npm run dev

#### IAM Mode (AWS Production)
USE_IAM_AUTH=true npm start
```

**Assumptions**:
- "Local Development" vs "AWS Production" distinction
- No mention of network configuration
- No port configuration shown
- No OAuth authentication mentioned

**Action Required**: ✅ Update Quick Start
- Remove "Local Development" references
- Add network configuration section
- Add OAuth setup requirements
- Add port configuration
- Update usage examples to show HTTP server startup

**Priority**: **HIGH** - Primary user documentation

---

#### Section: "Testing Connection" (Lines 96-104)

**Current Text**:
```markdown
### Testing Connection
npm run test:connection
npm run test:iam
```

**Assumptions**:
- Direct database connection testing
- No HTTP endpoint testing
- No OAuth token testing

**Action Required**: ✅ Add HTTP testing section
- Add health check endpoint testing (`curl http://localhost:3000/health`)
- Add OAuth token validation testing
- Keep existing database connection tests (still relevant)

**Priority**: **MEDIUM** - Testing documentation

---

### 2.2 SETUP.md

**Sections with Local Execution Assumptions**:

#### Section: "Project Setup" (Lines 64-96)

**Current Text**:
```markdown
### 1. Clone and Install
git clone <repository-url>
cd postgresql-mcp-server
npm install

### 2. Environment Configuration
Create a `.env` file...
```

**Assumptions**:
- No HTTP server configuration
- No OAuth configuration
- No port or network settings
- No EntraID setup instructions

**Action Required**: ✅ Complete rewrite of setup section
- Add EntraID application registration steps
- Add OAuth configuration variables
- Add HTTP server configuration (port, host)
- Add security group configuration for AWS
- Add TLS/certificate setup (if applicable)

**Priority**: **HIGH** - Essential for deployment

---

### 2.3 DEPLOYMENT.md

**Location**: `docs/DEPLOYMENT.md`

**Expected Assumptions** (need to verify):
- Process spawning model
- Systemd service configuration may be missing
- No load balancer configuration
- No health check endpoint documentation

**Action Required**: ✅ Review and update deployment guide
- Add systemd service configuration
- Add health check endpoint setup
- Add load balancer configuration (future)
- Update CI/CD pipeline for HTTP service
- Add network security group rules

**Priority**: **HIGH** - Deployment instructions

---

### 2.4 ARCHITECTURE.md

**Location**: `ARCHITECTURE.md`

**Assumptions**: Likely documents Stdio transport architecture

**Action Required**: ✅ Update architecture documentation
- Document HTTP transport architecture
- Add OAuth authentication flow diagrams
- Update security model section
- Document network topology
- Update client-server interaction diagrams

**Priority**: **MEDIUM** - Technical documentation

---

## 3. Infrastructure Files

### 3.1 Terraform Configuration

**Files to Review**:
- `infrastructure/terraform/main.tf`
- `infrastructure/terraform/modules/ec2/main.tf`
- `infrastructure/terraform/user_data.sh`

**Expected Assumptions**:
- EC2 user data may spawn process directly
- Security groups may not allow port 3000
- No load balancer configuration
- No health check configuration

**Action Required**: ✅ Update Terraform configuration
1. **Security Groups** (`modules/ec2/security-group.tf`):
   - Add ingress rule for port 3000 from client security group
   - Add egress rule for HTTPS to EntraID (443)

2. **User Data Script** (`user_data.sh`):
   - Install systemd service file
   - Configure environment variables
   - Start service via systemd (not direct execution)

3. **New Resources**:
   - Create `systemd/mcp-server.service` file
   - Create health check target group (future ALB)

**Priority**: **HIGH** - Deployment infrastructure

---

### 3.2 Deployment Scripts

**Files to Review**:
- `deployment/scripts/deploy.sh`
- `deployment/scripts/log-server.js`

**Expected Assumptions**:
- May spawn server process directly
- May not configure HTTP endpoints

**Action Required**: ✅ Review deployment scripts
- Ensure systemd service management
- Add health check validation
- Add OAuth configuration validation
- Add port availability checks

**Priority**: **MEDIUM** - Deployment automation

---

## 4. Testing Files

### 4.1 Connection Tests

**Files**:
- `src/test/connection.ts`
- `src/test/iam-connection.ts`

**Current Functionality**: Direct database connection testing

**Assumptions**: Tests only database layer, not transport layer

**Action Required**: ✅ Add HTTP transport tests
- Create `src/test/http-transport.ts`
- Test OAuth token validation
- Test HTTP endpoint responses
- Test health check endpoint
- Keep existing database tests (still valid)

**Priority**: **MEDIUM** - Test coverage

---

### 4.2 Testing Documentation

**File**: `TESTING_GUIDE.md`

**Expected Assumptions**: May document MCP Inspector with Stdio

**Action Required**: ✅ Update testing guide
- Document HTTP client configuration for MCP Inspector
- Add OAuth token configuration
- Update connection examples for HTTP transport
- Add health check testing procedures

**Priority**: **MEDIUM** - Testing documentation

---

## 5. Configuration Files

### 5.1 Environment Variables

**File**: `.env.example`

**Missing Configuration**:
```bash
# HTTP Server Configuration
MCP_SERVER_PORT=3000
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PATH=/mcp

# OAuth Configuration
OAUTH_ENABLED=true
OAUTH_ISSUER=https://login.microsoftonline.com/{tenant-id}/v2.0
OAUTH_AUDIENCE=api://{application-id}
OAUTH_JWKS_URI=https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys

# EntraID Configuration
ENTRAID_TENANT_ID=your-tenant-id
ENTRAID_CLIENT_ID=your-client-id
ENTRAID_SCOPE=api://{application-id}/.default
```

**Action Required**: ✅ Update .env.example
- Add all HTTP server configuration
- Add all OAuth configuration
- Add EntraID configuration
- Document each variable with comments

**Priority**: **HIGH** - Configuration template

---

## 6. GitHub Actions / CI/CD

**Files to Review**:
- `.github/workflows/deploy.yml`
- Any other CI/CD configuration

**Expected Assumptions**:
- May test Stdio connection
- May not validate HTTP endpoints
- May not test OAuth flow

**Action Required**: ✅ Update CI/CD pipeline
- Add HTTP health check after deployment
- Add OAuth token validation test
- Add port availability check
- Update deployment smoke tests

**Priority**: **MEDIUM** - CI/CD automation

---

## 7. Summary of Required Changes

### 7.1 By Priority

#### **CRITICAL** (Implementation Blockers)
1. ✅ `src/index.ts` - Replace StdioServerTransport with StreamableHTTPTransport

#### **HIGH** (Essential for Deployment)
1. ✅ `README.md` - Update quick start and usage sections
2. ✅ `SETUP.md` - Complete rewrite with OAuth setup
3. ✅ `docs/DEPLOYMENT.md` - Update for HTTP service deployment
4. ✅ `infrastructure/terraform/` - Update security groups, user data, add systemd
5. ✅ `.env.example` - Add HTTP and OAuth configuration

#### **MEDIUM** (Important for Operations)
1. ✅ `ARCHITECTURE.md` - Update architecture documentation
2. ✅ `TESTING_GUIDE.md` - Update testing procedures
3. ✅ `src/test/` - Add HTTP transport tests
4. ✅ `deployment/scripts/` - Update deployment scripts
5. ✅ `.github/workflows/` - Update CI/CD pipeline

#### **LOW** (Documentation Polish)
1. ✅ `package.json` - Update description
2. ✅ Other documentation files - General updates

---

### 7.2 By File Type

#### **Code Changes** (3 files)
1. `src/index.ts` - Transport replacement
2. `src/middleware/oauth.ts` - New file (OAuth)
3. `src/test/http-transport.ts` - New file (testing)

#### **Configuration Changes** (2 files)
1. `.env.example` - Add HTTP/OAuth vars
2. `package.json` - Update description

#### **Infrastructure Changes** (4-5 files)
1. `infrastructure/terraform/modules/ec2/security-group.tf` - Port 3000
2. `infrastructure/terraform/user_data.sh` - Systemd service
3. `infrastructure/systemd/mcp-server.service` - New file
4. `deployment/scripts/deploy.sh` - Update for HTTP
5. `.github/workflows/deploy.yml` - Update CI/CD

#### **Documentation Changes** (6+ files)
1. `README.md` - Complete sections rewrite
2. `SETUP.md` - Complete rewrite
3. `docs/DEPLOYMENT.md` - Complete rewrite
4. `ARCHITECTURE.md` - Update transport section
5. `TESTING_GUIDE.md` - Add HTTP testing
6. Other docs - Minor updates

---

## 8. Change Impact Assessment

### 8.1 Breaking Changes

**For End Users**:
- ❌ **Cannot use Stdio transport** - Complete migration to HTTP
- ❌ **Different configuration required** - Must set up OAuth
- ❌ **Different deployment model** - HTTP service vs CLI tool

**For Developers**:
- ❌ **Different testing approach** - HTTP client needed
- ❌ **Different local development** - Still runs via npm, but as HTTP server

### 8.2 Non-Breaking Changes

**Preserved Functionality**:
- ✅ **All MCP tools** - Same functionality
- ✅ **Database connections** - IAM and standard both work
- ✅ **Security features** - All existing security remains
- ✅ **Multi-database support** - Still supported
- ✅ **Logging** - Same logging system

---

## 9. Implementation Order

### Phase 1: Core Implementation (Day 1-2)
1. ✅ Implement OAuth middleware (`src/middleware/oauth.ts`)
2. ✅ Update `src/index.ts` with StreamableHTTPTransport
3. ✅ Add health check endpoint
4. ✅ Update `.env.example` with new variables
5. ✅ Test locally with HTTP transport

### Phase 2: Documentation (Day 2-3)
1. ✅ Update `README.md` - Quick Start, Usage, Testing
2. ✅ Rewrite `SETUP.md` - Add EntraID setup
3. ✅ Update `docs/DEPLOYMENT.md` - HTTP service deployment
4. ✅ Update `ARCHITECTURE.md` - Transport architecture

### Phase 3: Infrastructure (Day 3-4)
1. ✅ Create systemd service file
2. ✅ Update Terraform security groups
3. ✅ Update user data script
4. ✅ Update deployment scripts
5. ✅ Update CI/CD pipeline

### Phase 4: Testing (Day 4-5)
1. ✅ Create HTTP transport tests
2. ✅ Update testing guide
3. ✅ End-to-end OAuth flow test
4. ✅ Deployment validation

---

## 10. Verification Checklist

After implementation, verify:

### Code
- [ ] No imports of `StdioServerTransport`
- [ ] `StreamableHTTPTransport` properly configured
- [ ] OAuth middleware validates tokens
- [ ] Health check endpoint responds
- [ ] All MCP tools work via HTTP

### Configuration
- [ ] `.env.example` has all HTTP/OAuth variables
- [ ] `package.json` description updated
- [ ] Terraform includes port 3000 rules
- [ ] Systemd service file exists

### Documentation
- [ ] README.md mentions HTTP server
- [ ] SETUP.md includes EntraID setup
- [ ] DEPLOYMENT.md covers HTTP deployment
- [ ] ARCHITECTURE.md documents HTTP transport
- [ ] TESTING_GUIDE.md includes HTTP tests

### Infrastructure
- [ ] Security groups allow port 3000
- [ ] User data installs systemd service
- [ ] Health checks configured
- [ ] CI/CD validates HTTP endpoints

---

## Approval

**Reviewed By**: _________________
**Date**: _________________
**Status**: [ ] Approved [ ] Approved with Changes [ ] Rejected
**Comments**:

---

**Document End**
