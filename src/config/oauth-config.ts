/**
 * OAuth Configuration Module
 *
 * Manages OAuth 2.0 configuration for EntraID (Azure AD) authentication
 */

export interface OAuthConfig {
  enabled: boolean;
  issuer: string;
  audience: string;
  jwksUri: string;
  tokenAlgorithm: string;
  clockTolerance: number;
}

export interface HTTPServerConfig {
  port: number;
  host: string;
  path: string;
}

/**
 * Load OAuth configuration from environment variables
 */
export function loadOAuthConfig(): OAuthConfig {
  const enabled = process.env.OAUTH_ENABLED === 'true';

  if (!enabled) {
    return {
      enabled: false,
      issuer: '',
      audience: '',
      jwksUri: '',
      tokenAlgorithm: 'RS256',
      clockTolerance: 60
    };
  }

  // Validate required configuration
  const issuer = process.env.OAUTH_ISSUER;
  const audience = process.env.OAUTH_AUDIENCE;
  const jwksUri = process.env.OAUTH_JWKS_URI;

  if (!issuer) {
    throw new Error('OAUTH_ISSUER environment variable is required when OAUTH_ENABLED=true');
  }

  if (!audience) {
    throw new Error('OAUTH_AUDIENCE environment variable is required when OAUTH_ENABLED=true');
  }

  if (!jwksUri) {
    throw new Error('OAUTH_JWKS_URI environment variable is required when OAUTH_ENABLED=true');
  }

  return {
    enabled: true,
    issuer,
    audience,
    jwksUri,
    tokenAlgorithm: process.env.OAUTH_TOKEN_ALGORITHM || 'RS256',
    clockTolerance: parseInt(process.env.OAUTH_CLOCK_TOLERANCE || '60', 10)
  };
}

/**
 * Load HTTP server configuration from environment variables
 */
export function loadHTTPServerConfig(): HTTPServerConfig {
  return {
    port: parseInt(process.env.MCP_SERVER_PORT || '3000', 10),
    host: process.env.MCP_SERVER_HOST || '0.0.0.0',
    path: process.env.MCP_SERVER_PATH || '/mcp'
  };
}

/**
 * Validate OAuth configuration
 */
export function validateOAuthConfig(config: OAuthConfig): void {
  if (!config.enabled) {
    return;
  }

  // Validate issuer format
  try {
    new URL(config.issuer);
  } catch (error) {
    throw new Error(`Invalid OAUTH_ISSUER URL: ${config.issuer}`);
  }

  // Validate JWKS URI format
  try {
    new URL(config.jwksUri);
  } catch (error) {
    throw new Error(`Invalid OAUTH_JWKS_URI URL: ${config.jwksUri}`);
  }

  // Validate audience format (should be api:// or https://)
  if (!config.audience.startsWith('api://') && !config.audience.startsWith('https://')) {
    throw new Error('OAUTH_AUDIENCE must start with api:// or https://');
  }

  // Validate algorithm
  const validAlgorithms = ['RS256', 'RS384', 'RS512'];
  if (!validAlgorithms.includes(config.tokenAlgorithm)) {
    throw new Error(`Invalid OAUTH_TOKEN_ALGORITHM: ${config.tokenAlgorithm}. Must be one of: ${validAlgorithms.join(', ')}`);
  }

  // Validate clock tolerance
  if (config.clockTolerance < 0 || config.clockTolerance > 300) {
    throw new Error('OAUTH_CLOCK_TOLERANCE must be between 0 and 300 seconds');
  }
}

/**
 * Validate HTTP server configuration
 */
export function validateHTTPServerConfig(config: HTTPServerConfig): void {
  // Validate port
  if (config.port < 1 || config.port > 65535) {
    throw new Error(`Invalid MCP_SERVER_PORT: ${config.port}. Must be between 1 and 65535`);
  }

  // Validate host
  if (!config.host) {
    throw new Error('MCP_SERVER_HOST cannot be empty');
  }

  // Validate path
  if (!config.path.startsWith('/')) {
    throw new Error('MCP_SERVER_PATH must start with /');
  }
}
