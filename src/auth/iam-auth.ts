import { Signer } from '@aws-sdk/rds-signer';
import { fromInstanceMetadata } from '@aws-sdk/credential-providers';
import { IAMTokenInfo, DatabaseConfig } from '../types/index.js';
import { Logger } from '../logging/logger.js';

export class IAMAuthenticator {
  private signer: Signer;
  private logger: Logger;
  private currentToken: IAMTokenInfo | null = null;
  private readonly TOKEN_REFRESH_BUFFER_MS = 2 * 60 * 1000; // 2 minutes

  constructor(config: DatabaseConfig, logger: Logger) {
    this.logger = logger;

    this.signer = new Signer({
      credentials: fromInstanceMetadata(),
      region: config.region,
      hostname: config.host,
      port: config.port,
      username: config.user
    });
  }

  async getAuthToken(): Promise<string> {
    if (this.shouldRefreshToken()) {
      await this.refreshToken();
    }

    if (!this.currentToken) {
      throw new Error('Failed to obtain IAM authentication token');
    }

    return this.currentToken.token;
  }

  private shouldRefreshToken(): boolean {
    if (!this.currentToken) {
      return true;
    }

    const now = new Date();
    const timeUntilExpiry = this.currentToken.expires_at.getTime() - now.getTime();

    return timeUntilExpiry <= this.TOKEN_REFRESH_BUFFER_MS;
  }

  private async refreshToken(): Promise<void> {
    try {
      this.logger.debug('Refreshing IAM authentication token');

      const token = await this.signer.getAuthToken();
      const now = new Date();
      const expiresAt = new Date(now.getTime() + 15 * 60 * 1000); // 15 minutes

      this.currentToken = {
        token,
        generated_at: now,
        expires_at: expiresAt
      };

      this.logger.info('IAM token refreshed successfully', {
        expires_at: expiresAt.toISOString(),
        time_until_expiry_minutes: 15
      });

    } catch (error) {
      this.logger.error('Failed to refresh IAM token', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw new Error(`IAM token refresh failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  getTokenInfo(): IAMTokenInfo | null {
    return this.currentToken;
  }

  async validateCredentials(): Promise<boolean> {
    try {
      await this.getAuthToken();
      return true;
    } catch (error) {
      this.logger.error('IAM credentials validation failed', {
        error: error instanceof Error ? error.message : String(error)
      });
      return false;
    }
  }

  isTokenExpired(): boolean {
    if (!this.currentToken) {
      return true;
    }

    return new Date() >= this.currentToken.expires_at;
  }

  getTimeUntilExpiry(): number | null {
    if (!this.currentToken) {
      return null;
    }

    return Math.max(0, this.currentToken.expires_at.getTime() - new Date().getTime());
  }
}