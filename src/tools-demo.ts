#!/usr/bin/env node

import { DatabaseTools } from './tools/database-tools.js';
import { IAMDatabaseTools } from './tools/iam-database-tools.js';
import { SecureDatabaseTools } from './tools/secure-database-tools.js';
import { Logger } from './logging/logger.js';

// Mock classes for demonstration
class MockQueries {
  async listTables() { return []; }
  async describeTable() { return {}; }
  async executeSelect() { return { rows: [], row_count: 0, execution_time_ms: 0 }; }
}

class MockIAMQueries extends MockQueries {
  async getConnectionHealth() { return { is_connected: true, token_expires_in_ms: 900000, reconnect_attempts: 0, last_activity: new Date().toISOString() }; }
}

function displayTools(): void {
  const logger = new Logger();

  console.log('\n🔧 PostgreSQL MCP Server - Available Tools\n');
  console.log('=' .repeat(60));

  // Standard Tools
  const mockQueries = new MockQueries() as any;
  const standardTools = new DatabaseTools(mockQueries, logger);

  console.log('\n📋 STANDARD TOOLS (Basic Authentication)\n');
  standardTools.getToolDefinitions().forEach((tool, index) => {
    console.log(`${index + 1}. ${tool.name}`);
    console.log(`   Description: ${tool.description}`);
    console.log(`   Parameters: ${JSON.stringify(tool.inputSchema.properties || {}, null, 2)}`);
    console.log('');
  });

  // IAM Tools
  const mockIAMQueries = new MockIAMQueries() as any;
  const iamTools = new IAMDatabaseTools(mockIAMQueries, logger);

  console.log('\n🔐 IAM TOOLS (IAM Authentication)\n');
  iamTools.getToolDefinitions().forEach((tool, index) => {
    console.log(`${index + 1}. ${tool.name}`);
    console.log(`   Description: ${tool.description}`);
    console.log(`   Parameters: ${JSON.stringify(tool.inputSchema.properties || {}, null, 2)}`);
    console.log('');
  });

  // Secure Tools (Standard)
  const secureToolsStd = new SecureDatabaseTools(mockQueries, logger, false);

  console.log('\n🛡️  SECURE TOOLS (Standard Auth + Advanced Security)\n');
  secureToolsStd.getToolDefinitions().forEach((tool, index) => {
    console.log(`${index + 1}. ${tool.name}`);
    console.log(`   Description: ${tool.description}`);
    console.log(`   Parameters: ${JSON.stringify(tool.inputSchema.properties || {}, null, 2)}`);
    console.log('');
  });

  // Secure Tools (IAM)
  const secureToolsIAM = new SecureDatabaseTools(mockIAMQueries, logger, true);

  console.log('\n🔐🛡️  SECURE IAM TOOLS (IAM Auth + Advanced Security)\n');
  secureToolsIAM.getToolDefinitions().forEach((tool, index) => {
    console.log(`${index + 1}. ${tool.name}`);
    console.log(`   Description: ${tool.description}`);
    console.log(`   Parameters: ${JSON.stringify(tool.inputSchema.properties || {}, null, 2)}`);
    console.log('');
  });

  console.log('=' .repeat(60));
  console.log('\n🚀 SERVER MODES:\n');
  console.log('• Basic Mode:    npm start       - Standard auth, basic tools');
  console.log('• IAM Mode:      npm start:iam   - IAM auth, standard + IAM tools');
  console.log('• Secure Mode:   npm start:secure - Advanced security + all tools');
  console.log('\n📖 For detailed usage, see FUNCTIONS.md');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  displayTools();
}