#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createEvidenceServer } from './server.js';

async function main() {
  const server = createEvidenceServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('[Evidence-MCP] Server running on stdio');
}

main().catch((err: unknown) => {
  console.error('[Evidence-MCP] Fatal server error:', err);
  process.exit(1);
});
