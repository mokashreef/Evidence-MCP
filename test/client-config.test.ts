import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  generateClientConfig,
  writeClientConfig,
  getDefaultConfigPath,
  SUPPORTED_MCP_CLIENTS,
} from '../src/client-config.js';
import { runCli } from '../src/cli.js';

describe('MCP Client Configuration Generator', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-client-config-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('Path Resolution & OS Defaults', () => {
    it('supports all required clients', () => {
      expect(SUPPORTED_MCP_CLIENTS).toEqual(['claude', 'cursor', 'gemini', 'vscode-cline']);
    });

    it('resolves correct config paths for Claude Desktop across operating systems', () => {
      const winPath = getDefaultConfigPath('claude', tempWorkspace, 'win32', 'C:\\Users\\TestUser');
      expect(winPath.toLowerCase()).toContain('claude\\claude_desktop_config.json');

      const macPath = getDefaultConfigPath('claude', tempWorkspace, 'darwin', '/Users/TestUser');
      expect(macPath).toBe('/Users/TestUser/Library/Application Support/Claude/claude_desktop_config.json');

      const linuxPath = getDefaultConfigPath('claude', tempWorkspace, 'linux', '/home/testuser');
      expect(linuxPath).toBe('/home/testuser/.config/Claude/claude_desktop_config.json');
    });

    it('resolves correct config paths for Cursor within target workspace', () => {
      const cursorPath = getDefaultConfigPath('cursor', tempWorkspace);
      expect(cursorPath).toBe(path.join(path.resolve(tempWorkspace), '.cursor', 'mcp.json'));
    });

    it('resolves correct config paths for Gemini CLI / Antigravity', () => {
      const geminiPath = getDefaultConfigPath('gemini', tempWorkspace, 'linux', '/home/testuser');
      expect(geminiPath).toBe('/home/testuser/.gemini/antigravity/mcp_config.json');
    });

    it('resolves correct config paths for VS Code Cline across operating systems', () => {
      const macCline = getDefaultConfigPath('vscode-cline', tempWorkspace, 'darwin', '/Users/TestUser');
      expect(macCline).toContain('saoudrizwan.claude-dev');
      expect(macCline).toContain('cline_mcp_settings.json');
    });
  });

  describe('Configuration Snippet Generation', () => {
    it('generates standard node execution config snippet with workspace argument', () => {
      const res = generateClientConfig({
        client: 'claude',
        workspacePath: tempWorkspace,
        cliScriptPath: 'dist/cli.js',
      });

      expect(res.client).toBe('claude');
      expect(res.serverName).toBe('evidence');
      expect(res.command).toBe('node');
      expect(res.args).toContain('--workspace');
      expect(res.args).toContain(path.resolve(tempWorkspace).replace(/\\/g, '/'));

      const serverObj = (res.configSnippet.mcpServers as Record<string, any>).evidence;
      expect(serverObj.command).toBe('node');
      expect(serverObj.args).toEqual(res.args);
    });

    it('generates global binary configuration when useGlobalBinary is true', () => {
      const res = generateClientConfig({
        client: 'cursor',
        workspacePath: tempWorkspace,
        useGlobalBinary: true,
      });

      expect(res.command).toBe('evidence-mcp');
      expect(res.args).toEqual(['--workspace', path.resolve(tempWorkspace).replace(/\\/g, '/')]);

      const serverObj = (res.configSnippet.mcpServers as Record<string, any>).evidence;
      expect(serverObj.command).toBe('evidence-mcp');
    });

    it('includes client-specific properties for VS Code Cline', () => {
      const res = generateClientConfig({
        client: 'vscode-cline',
        workspacePath: tempWorkspace,
      });

      const serverObj = (res.configSnippet.mcpServers as Record<string, any>).evidence;
      expect(serverObj.disabled).toBe(false);
      expect(serverObj.autoApprove).toEqual([]);
    });

    it('includes environment variables and custom serverName when specified', () => {
      const res = generateClientConfig({
        client: 'gemini',
        serverName: 'evidence-auditor',
        environmentVariables: {
          EVIDENCE_LOG_LEVEL: 'debug',
        },
      });

      expect(res.serverName).toBe('evidence-auditor');
      const servers = res.configSnippet.mcpServers as Record<string, any>;
      expect(servers['evidence-auditor']).toBeDefined();
      expect(servers['evidence-auditor'].env).toEqual({ EVIDENCE_LOG_LEVEL: 'debug' });
    });
  });

  describe('Safe File Writing & Server Merging', () => {
    it('creates new config file and parent directories when file does not exist', async () => {
      const targetFile = path.join(tempWorkspace, 'custom-configs', 'claude.json');

      const writeRes = await writeClientConfig({
        client: 'claude',
        workspacePath: tempWorkspace,
        targetPath: targetFile,
      });

      expect(writeRes.writtenToPath).toBe(targetFile);
      expect(writeRes.mergedWithExisting).toBe(false);
      expect(writeRes.totalServersInFile).toBe(1);

      expect(fs.existsSync(targetFile)).toBe(true);
      const parsed = JSON.parse(await fs.promises.readFile(targetFile, 'utf8'));
      expect(parsed.mcpServers.evidence).toBeDefined();
    });

    it('merges seamlessly into an existing config file preserving other MCP servers', async () => {
      const targetFile = path.join(tempWorkspace, 'mcp_settings.json');
      const existingConfig = {
        theme: 'dark',
        mcpServers: {
          github: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-github'],
          },
          postgres: {
            command: 'docker',
            args: ['run', '-i', 'mcp/postgres'],
          },
        },
      };

      await fs.promises.writeFile(targetFile, JSON.stringify(existingConfig, null, 2), 'utf8');

      const writeRes = await writeClientConfig({
        client: 'cursor',
        workspacePath: tempWorkspace,
        targetPath: targetFile,
      });

      expect(writeRes.mergedWithExisting).toBe(true);
      expect(writeRes.totalServersInFile).toBe(3);

      const updated = JSON.parse(await fs.promises.readFile(targetFile, 'utf8'));
      expect(updated.theme).toBe('dark');
      expect(updated.mcpServers.github).toBeDefined();
      expect(updated.mcpServers.postgres).toBeDefined();
      expect(updated.mcpServers.evidence).toBeDefined();
      expect(updated.mcpServers.evidence.command).toBe('node');
    });

    it('updates existing evidence server configuration without duplicating keys', async () => {
      const targetFile = path.join(tempWorkspace, 'claude.json');
      const initialConfig = {
        mcpServers: {
          evidence: {
            command: 'old-binary',
            args: [],
          },
        },
      };
      await fs.promises.writeFile(targetFile, JSON.stringify(initialConfig, null, 2), 'utf8');

      const writeRes = await writeClientConfig({
        client: 'claude',
        workspacePath: tempWorkspace,
        useGlobalBinary: true,
        targetPath: targetFile,
      });

      expect(writeRes.totalServersInFile).toBe(1);
      const updated = JSON.parse(await fs.promises.readFile(targetFile, 'utf8'));
      expect(updated.mcpServers.evidence.command).toBe('evidence-mcp');
    });
  });

  describe('CLI Integration', () => {
    it('outputs configuration snippet via evidence-mcp client config <client>', async () => {
      const exitCode = await runCli([
        'client',
        'config',
        'cursor',
        '--workspace',
        tempWorkspace,
      ]);
      expect(exitCode).toBe(0);
    });

    it('writes configuration file via evidence-mcp client config <client> --write', async () => {
      const outPath = path.join(tempWorkspace, 'cline.json');
      const exitCode = await runCli([
        'client',
        'config',
        'vscode-cline',
        '--write',
        '--path',
        outPath,
        '--workspace',
        tempWorkspace,
        '--global-bin',
      ]);

      expect(exitCode).toBe(0);
      expect(fs.existsSync(outPath)).toBe(true);
      const parsed = JSON.parse(await fs.promises.readFile(outPath, 'utf8'));
      expect(parsed.mcpServers.evidence.command).toBe('evidence-mcp');
      expect(parsed.mcpServers.evidence.disabled).toBe(false);
    });

    it('rejects unsupported client and prints error', async () => {
      const exitCode = await runCli(['client', 'config', 'unsupported-client']);
      expect(exitCode).toBe(1);
    });

    it('rejects unknown client sub-command', async () => {
      const exitCode = await runCli(['client', 'unknown-action']);
      expect(exitCode).toBe(1);
    });
  });
});
