import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  isCommandAllowed,
  sanitizeEnvironment,
  resolveCommandInvocation,
  executeSandboxedCommand,
  setMaxRunnerConcurrency,
  getActiveRunnerProcesses,
  ALLOWED_COMMANDS,
  FORBIDDEN_COMMANDS,
} from '../src/runner.js';
import { createEvidenceServer } from '../src/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { loadBundle } from '../src/storage.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { runCli } from '../src/cli.js';

describe('Sandboxed Command Runner & Execution Security', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-runner-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('Policy & Allowlist / Blocklist', () => {
    it('approves standard developer tooling', () => {
      expect(isCommandAllowed('npm')).toBe(true);
      expect(isCommandAllowed('npx')).toBe(true);
      expect(isCommandAllowed('node')).toBe(true);
      expect(isCommandAllowed('git')).toBe(true);
      expect(isCommandAllowed('vitest')).toBe(true);
      expect(isCommandAllowed('cargo')).toBe(true);
      expect(isCommandAllowed('python3')).toBe(true);
    });

    it('handles case-insensitivity and binary extensions (.exe, .cmd)', () => {
      expect(isCommandAllowed('NODE.EXE')).toBe(true);
      expect(isCommandAllowed('npm.cmd')).toBe(true);
      expect(isCommandAllowed('Git.exe')).toBe(true);
    });

    it('strictly forbids raw shells, subshells, and interpreters', () => {
      expect(isCommandAllowed('sh')).toBe(false);
      expect(isCommandAllowed('bash')).toBe(false);
      expect(isCommandAllowed('zsh')).toBe(false);
      expect(isCommandAllowed('powershell')).toBe(false);
      expect(isCommandAllowed('pwsh')).toBe(false);
      expect(isCommandAllowed('cmd')).toBe(false);
      expect(isCommandAllowed('cmd.exe')).toBe(false);
    });

    it('strictly forbids file destroyers and system modifiers', () => {
      expect(isCommandAllowed('rm')).toBe(false);
      expect(isCommandAllowed('del')).toBe(false);
      expect(isCommandAllowed('format')).toBe(false);
      expect(isCommandAllowed('sudo')).toBe(false);
      expect(isCommandAllowed('chmod')).toBe(false);
    });

    it('strictly forbids network exfiltration and download utilities', () => {
      expect(isCommandAllowed('curl')).toBe(false);
      expect(isCommandAllowed('wget')).toBe(false);
      expect(isCommandAllowed('ssh')).toBe(false);
      expect(isCommandAllowed('nc')).toBe(false);
      expect(isCommandAllowed('ftp')).toBe(false);
    });

    it('rejects path separators and path traversal in command names', () => {
      expect(isCommandAllowed('/bin/node')).toBe(false);
      expect(isCommandAllowed('..\\node')).toBe(false);
      expect(isCommandAllowed('C:\\Windows\\System32\\node.exe')).toBe(false);
    });
  });

  describe('Environment Sanitization', () => {
    it('filters out sensitive tokens and API keys from process.env', () => {
      const origAwsKey = process.env.AWS_SECRET_ACCESS_KEY;
      const origGithubToken = process.env.GITHUB_TOKEN;
      const origApiKey = process.env.OPENAI_API_KEY;

      process.env.AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
      process.env.GITHUB_TOKEN = 'ghp_secrettoken123456';
      process.env.OPENAI_API_KEY = 'sk-proj-supersecretkey';

      try {
        const sanitized = sanitizeEnvironment();
        expect(sanitized.AWS_SECRET_ACCESS_KEY).toBeUndefined();
        expect(sanitized.GITHUB_TOKEN).toBeUndefined();
        expect(sanitized.OPENAI_API_KEY).toBeUndefined();
        expect(sanitized.PATH).toBeDefined();
      } finally {
        if (origAwsKey !== undefined) process.env.AWS_SECRET_ACCESS_KEY = origAwsKey;
        else delete process.env.AWS_SECRET_ACCESS_KEY;
        if (origGithubToken !== undefined) process.env.GITHUB_TOKEN = origGithubToken;
        else delete process.env.GITHUB_TOKEN;
        if (origApiKey !== undefined) process.env.OPENAI_API_KEY = origApiKey;
        else delete process.env.OPENAI_API_KEY;
      }
    });

    it('rejects custom environment variables containing sensitive keywords', () => {
      expect(() => {
        sanitizeEnvironment({ MY_DATABASE_PASSWORD: 'password123' });
      }).toThrow(/contains sensitive secret keywords/i);

      expect(() => {
        sanitizeEnvironment({ SERVICE_ACCOUNT_KEY: 'secret-key' });
      }).toThrow(/contains sensitive secret keywords/i);

      expect(() => {
        sanitizeEnvironment({ AUTH_TOKEN: 'Bearer xyz' });
      }).toThrow(/contains sensitive secret keywords/i);
    });

    it('permits safe custom environment variables', () => {
      const sanitized = sanitizeEnvironment({ CI_BUILD_NUMBER: '42', FEATURE_FLAG: 'true' });
      expect(sanitized.CI_BUILD_NUMBER).toBe('42');
      expect(sanitized.FEATURE_FLAG).toBe('true');
    });
  });

  describe('Binary Invocation Resolution', () => {
    it('resolves node to process.execPath', () => {
      const res = resolveCommandInvocation('node', ['-v']);
      expect(res.binary).toBe(process.execPath);
      expect(res.finalArgs).toEqual(['-v']);
    });
  });

  describe('Process Execution & Sandbox Boundaries', () => {
    it('rejects unapproved commands', async () => {
      await expect(
        executeSandboxedCommand({
          command: 'bash',
          args: ['-c', 'echo test'],
          workspacePath: tempWorkspace,
        })
      ).rejects.toThrow(/Execution policy violation/i);
    });

    it('rejects null byte in command or arguments', async () => {
      await expect(
        executeSandboxedCommand({
          command: 'node\0',
          workspacePath: tempWorkspace,
        })
      ).rejects.toThrow(/null byte/i);

      await expect(
        executeSandboxedCommand({
          command: 'node',
          args: ['-e\0'],
          workspacePath: tempWorkspace,
        })
      ).rejects.toThrow(/null byte/i);
    });

    it('rejects cwd escaping workspace boundary', async () => {
      await expect(
        executeSandboxedCommand({
          command: 'node',
          args: ['-v'],
          cwd: '../../escape',
          workspacePath: tempWorkspace,
        })
      ).rejects.toThrow(/escapes workspace boundary/i);
    });

    it('executes a safe command successfully and captures output with duration', async () => {
      const res = await executeSandboxedCommand({
        command: 'node',
        args: ['-e', 'process.stdout.write("runner-success");'],
        workspacePath: tempWorkspace,
      });

      expect(res.exitCode).toBe(0);
      expect(res.stdout).toBe('runner-success');
      expect(res.stderr).toBe('');
      expect(res.timedOut).toBe(false);
      expect(res.provenance).toBe('server_executed');
      expect(res.durationMs).toBeGreaterThan(0);
    });

    it('captures non-zero exit codes accurately', async () => {
      const res = await executeSandboxedCommand({
        command: 'node',
        args: ['-e', 'process.stderr.write("failure msg"); process.exit(7);'],
        workspacePath: tempWorkspace,
      });

      expect(res.exitCode).toBe(7);
      expect(res.stderr).toContain('failure msg');
      expect(res.provenance).toBe('server_executed');
    });

    it('enforces execution timeout and terminates runaway processes', async () => {
      const res = await executeSandboxedCommand({
        command: 'node',
        args: ['-e', 'setInterval(() => {}, 1000);'],
        timeoutMs: 800,
        workspacePath: tempWorkspace,
      });

      expect(res.timedOut).toBe(true);
      expect(res.exitCode).toBe(124);
      expect(res.stderr).toContain('Process timed out');
    }, 15000);
  });

  describe('End-to-End MCP Server & Verifier Integration', () => {
    it('executes verified command via execute_verified_command and achieves verified bundle status', async () => {
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const server = createEvidenceServer();
      await server.connect(serverTransport);
      const client = new Client({ name: 'test-runner-client', version: '1.0.0' }, { capabilities: {} });
      await client.connect(clientTransport);

      try {
        // 1. Create bundle
        const createRes = (await client.callTool({
          name: 'create_evidence_bundle',
          arguments: {
            task: 'Run automated build and unit verification',
            workspacePath: tempWorkspace,
          },
        })) as { content: [{ type: 'text'; text: string }] };
        const { bundleId } = JSON.parse(createRes.content[0].text);

        // 2. Execute verified command
        const execRes = (await client.callTool({
          name: 'execute_verified_command',
          arguments: {
            bundleId,
            command: 'node',
            args: ['-e', 'console.log("build verified successfully");'],
            workspacePath: tempWorkspace,
          },
        })) as { content: [{ type: 'text'; text: string }] };

        const execData = JSON.parse(execRes.content[0].text);
        expect(execData.exitCode).toBe(0);
        expect(execData.provenance).toBe('server_executed');
        expect(execData.evidenceId).toBeDefined();

        // 3. Add assertion backed by server_executed command
        await client.callTool({
          name: 'add_assertion',
          arguments: {
            bundleId,
            claim: 'Automated build completed with exit 0',
            evidenceIds: [execData.evidenceId],
            workspacePath: tempWorkspace,
          },
        });

        // 4. Verify bundle
        const verifyRes = (await client.callTool({
          name: 'verify_evidence_bundle',
          arguments: { bundleId, workspacePath: tempWorkspace },
        })) as { content: [{ type: 'text'; text: string }] };

        const verifyData = JSON.parse(verifyRes.content[0].text);
        expect(verifyData.status).toBe('verified');
        expect(verifyData.summary).toContain('All assertions are backed by independently verified evidence');

        // Check command item status in verification items
        const cmdItem = verifyData.items.find((i: { id: string }) => i.id === execData.evidenceId);
        expect(cmdItem).toBeDefined();
        expect(cmdItem.status).toBe('verified');
        expect(cmdItem.details).toContain('Server-executed verified command succeeded');
      } finally {
        await client.close();
      }
    });

    it('marks bundle as failed when a server_executed command fails with non-zero exit code', async () => {
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const server = createEvidenceServer();
      await server.connect(serverTransport);
      const client = new Client({ name: 'test-runner-client', version: '1.0.0' }, { capabilities: {} });
      await client.connect(clientTransport);

      try {
        const createRes = (await client.callTool({
          name: 'create_evidence_bundle',
          arguments: {
            task: 'Verify failing test suite',
            workspacePath: tempWorkspace,
          },
        })) as { content: [{ type: 'text'; text: string }] };
        const { bundleId } = JSON.parse(createRes.content[0].text);

        const execRes = (await client.callTool({
          name: 'execute_verified_command',
          arguments: {
            bundleId,
            command: 'node',
            args: ['-e', 'process.exit(1);'],
            workspacePath: tempWorkspace,
          },
        })) as { content: [{ type: 'text'; text: string }] };

        const execData = JSON.parse(execRes.content[0].text);
        expect(execData.exitCode).toBe(1);

        await client.callTool({
          name: 'add_assertion',
          arguments: {
            bundleId,
            claim: 'Tests must pass',
            evidenceIds: [execData.evidenceId],
            workspacePath: tempWorkspace,
          },
        });

        const verifyRes = (await client.callTool({
          name: 'verify_evidence_bundle',
          arguments: { bundleId, workspacePath: tempWorkspace },
        })) as { content: [{ type: 'text'; text: string }] };

        const verifyData = JSON.parse(verifyRes.content[0].text);
        expect(verifyData.status).toBe('failed');
      } finally {
        await client.close();
      }
    });

    it('executes command via CLI exec command and saves verified evidence', async () => {
      // 1. Create a bundle file directly
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const server = createEvidenceServer();
      await server.connect(serverTransport);
      const client = new Client({ name: 'test-cli-client', version: '1.0.0' }, { capabilities: {} });
      await client.connect(clientTransport);

      let bundleId: string;
      try {
        const createRes = (await client.callTool({
          name: 'create_evidence_bundle',
          arguments: {
            task: 'CLI exec test',
            workspacePath: tempWorkspace,
          },
        })) as { content: [{ type: 'text'; text: string }] };
        bundleId = JSON.parse(createRes.content[0].text).bundleId;
      } finally {
        await client.close();
      }

      // 2. Invoke runCli with exec
      const exitCode = await runCli([
        'exec',
        bundleId,
        'node',
        '-e',
        'process.stdout.write("cli execution verified");',
        '--workspace',
        tempWorkspace,
      ]);

      expect(exitCode).toBe(0);

      // 3. Inspect saved bundle
      const bundle = await loadBundle(bundleId, tempWorkspace);
      expect(bundle.evidence.commands).toBeDefined();
      expect(bundle.evidence.commands!.length).toBe(1);
      const cmdEv = bundle.evidence.commands![0];
      expect(cmdEv.provenance).toBe('server_executed');
      expect(cmdEv.exitCode).toBe(0);
      expect(cmdEv.stdout).toContain('cli execution verified');
    });

    it('limits concurrent command executions with active process semaphore', async () => {
      setMaxRunnerConcurrency(2);

      const promises = [
        executeSandboxedCommand({
          command: 'node',
          args: ['-e', 'setTimeout(() => process.exit(0), 100)'],
          workspacePath: tempWorkspace,
        }),
        executeSandboxedCommand({
          command: 'node',
          args: ['-e', 'setTimeout(() => process.exit(0), 100)'],
          workspacePath: tempWorkspace,
        }),
        executeSandboxedCommand({
          command: 'node',
          args: ['-e', 'setTimeout(() => process.exit(0), 100)'],
          workspacePath: tempWorkspace,
        }),
      ];

      expect(getActiveRunnerProcesses()).toBeLessThanOrEqual(2);
      const results = await Promise.all(promises);
      expect(results.length).toBe(3);
      expect(results.every((r) => r.exitCode === 0)).toBe(true);

      // Reset to default
      setMaxRunnerConcurrency(4);
    });
  });
});
