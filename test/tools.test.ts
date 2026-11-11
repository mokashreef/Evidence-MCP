import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { createEvidenceServer } from '../src/server.js';

describe('Evidence MCP Server Tools Integration', () => {
  let tempWorkspace: string;
  let client: Client;
  let serverTransport: InMemoryTransport;
  let clientTransport: InMemoryTransport;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-e2e-'));
    const [cTrans, sTrans] = InMemoryTransport.createLinkedPair();
    clientTransport = cTrans;
    serverTransport = sTrans;

    const server = createEvidenceServer();
    await server.connect(serverTransport);

    client = new Client({ name: 'evidence-test-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  it('exposes all 21 expected tools', async () => {
    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);

    expect(names).toContain('create_evidence_bundle');
    expect(names).toContain('capture_git_evidence');
    expect(names).toContain('record_command_result');
    expect(names).toContain('snapshot_files');
    expect(names).toContain('add_assertion');
    expect(names).toContain('verify_evidence_bundle');
    expect(names).toContain('export_evidence_report');
    expect(names).toContain('sign_evidence_bundle');
    expect(names).toContain('execute_verified_command');
    expect(names).toContain('register_workspace');
    expect(names).toContain('capture_ast_evidence');
    expect(names).toContain('export_verification_proof');
    expect(names).toContain('verify_replay_proof');
    expect(names).toContain('endorse_evidence_bundle');
    expect(names).toContain('check_bundle_quorum');
    expect(names).toContain('evaluate_evidence_policy');
    expect(names).toContain('dispatch_webhook_audit');
    expect(names).toContain('register_trusted_agent');
    expect(names).toContain('revoke_trusted_agent');
    expect(names).toContain('capture_sbom_evidence');
    expect(names).toContain('notarize_evidence_bundle');
    expect(names.length).toBe(21);
  });

  it('executes the full end-to-end evidence lifecycle successfully', async () => {
    // 1. Create bundle
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Refactor calculateTotal function',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const bundleData = JSON.parse(createRes.content[0].text);
    const bundleId = bundleData.bundleId;
    expect(bundleId).toBeDefined();
    expect(bundleData.status).toBe('in_progress');

    // 2. Prepare sample workspace files
    const file1 = path.join(tempWorkspace, 'math.ts');
    await fs.promises.writeFile(file1, 'export function add(a: number, b: number) { return a + b; }\n', 'utf8');

    // 3. Snapshot files
    const snapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['math.ts'],
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const snapData = JSON.parse(snapRes.content[0].text);
    expect(snapData.snapshots.length).toBe(1);
    const fileEvidenceId = snapData.snapshots[0].evidenceId;
    expect(fileEvidenceId).toBeDefined();

    // 4. Record command result (agent-reported provenance)
    const cmdRes = (await client.callTool({
      name: 'record_command_result',
      arguments: {
        bundleId,
        command: 'npm run test:math',
        exitCode: 0,
        stdout: 'PASS test/math.test.ts',
        stderr: '',
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const cmdData = JSON.parse(cmdRes.content[0].text);
    const cmdEvidenceId = cmdData.evidenceId;
    expect(cmdEvidenceId).toBeDefined();
    expect(cmdData.provenance).toBe('agent_reported');

    // 5. Add assertion referencing evidence
    const assertRes = (await client.callTool({
      name: 'add_assertion',
      arguments: {
        bundleId,
        claim: 'add function is implemented and test suite passes',
        evidenceIds: [fileEvidenceId, cmdEvidenceId],
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const assertData = JSON.parse(assertRes.content[0].text);
    expect(assertData.assertionId).toBeDefined();

    // 6. Verify evidence bundle (backed by verified file evidence)
    const verifyRes = (await client.callTool({
      name: 'verify_evidence_bundle',
      arguments: {
        bundleId,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const verifyData = JSON.parse(verifyRes.content[0].text);
    expect(verifyData.status).toBe('verified');
    expect(verifyData.reasons.length).toBe(0);

    // 7. Export evidence report (Markdown)
    const exportMdRes = (await client.callTool({
      name: 'export_evidence_report',
      arguments: {
        bundleId,
        format: 'markdown',
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const mdReport = exportMdRes.content[0].text;
    expect(mdReport).toContain('# Evidence Bundle Report');
    expect(mdReport).toContain('Refactor calculateTotal function');
    expect(mdReport).toContain('add function is implemented');
    expect(mdReport).toContain('PASS test/math.test.ts');
    expect(mdReport).toContain('🟢 VERIFIED');
    expect(mdReport).toContain('agent_reported');

    // 8. Export evidence report (JSON)
    const exportJsonRes = (await client.callTool({
      name: 'export_evidence_report',
      arguments: {
        bundleId,
        format: 'json',
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const parsedJson = JSON.parse(exportJsonRes.content[0].text);
    expect(parsedJson.bundle.id).toBe(bundleId);
    expect(parsedJson.verification.status).toBe('verified');
  });

  it('marks bundle as unverifiable if assertion relies only on command evidence', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Command only task',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const cmdRes = (await client.callTool({
      name: 'record_command_result',
      arguments: {
        bundleId,
        command: 'echo test',
        exitCode: 0,
        stdout: 'ok',
        stderr: '',
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { evidenceId } = JSON.parse(cmdRes.content[0].text);

    await client.callTool({
      name: 'add_assertion',
      arguments: {
        bundleId,
        claim: 'Claim backed only by unverified command output',
        evidenceIds: [evidenceId],
      },
    });

    const verifyRes = (await client.callTool({
      name: 'verify_evidence_bundle',
      arguments: { bundleId },
    })) as { content: [{ type: 'text'; text: string }] };

    const verifyData = JSON.parse(verifyRes.content[0].text);
    expect(verifyData.status).toBe('unverifiable');
    expect(verifyData.reasons.some((r: string) => r.includes('agent-reported command evidence'))).toBe(true);
  });

  it('rejects snapshotting sensitive files and returns an error', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Security test',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    // Create a .env file
    await fs.promises.writeFile(path.join(tempWorkspace, '.env'), 'SECRET_KEY=12345');

    const snapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['.env'],
      },
    })) as { isError?: boolean; content: [{ type: 'text'; text: string }] };

    expect(snapRes.isError).toBe(true);
    expect(snapRes.content[0].text).toMatch(/sensitive file blocked/i);
  });

  it('rejects snapshotting paths outside workspace (path traversal)', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Path traversal test',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const snapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['../../etc/passwd'],
      },
    })) as { isError?: boolean; content: [{ type: 'text'; text: string }] };

    expect(snapRes.isError).toBe(true);
    expect(snapRes.content[0].text).toMatch(/Path traversal rejected/i);
  });

  it('rejects assertion referencing non-existent evidence IDs', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Assertion test',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const assertRes = (await client.callTool({
      name: 'add_assertion',
      arguments: {
        bundleId,
        claim: 'Bogus claim with non-existent evidence',
        evidenceIds: ['fake_evidence_id_123'],
      },
    })) as { isError?: boolean; content: [{ type: 'text'; text: string }] };

    expect(assertRes.isError).toBe(true);
    expect(assertRes.content[0].text).toMatch(/Referenced evidence IDs do not exist/i);
  });

  it('captures git evidence safely via capture_git_evidence', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execFileAsync = promisify(execFile);

    // Initialize git repo in workspace
    await execFileAsync('git', ['init', '-b', 'main'], { cwd: tempWorkspace });
    await execFileAsync('git', ['config', 'user.name', 'Test'], { cwd: tempWorkspace });
    await execFileAsync('git', ['config', 'user.email', 'test@example.com'], { cwd: tempWorkspace });
    await execFileAsync('git', ['commit', '--allow-empty', '-m', 'Initial commit'], { cwd: tempWorkspace });

    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Git test task',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const gitRes = (await client.callTool({
      name: 'capture_git_evidence',
      arguments: {
        bundleId,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const gitData = JSON.parse(gitRes.content[0].text);
    expect(gitData.evidenceId).toMatch(/^git_/);
    expect(gitData.branch).toBe('main');
    expect(gitData.headCommit).toBeDefined();
    expect(gitData.isClean).toBe(true);
  });
});
