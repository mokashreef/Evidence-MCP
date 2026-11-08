import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createEvidenceServer } from '../src/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { loadBundle, resolveWorkspaceForBundle } from '../src/storage.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { exportEvidenceReport } from '../src/reporter.js';
import { runCli } from '../src/cli.js';

describe('Multi-Workspace & Monorepo Support', () => {
  let rootWorkspace: string;
  let frontendDir: string;
  let backendDir: string;
  let client: Client;
  let serverTransport: InMemoryTransport;
  let clientTransport: InMemoryTransport;

  beforeEach(async () => {
    rootWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-monorepo-'));
    frontendDir = path.join(rootWorkspace, 'packages', 'frontend');
    backendDir = path.join(rootWorkspace, 'packages', 'backend');

    await fs.promises.mkdir(frontendDir, { recursive: true });
    await fs.promises.mkdir(backendDir, { recursive: true });

    [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createEvidenceServer();
    await server.connect(serverTransport);

    client = new Client({ name: 'test-monorepo-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(clientTransport);
  });

  afterEach(async () => {
    await client.close();
    await fs.promises.rm(rootWorkspace, { recursive: true, force: true });
  });

  it('creates bundle with additionalWorkspaces map', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Full-stack monorepo authentication feature',
        workspacePath: rootWorkspace,
        additionalWorkspaces: {
          frontend: './packages/frontend',
          backend: './packages/backend',
        },
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const data = JSON.parse(createRes.content[0].text);
    expect(data.bundleId).toBeDefined();
    expect(data.workspaces).toBeDefined();
    expect(data.workspaces.root).toBe(path.resolve(rootWorkspace));
    expect(data.workspaces.frontend).toBe(path.resolve(frontendDir));
    expect(data.workspaces.backend).toBe(path.resolve(backendDir));

    const loaded = await loadBundle(data.bundleId, rootWorkspace);
    expect(resolveWorkspaceForBundle(loaded, 'frontend')).toBe(path.resolve(frontendDir));
    expect(resolveWorkspaceForBundle(loaded, 'backend')).toBe(path.resolve(backendDir));
    expect(resolveWorkspaceForBundle(loaded)).toBe(path.resolve(rootWorkspace));
  });

  it('registers additional workspace dynamically via register_workspace tool', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Dynamic workspace addition test',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const regRes = (await client.callTool({
      name: 'register_workspace',
      arguments: {
        bundleId,
        name: 'shared_lib',
        path: './packages/frontend',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const regData = JSON.parse(regRes.content[0].text);
    expect(regData.workspaceName).toBe('shared_lib');
    expect(regData.allWorkspaces.shared_lib).toBe(path.resolve(frontendDir));

    const loaded = await loadBundle(bundleId, rootWorkspace);
    expect(loaded.workspaces?.shared_lib).toBe(path.resolve(frontendDir));
  });

  it('rejects invalid workspace names or non-existent directories', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Invalid workspace test',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    // Invalid name with special characters
    const invalidNameRes = (await client.callTool({
      name: 'register_workspace',
      arguments: {
        bundleId,
        name: 'frontend/invalid',
        path: './packages/frontend',
        workspacePath: rootWorkspace,
      },
    })) as { isError: boolean; content: [{ type: 'text'; text: string }] };
    expect(invalidNameRes.isError).toBe(true);

    // Non-existent directory
    const missingDirRes = (await client.callTool({
      name: 'register_workspace',
      arguments: {
        bundleId,
        name: 'ghost_pkg',
        path: './packages/does_not_exist',
        workspacePath: rootWorkspace,
      },
    })) as { isError: boolean; content: [{ type: 'text'; text: string }] };
    expect(missingDirRes.isError).toBe(true);
  });

  it('snapshots files within declared secondary workspaces with strict boundary confinement', async () => {
    // 1. Create files in subpackages
    const feFile = path.join(frontendDir, 'App.tsx');
    const beFile = path.join(backendDir, 'server.ts');
    await fs.promises.writeFile(feFile, 'export const App = () => <div>Hello</div>;', 'utf8');
    await fs.promises.writeFile(beFile, 'import http from "http";', 'utf8');

    // 2. Create bundle
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Multi-package file snapshot test',
        workspacePath: rootWorkspace,
        additionalWorkspaces: {
          frontend: './packages/frontend',
          backend: './packages/backend',
        },
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    // 3. Snapshot in frontend
    const feSnapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['App.tsx'],
        workspaceName: 'frontend',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const feSnapData = JSON.parse(feSnapRes.content[0].text);
    expect(feSnapData.snapshots[0].workspaceName).toBe('frontend');
    expect(feSnapData.snapshots[0].path).toBe('App.tsx');

    // 4. Snapshot in backend
    const beSnapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['server.ts'],
        workspaceName: 'backend',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const beSnapData = JSON.parse(beSnapRes.content[0].text);
    expect(beSnapData.snapshots[0].workspaceName).toBe('backend');

    // 5. Attempt path traversal outside frontend package boundary (should be rejected)
    const traverseRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['../backend/server.ts'],
        workspaceName: 'frontend',
        workspacePath: rootWorkspace,
      },
    })) as { isError: boolean };
    expect(traverseRes.isError).toBe(true);

    // 6. Verify bundle
    const bundle = await loadBundle(bundleId, rootWorkspace);
    bundle.assertions = [
      {
        id: 'assert_1',
        claim: 'Frontend and backend files are created',
        evidenceIds: [feSnapData.snapshots[0].evidenceId, beSnapData.snapshots[0].evidenceId],
        createdAt: new Date().toISOString(),
      },
    ];
    const verifyRes = await verifyEvidenceBundle(bundle);
    expect(verifyRes.status).toBe('verified');
  });

  it('detects modification in secondary workspace file and marks bundle as stale', async () => {
    const feFile = path.join(frontendDir, 'Button.tsx');
    await fs.promises.writeFile(feFile, 'export const Button = () => <button>Click</button>;', 'utf8');

    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Detect stale in subpackage',
        workspacePath: rootWorkspace,
        additionalWorkspaces: { frontend: './packages/frontend' },
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const snapRes = (await client.callTool({
      name: 'snapshot_files',
      arguments: {
        bundleId,
        paths: ['Button.tsx'],
        workspaceName: 'frontend',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { snapshots } = JSON.parse(snapRes.content[0].text);

    const bundle = await loadBundle(bundleId, rootWorkspace);
    bundle.assertions = [
      {
        id: 'assert_btn',
        claim: 'Button component implemented',
        evidenceIds: [snapshots[0].evidenceId],
        createdAt: new Date().toISOString(),
      },
    ];

    // Modify file
    await fs.promises.writeFile(feFile, 'export const Button = () => <button>Modified</button>;', 'utf8');

    const verifyRes = await verifyEvidenceBundle(bundle);
    expect(verifyRes.status).toBe('stale');
    expect(verifyRes.reasons.some((r) => r.includes('SHA-256 has changed'))).toBe(true);
  });

  it('executes verified command targeting a specific workspace', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Workspace-targeted command execution',
        workspacePath: rootWorkspace,
        additionalWorkspaces: { frontend: './packages/frontend' },
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const execRes = (await client.callTool({
      name: 'execute_verified_command',
      arguments: {
        bundleId,
        command: 'node',
        args: ['-e', 'console.log(process.cwd());'],
        workspaceName: 'frontend',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    const execData = JSON.parse(execRes.content[0].text);
    expect(execData.exitCode).toBe(0);
    expect(execData.workspaceName).toBe('frontend');
    expect(execData.stdoutPreview.toLowerCase()).toContain('frontend');
  });

  it('supports CLI workspace add and workspace list commands', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'CLI workspace management',
        workspacePath: rootWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    // Register via CLI
    const addCode = await runCli([
      'workspace',
      'add',
      bundleId,
      'core_api',
      './packages/backend',
      '--workspace',
      rootWorkspace,
    ]);
    expect(addCode).toBe(0);

    const bundle = await loadBundle(bundleId, rootWorkspace);
    expect(bundle.workspaces?.core_api).toBe(path.resolve(backendDir));

    // List via CLI
    const listCode = await runCli(['workspace', 'list', bundleId, '--workspace', rootWorkspace]);
    expect(listCode).toBe(0);
  });

  it('exports report with registered workspaces table in Markdown and HTML', async () => {
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'Report multi-workspace test',
        workspacePath: rootWorkspace,
        additionalWorkspaces: {
          client: './packages/frontend',
          server: './packages/backend',
        },
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    const bundle = await loadBundle(bundleId, rootWorkspace);
    const mdReport = exportEvidenceReport(bundle, 'markdown');
    expect(mdReport).toContain('## Registered Workspaces');
    expect(mdReport).toContain('client');
    expect(mdReport).toContain('server');

    const htmlReport = exportEvidenceReport(bundle, 'html');
    expect(htmlReport).toContain('Registered Workspaces');
  });
});
