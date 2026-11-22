import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import {
  computeWorkspaceDashboard,
  renderTerminalDashboard,
  getWorkspaceDashboard,
} from '../src/dashboard.js';
import { EvidenceBundle } from '../src/types.js';
import { saveBundle } from '../src/storage.js';
import { registerTrustedAgent } from '../src/registry.js';
import { generateKeyPairSync } from 'node:crypto';
import { createEvidenceServer } from '../src/server.js';
import { runCli } from '../src/cli.js';

describe('Interactive Terminal & Workspace Audit Dashboard', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-dashboard-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  it('computes empty dashboard metrics for a freshly initialized workspace', async () => {
    const data = await computeWorkspaceDashboard({ workspacePath: tempWorkspace });

    expect(data.workspacePath).toBe(path.resolve(tempWorkspace));
    expect(data.summary.totalBundles).toBe(0);
    expect(data.summary.verified).toBe(0);
    expect(data.summary.stale).toBe(0);
    expect(data.summary.failed).toBe(0);
    expect(data.summary.inProgress).toBe(0);
    expect(data.summary.unverifiable).toBe(0);

    expect(data.security.signedAttestations).toBe(0);
    expect(data.security.notaryReceipts).toBe(0);
    expect(data.security.rekorEntries).toBe(0);
    expect(data.security.activeTrustedAgents).toBe(0);
    expect(data.security.revokedAgents).toBe(0);
    expect(data.security.activePolicies).toBe(false);

    expect(data.breakdowns.totalAssertions).toBe(0);
    expect(data.breakdowns.totalSnapshots).toBe(0);
    expect(data.breakdowns.totalAstEvidence).toBe(0);
    expect(data.breakdowns.totalBreakingChanges).toBe(0);
    expect(data.breakdowns.totalCommandsExecuted).toBe(0);
    expect(data.breakdowns.totalSbomComponents).toBe(0);

    expect(data.recentBundles).toEqual([]);
  });

  it('accurately aggregates bundles, attestations, registry keys, and breaking changes', async () => {
    // 1. Create a dummy active policy file
    await fs.promises.writeFile(
      path.join(tempWorkspace, 'evidence.policy.json'),
      JSON.stringify({ version: '1' }),
      'utf8'
    );

    // 2. Register a trusted agent
    const { publicKey } = generateKeyPairSync('ed25519');
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const agent = await registerTrustedAgent({
      workspacePath: tempWorkspace,
      agentId: 'agent:sec-lead',
      name: 'Security Lead',
      role: 'security_auditor',
      publicKeyPem: pubPem,
    });

    // 3. Create Bundle 1 (Verified, signed, notarized, with AST breaking change & SBOM)
    const bundle1: EvidenceBundle = {
      id: 'bundle_test_01',
      task: 'Migrate cryptography module',
      workspacePath: tempWorkspace,
      status: 'verified',
      createdAt: '2026-11-20T10:00:00.000Z',
      updatedAt: '2026-11-20T10:30:00.000Z',
      attestation: {
        algorithm: 'ed25519',
        publicKeyPem: pubPem,
        keyFingerprint: agent.keyFingerprint,
        signedAt: '2026-11-20T10:30:00.000Z',
        signature: 'mock_sig_1',
      },
      notaryReceipts: [
        {
          id: 'notary_01',
          bundleId: 'bundle_test_01',
          bundleDigest: 'sha256_mock_01',
          notaryUrl: 'https://notary.example.com',
          notaryPublicKeyPem: pubPem,
          notaryKeyFingerprint: 'notary_fp_01',
          algorithm: 'ed25519',
          logIndex: 12,
          merkleLeafHash: 'leaf_hash_01',
          notarizedAt: '2026-11-20T10:31:00.000Z',
          signature: 'sig_notary_01',
        },
      ],
      rekorEntries: [
        {
          uuid: 'rekor_uuid_01',
          bundleId: 'bundle_test_01',
          bundleDigest: 'sha256_mock_01',
          rekorUrl: 'https://rekor.sigstore.dev',
          logIndex: 4001,
          logID: 'log_id_sigstore',
          integratedTime: 1763634000,
          signedEntryTimestamp: 'set_mock_01',
          recordedAt: '2026-11-20T10:32:00.000Z',
        },
      ],
      evidence: {
        fileSnapshots: [
          {
            id: 'file_01',
            type: 'file',
            capturedAt: '2026-11-20T10:05:00.000Z',
            path: 'src/crypto.ts',
            sha256: 'abc123hash',
            sizeBytes: 1024,
          },
        ],
        commands: [
          {
            id: 'cmd_01',
            type: 'command',
            capturedAt: '2026-11-20T10:10:00.000Z',
            command: 'npm test',
            exitCode: 0,
            stdout: 'PASS',
            stderr: '',
            provenance: 'server_executed',
          },
        ],
        ast: [
          {
            id: 'ast_01',
            type: 'ast',
            capturedAt: '2026-11-20T10:15:00.000Z',
            filePath: 'src/crypto.ts',
            language: 'typescript',
            symbolsCount: 5,
            symbols: [],
            diff: {
              filePath: 'src/crypto.ts',
              hasChanges: true,
              isBreakingChange: true,
              addedSymbols: [],
              removedSymbols: [],
              modifiedSymbols: [],
            },
          },
        ],
        sbom: [
          {
            id: 'sbom_01',
            type: 'sbom',
            capturedAt: '2026-11-20T10:20:00.000Z',
            format: 'cyclonedx-1.5',
            manifestPath: 'package.json',
            manifestSha256: 'man_sha',
            componentCount: 4,
            components: [
              { name: 'pkg-a', version: '1.0.0' },
              { name: 'pkg-b', version: '2.0.0' },
            ],
            licenseSummary: { MIT: 2 },
            bomDigest: 'bom_digest_01',
          },
        ],
      },
      assertions: [
        {
          id: 'assert_01',
          claim: 'Tests pass and crypto updated',
          evidenceIds: ['file_01', 'cmd_01'],
          createdAt: '2026-11-20T10:25:00.000Z',
        },
        {
          id: 'assert_02',
          claim: 'AST diff analyzed',
          evidenceIds: ['ast_01'],
          createdAt: '2026-11-20T10:26:00.000Z',
        },
      ],
    };

    // 4. Create Bundle 2 (Stale, unsigned)
    const bundle2: EvidenceBundle = {
      id: 'bundle_test_02',
      task: 'Fix styling bug',
      workspacePath: tempWorkspace,
      status: 'stale',
      createdAt: '2026-11-21T12:00:00.000Z',
      updatedAt: '2026-11-21T12:10:00.000Z',
      evidence: {
        fileSnapshots: [],
        commands: [],
      },
      assertions: [
        {
          id: 'assert_03',
          claim: 'Style adjusted',
          evidenceIds: ['file_dummy'],
          createdAt: '2026-11-21T12:05:00.000Z',
        },
      ],
    };

    await saveBundle(bundle1);
    await saveBundle(bundle2);

    const data = await computeWorkspaceDashboard({ workspacePath: tempWorkspace });

    expect(data.summary.totalBundles).toBe(2);
    expect(data.summary.verified).toBe(1);
    expect(data.summary.stale).toBe(1);
    expect(data.summary.failed).toBe(0);

    expect(data.security.activePolicies).toBe(true);
    expect(data.security.activeTrustedAgents).toBe(1);
    expect(data.security.revokedAgents).toBe(0);
    expect(data.security.signedAttestations).toBe(1);
    expect(data.security.notaryReceipts).toBe(1);
    expect(data.security.rekorEntries).toBe(1);

    expect(data.breakdowns.totalAssertions).toBe(3);
    expect(data.breakdowns.totalSnapshots).toBe(1);
    expect(data.breakdowns.totalCommandsExecuted).toBe(1);
    expect(data.breakdowns.totalAstEvidence).toBe(1);
    expect(data.breakdowns.totalBreakingChanges).toBe(1);
    expect(data.breakdowns.totalSbomComponents).toBe(4);

    expect(data.recentBundles.length).toBe(2);
    // Bundle 2 was created on Nov 21, so it appears first
    expect(data.recentBundles[0].id).toBe('bundle_test_02');
    expect(data.recentBundles[0].status).toBe('stale');
    expect(data.recentBundles[0].signed).toBe(false);

    // Bundle 1 was created on Nov 20, appears second
    expect(data.recentBundles[1].id).toBe('bundle_test_01');
    expect(data.recentBundles[1].status).toBe('verified');
    expect(data.recentBundles[1].signed).toBe(true);
    expect(data.recentBundles[1].signerRole).toBe('security_auditor');
    expect(data.recentBundles[1].notarized).toBe(true);
    expect(data.recentBundles[1].rekorAudit).toBe(true);
    expect(data.recentBundles[1].breakingChanges).toBe(1);
  });

  it('renders rich text terminal dashboard with and without ANSI color sequences', async () => {
    const data = await computeWorkspaceDashboard({ workspacePath: tempWorkspace });

    const coloredText = renderTerminalDashboard(data, { noColor: false });
    const plainText = renderTerminalDashboard(data, { noColor: true });

    expect(coloredText).toContain('\x1b[');
    expect(plainText).not.toContain('\x1b[');

    expect(plainText).toContain('EVIDENCE MCP — WORKSPACE SECURITY & AUDIT DASHBOARD');
    expect(plainText).toContain('[1] BUNDLE STATUS SUMMARY');
    expect(plainText).toContain('[2] CRYPTOGRAPHIC & SUPPLY-CHAIN SECURITY');
    expect(plainText).toContain('[3] EVIDENCE INVENTORY BREAKDOWNS');
    expect(plainText).toContain('[4] RECENT EVIDENCE BUNDLES');
  });

  it('supports getWorkspaceDashboard coordinator for json and text representations', async () => {
    const jsonRes = await getWorkspaceDashboard({
      workspacePath: tempWorkspace,
      format: 'json',
    });
    expect(typeof jsonRes.formatted).toBe('string');
    const parsed = JSON.parse(jsonRes.formatted);
    expect(parsed.summary.totalBundles).toBe(0);

    const textRes = await getWorkspaceDashboard({
      workspacePath: tempWorkspace,
      format: 'text',
      noColor: true,
    });
    expect(textRes.formatted).toContain('EVIDENCE MCP — WORKSPACE SECURITY & AUDIT DASHBOARD');
  });

  it('exposes get_workspace_dashboard tool on MCP server', async () => {
    const [cTrans, sTrans] = InMemoryTransport.createLinkedPair();
    const server = createEvidenceServer();
    await server.connect(sTrans);

    const client = new Client({ name: 'test-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(cTrans);

    const res = (await client.callTool({
      name: 'get_workspace_dashboard',
      arguments: {
        workspacePath: tempWorkspace,
        format: 'text',
        noColor: true,
      },
    })) as { content: [{ type: 'text'; text: string }] };

    expect(res.content[0].type).toBe('text');
    expect(res.content[0].text).toContain('EVIDENCE MCP — WORKSPACE SECURITY & AUDIT DASHBOARD');

    await client.close();
  });

  it('supports evidence-mcp dashboard CLI command with --json and --no-color flags', async () => {
    const codePlain = await runCli(['dashboard', tempWorkspace, '--no-color']);
    expect(codePlain).toBe(0);

    const codeJson = await runCli(['dashboard', tempWorkspace, '--json']);
    expect(codeJson).toBe(0);

    const codeInvalid = await runCli(['dashboard', '/invalid/path/that/does/not/exist/987654']);
    expect(codeInvalid).toBe(1);
  });
});
