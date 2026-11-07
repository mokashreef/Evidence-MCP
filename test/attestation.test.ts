import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  generateAgentKeyPair,
  computeKeyFingerprint,
  signEvidenceBundle,
  verifyBundleAttestation,
  getCanonicalPayload,
} from '../src/attestation.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { saveBundle, loadBundle } from '../src/storage.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle } from '../src/types.js';
import { createEvidenceServer } from '../src/server.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

describe('Ed25519 Cryptographic Attestation', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-attest-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('generates a valid Ed25519 keypair with SHA-256 fingerprint', () => {
    const keyPair = generateAgentKeyPair();
    expect(keyPair.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(keyPair.privateKeyPem).toContain('BEGIN PRIVATE KEY');
    expect(keyPair.fingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(computeKeyFingerprint(keyPair.publicKeyPem)).toBe(keyPair.fingerprint);
  });

  it('produces identical canonical payloads regardless of object key order', () => {
    const bundle1: EvidenceBundle = {
      id: 'bundle_canon_1',
      task: 'Deterministic task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: '2026-11-07T12:00:00Z',
      updatedAt: '2026-11-07T12:00:00Z',
      evidence: {
        commands: [
          {
            id: 'cmd_1',
            type: 'command',
            recordedAt: '2026-11-07T12:00:00Z',
            command: 'npm test',
            exitCode: 0,
            stdout: 'pass',
            stderr: '',
            provenance: 'agent_reported',
          },
        ],
      },
      assertions: [
        {
          id: 'assert_1',
          claim: 'Tested',
          evidenceIds: ['cmd_1'],
          createdAt: '2026-11-07T12:00:00Z',
        },
      ],
    };

    // Reconstruct bundle with different key order
    const bundle2: EvidenceBundle = {
      status: 'in_progress',
      updatedAt: '2026-11-07T13:45:00Z', // Should be ignored in canonical payload!
      task: 'Deterministic task',
      id: 'bundle_canon_1',
      assertions: [
        {
          createdAt: '2026-11-07T12:00:00Z',
          claim: 'Tested',
          id: 'assert_1',
          evidenceIds: ['cmd_1'],
        },
      ],
      workspacePath: tempWorkspace,
      createdAt: '2026-11-07T12:00:00Z',
      evidence: {
        commands: [
          {
            stderr: '',
            stdout: 'pass',
            provenance: 'agent_reported',
            exitCode: 0,
            command: 'npm test',
            recordedAt: '2026-11-07T12:00:00Z',
            type: 'command',
            id: 'cmd_1',
          },
        ],
      },
    };

    const payload1 = getCanonicalPayload(bundle1);
    const payload2 = getCanonicalPayload(bundle2);
    expect(payload1.toString('utf8')).toBe(payload2.toString('utf8'));
  });

  it('signs and verifies an unaltered bundle successfully', async () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_sign_ok',
      task: 'Authentic task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {},
      assertions: [
        {
          id: 'assert_sign',
          claim: 'Authentic work',
          evidenceIds: ['some_id'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    const attestation = await signEvidenceBundle(bundle);
    expect(attestation.algorithm).toBe('ed25519');
    expect(attestation.signature).toBeDefined();
    expect(attestation.keyFingerprint).toMatch(/^[a-f0-9]{64}$/);

    const check = verifyBundleAttestation(bundle);
    expect(check.valid).toBe(true);
  });

  it('detects tampering and fails attestation verification if bundle content is modified', async () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_tamper_test',
      task: 'Original authentic task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {},
      assertions: [
        {
          id: 'assert_1',
          claim: 'Original claim',
          evidenceIds: ['id1'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await signEvidenceBundle(bundle);
    expect(verifyBundleAttestation(bundle).valid).toBe(true);

    // Tamper with the task!
    bundle.task = 'Maliciously altered task description';
    const checkTaskTamper = verifyBundleAttestation(bundle);
    expect(checkTaskTamper.valid).toBe(false);
    expect(checkTaskTamper.reason).toContain('signature mismatch');

    // Restore task, but tamper with assertions!
    bundle.task = 'Original authentic task';
    bundle.assertions[0].claim = 'Fake claim added after signing';
    const checkClaimTamper = verifyBundleAttestation(bundle);
    expect(checkClaimTamper.valid).toBe(false);
  });

  it('verifies signed bundle through verifyEvidenceBundle engine', async () => {
    const filePath = path.join(tempWorkspace, 'code.ts');
    await fs.promises.writeFile(filePath, 'export const valid = true;\n', 'utf8');

    const crypto = await import('node:crypto');
    const hash = crypto.createHash('sha256').update('export const valid = true;\n').digest('hex');

    const bundle: EvidenceBundle = {
      id: 'bundle_engine_sign',
      task: 'Engine signature test',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_code',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'code.ts',
            absolutePath: filePath,
            sha256: hash,
            sizeBytes: 28,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_code',
          claim: 'Code valid',
          evidenceIds: ['file_code'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await signEvidenceBundle(bundle);
    await saveBundle(bundle);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('verified');

    const attestItem = result.items.find((i) => i.type === 'attestation');
    expect(attestItem?.status).toBe('verified');
    expect(attestItem?.details).toContain('Ed25519 signature verified');

    // Now tamper with the bundle file directly on disk!
    const loaded = await loadBundle(bundle.id, tempWorkspace);
    loaded.task = 'Tampered on disk!';
    await saveBundle(loaded);

    const tamperedResult = await verifyEvidenceBundle(loaded);
    expect(tamperedResult.status).toBe('failed');
    const tamperedItem = tamperedResult.items.find((i) => i.type === 'attestation');
    expect(tamperedItem?.status).toBe('failed');
    expect(tamperedResult.reasons.some((r) => r.includes('Attestation failure'))).toBe(true);
  });

  it('exposes sign_evidence_bundle tool in MCP Server', async () => {
    const [cTrans, sTrans] = InMemoryTransport.createLinkedPair();
    const server = createEvidenceServer();
    await server.connect(sTrans);

    const client = new Client({ name: 'attestation-test-client', version: '1.0.0' }, { capabilities: {} });
    await client.connect(cTrans);

    const tools = await client.listTools();
    const names = tools.tools.map((t) => t.name);
    expect(names).toContain('sign_evidence_bundle');

    // Create a bundle
    const createRes = (await client.callTool({
      name: 'create_evidence_bundle',
      arguments: {
        task: 'MCP Sign Task',
        workspacePath: tempWorkspace,
      },
    })) as { content: [{ type: 'text'; text: string }] };
    const { bundleId } = JSON.parse(createRes.content[0].text);

    // Call sign_evidence_bundle
    const signRes = (await client.callTool({
      name: 'sign_evidence_bundle',
      arguments: { bundleId },
    })) as { content: [{ type: 'text'; text: string }] };

    const signData = JSON.parse(signRes.content[0].text);
    expect(signData.algorithm).toBe('ed25519');
    expect(signData.keyFingerprint).toMatch(/^[a-f0-9]{64}$/);
    expect(signData.message).toContain('cryptographically signed');

    await client.close();
  });

  it('supports evidence-mcp sign command in CLI', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const bundle: EvidenceBundle = {
      id: 'bundle_cli_sign_test',
      task: 'Sign via CLI',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {},
      assertions: [],
    };
    await saveBundle(bundle);

    const exitCode = await runCli(['sign', 'bundle_cli_sign_test', '--workspace', tempWorkspace]);
    expect(exitCode).toBe(0);

    const loaded = await loadBundle('bundle_cli_sign_test', tempWorkspace);
    expect(loaded.attestation).toBeDefined();
    expect(loaded.attestation?.algorithm).toBe('ed25519');
  });
});
