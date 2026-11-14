import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import {
  verifyRfc6962InclusionProof,
  submitRekorLogEntry,
  verifyRekorEntryReceipt,
} from '../src/rekor.js';
import { EvidenceBundle, EvidencePolicy } from '../src/types.js';
import { saveBundle } from '../src/storage.js';
import { signEvidenceBundle } from '../src/attestation.js';
import { evaluateEvidencePolicy } from '../src/policy.js';
import { runCli } from '../src/cli.js';

describe('Sigstore Rekor Transparency Log Integration', () => {
  let tempWorkspace: string;
  let mockServer: http.Server;
  let serverPort: number;
  let logEntriesReceived: any[] = [];
  const MOCK_LOG_ID = 'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d';

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-rekor-test-'));
    logEntriesReceived = [];

    mockServer = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body);
          logEntriesReceived.push(parsed);

          const bundleDigest = parsed.spec?.data?.hash?.value || 'unknown_digest';
          // Compute a mock Merkle tree with 2 leaves: leaf0 = entry, leaf1 = sibling
          const leaf0 = crypto.createHash('sha256').update(bundleDigest).digest('hex');
          const leaf1 = crypto.createHash('sha256').update('sibling_leaf').digest('hex');
          const rootHash = crypto
            .createHash('sha256')
            .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(leaf0, 'hex'), Buffer.from(leaf1, 'hex')]))
            .digest('hex');

          const uuid = `${leaf0}${leaf0.slice(0, 16)}`; // 80-char Rekor UUID format
          const responsePayload = {
            [uuid]: {
              logID: MOCK_LOG_ID,
              logIndex: 0,
              integratedTime: Math.floor(Date.now() / 1000),
              body: Buffer.from(body).toString('base64'),
              verification: {
                signedEntryTimestamp: 'MEQCIQDg1234567890abcdef...',
                inclusionProof: {
                  logIndex: 0,
                  rootHash,
                  treeSize: 2,
                  hashes: [leaf1],
                  checkpoint: `rekor.example.com\n2\n${rootHash}\n`,
                },
              },
            },
          };

          res.writeHead(201, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(responsePayload));
        } catch (err: unknown) {
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: (err as Error).message }));
        }
      });
    });

    await new Promise<void>((resolve) => {
      mockServer.listen(0, '127.0.0.1', () => {
        serverPort = (mockServer.address() as any).port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    mockServer.close();
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  function createTestBundle(): EvidenceBundle {
    const now = new Date().toISOString();
    return {
      id: 'bundle_rekor123',
      task: 'Supply Chain Provenance Verification',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        git: [
          {
            id: 'git_1',
            type: 'git',
            capturedAt: now,
            branch: 'main',
            headCommit: 'a1b2c3d4e5f6',
            statusShort: '',
            diffCheck: '',
            isClean: true,
          },
        ],
        fileSnapshots: [
          {
            id: 'file_1',
            type: 'file_snapshot',
            capturedAt: now,
            path: 'src/main.ts',
            absolutePath: path.join(tempWorkspace, 'src', 'main.ts'),
            sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
            sizeBytes: 128,
          },
        ],
      },
      assertions: [
        {
          id: 'asrt_1',
          claim: 'Source code snapshotted and audited',
          evidenceIds: ['file_1'],
          createdAt: now,
        },
      ],
    };
  }

  describe('RFC 6962 Merkle Tree Inclusion Proof Verification', () => {
    it('verifies standard RFC 6962 audit path for 2-leaf tree', () => {
      const leaf0 = crypto.createHash('sha256').update('leaf0').digest('hex');
      const leaf1 = crypto.createHash('sha256').update('leaf1').digest('hex');
      const rootHash = crypto
        .createHash('sha256')
        .update(Buffer.concat([Buffer.from([0x01]), Buffer.from(leaf0, 'hex'), Buffer.from(leaf1, 'hex')]))
        .digest('hex');

      // Check leaf 0 inclusion
      const valid0 = verifyRfc6962InclusionProof(leaf0, 0, 2, [leaf1], rootHash);
      expect(valid0).toBe(true);

      // Check leaf 1 inclusion
      const valid1 = verifyRfc6962InclusionProof(leaf1, 1, 2, [leaf0], rootHash);
      expect(valid1).toBe(true);

      // Altered root fails
      expect(verifyRfc6962InclusionProof(leaf0, 0, 2, [leaf1], 'bad_root_12345')).toBe(false);

      // Out of bounds index fails
      expect(verifyRfc6962InclusionProof(leaf0, 2, 2, [leaf1], rootHash)).toBe(false);
    });
  });

  describe('Rekor Log Entry Submission & SSRF Protection', () => {
    it('blocks private network loopback without allowPrivateNetwork', async () => {
      const bundle = createTestBundle();
      await saveBundle(bundle);

      await expect(
        submitRekorLogEntry({
          bundleId: bundle.id,
          rekorUrl: `http://127.0.0.1:${serverPort}`,
          allowPrivateNetwork: false,
          workspacePath: tempWorkspace,
        })
      ).rejects.toThrow(/Blocked private or restricted network host/);
    });

    it('submits entry to Rekor, receives receipt, and verifies inclusion proof', async () => {
      const bundle = createTestBundle();
      await signEvidenceBundle(bundle);
      await saveBundle(bundle);

      const { receipt, alreadyExists } = await submitRekorLogEntry({
        bundleId: bundle.id,
        rekorUrl: `http://127.0.0.1:${serverPort}`,
        allowPrivateNetwork: true,
        workspacePath: tempWorkspace,
      });

      expect(alreadyExists).toBe(false);
      expect(receipt.bundleId).toBe(bundle.id);
      expect(receipt.logID).toBe(MOCK_LOG_ID);
      expect(receipt.uuid).toBeDefined();
      expect(receipt.inclusionProof).toBeDefined();
      expect(receipt.inclusionProof?.rootHash).toBeDefined();

      // Verify receipt locally
      const verifyRes = verifyRekorEntryReceipt({ receipt, bundle });
      expect(verifyRes.valid).toBe(true);
      expect(verifyRes.inclusionVerified).toBe(true);
    });

    it('detects tampering when bundle is modified after Rekor logging', async () => {
      const bundle = createTestBundle();
      await signEvidenceBundle(bundle);
      await saveBundle(bundle);

      const { receipt } = await submitRekorLogEntry({
        bundleId: bundle.id,
        rekorUrl: `http://127.0.0.1:${serverPort}`,
        allowPrivateNetwork: true,
        workspacePath: tempWorkspace,
      });

      // Modify bundle
      bundle.task = 'Tampered task name';

      const verifyRes = verifyRekorEntryReceipt({ receipt, bundle });
      expect(verifyRes.valid).toBe(false);
      expect(verifyRes.reason).toContain('bundle was modified after Rekor logging');
    });
  });

  describe('Policy Compliance Rules (requireRekor, minRekorCount, allowedRekorLogIds)', () => {
    it('enforces Rekor policy rules in evaluateEvidencePolicy', async () => {
      const bundle = createTestBundle();
      await signEvidenceBundle(bundle);
      await saveBundle(bundle);

      // 1. requireRekor fails when no entry attached
      let policy: EvidencePolicy = {
        attestation: { requireRekor: true },
      };
      let result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'attestation.requireRekor')?.passed).toBe(false);

      // 2. Attach valid entry
      const { receipt } = await submitRekorLogEntry({
        bundleId: bundle.id,
        bundle,
        rekorUrl: `http://127.0.0.1:${serverPort}`,
        allowPrivateNetwork: true,
        workspacePath: tempWorkspace,
      });

      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(true);
      expect(result.evaluations.find((e) => e.rule === 'attestation.requireRekor')?.passed).toBe(true);

      // 3. minRekorCount
      policy = {
        attestation: { minRekorCount: 2 },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'attestation.minRekorCount')?.passed).toBe(false);

      // 4. allowedRekorLogIds
      policy = {
        attestation: {
          allowedRekorLogIds: ['disallowed_log_id_123'],
        },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'attestation.allowedRekorLogIds')?.passed).toBe(false);

      policy = {
        attestation: {
          allowedRekorLogIds: [MOCK_LOG_ID],
        },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(true);
      expect(result.evaluations.find((e) => e.rule === 'attestation.allowedRekorLogIds')?.passed).toBe(true);
    });
  });

  describe('CLI Integration', () => {
    it('submits and verifies Rekor entries via evidence-mcp rekor submit & verify', async () => {
      const bundle = createTestBundle();
      await signEvidenceBundle(bundle);
      await saveBundle(bundle);

      // CLI submit
      const submitExit = await runCli([
        'rekor',
        'submit',
        bundle.id,
        `http://127.0.0.1:${serverPort}`,
        '--allow-private-network',
        '--workspace',
        tempWorkspace,
      ]);
      expect(submitExit).toBe(0);

      // CLI verify
      const verifyExit = await runCli([
        'rekor',
        'verify',
        bundle.id,
        '--workspace',
        tempWorkspace,
      ]);
      expect(verifyExit).toBe(0);
    });

    it('rejects unknown rekor sub-command', async () => {
      const exitCode = await runCli(['rekor', 'unknown', 'bundle_123']);
      expect(exitCode).toBe(1);
    });
  });
});
