import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
import {
  computeBundleDigest,
  createVerificationProof,
  verifyProofSignature,
  replayEvidenceBundle,
} from '../src/proof.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { createEvidenceServer } from '../src/server.js';
import { saveBundle, loadBundle, generateId, loadProof } from '../src/storage.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle } from '../src/types.js';

describe('Verification Proofs & Evidence Replay Engine', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-proof-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on Windows
    }
  });

  describe('computeBundleDigest', () => {
    it('produces a deterministic SHA-256 hash that changes if bundle evidence changes', () => {
      const bundle1: EvidenceBundle = {
        id: 'bundle_digest_1',
        task: 'Test task',
        workspacePath: tempDir,
        status: 'verified',
        createdAt: '2026-11-08T12:00:00.000Z',
        updatedAt: '2026-11-08T12:00:00.000Z',
        evidence: {
          fileSnapshots: [
            {
              id: 'file_1',
              type: 'file_snapshot',
              capturedAt: '2026-11-08T12:00:00.000Z',
              path: 'index.ts',
              absolutePath: path.join(tempDir, 'index.ts'),
              sha256: 'a'.repeat(64),
              sizeBytes: 100,
            },
          ],
        },
        assertions: [
          {
            id: 'assert_1',
            claim: 'File exists',
            evidenceIds: ['file_1'],
            createdAt: '2026-11-08T12:00:00.000Z',
          },
        ],
      };

      const digest1 = computeBundleDigest(bundle1);
      expect(digest1).toMatch(/^[a-f0-9]{64}$/);

      // Same content should yield identical digest
      const digest1Copy = computeBundleDigest({ ...bundle1 });
      expect(digest1Copy).toBe(digest1);

      // Modified content yields different digest
      const bundleModified: EvidenceBundle = {
        ...bundle1,
        assertions: [
          {
            id: 'assert_1',
            claim: 'File exists and is modified',
            evidenceIds: ['file_1'],
            createdAt: '2026-11-08T12:00:00.000Z',
          },
        ],
      };
      const digestModified = computeBundleDigest(bundleModified);
      expect(digestModified).not.toBe(digest1);
    });
  });

  describe('createVerificationProof & verifyProofSignature', () => {
    it('creates a signed proof and verifies cryptographic authenticity and bundle digest', async () => {
      const testFile = path.join(tempDir, 'data.ts');
      fs.writeFileSync(testFile, 'export const value = 42;\n');
      const hashInfo = await computeFileSha256AndSize(testFile);

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Export proof test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          fileSnapshots: [
            {
              id: generateId('file'),
              type: 'file_snapshot',
              capturedAt: new Date().toISOString(),
              path: 'data.ts',
              absolutePath: testFile,
              sha256: hashInfo.sha256,
              sizeBytes: hashInfo.sizeBytes,
            },
          ],
        },
        assertions: [],
      };
      bundle.assertions.push({
        id: generateId('assert'),
        claim: 'data.ts is captured',
        evidenceIds: [bundle.evidence.fileSnapshots![0].id],
        createdAt: new Date().toISOString(),
      });

      await saveBundle(bundle);

      const verification = await verifyEvidenceBundle(bundle);
      expect(verification.status).toBe('verified');

      const proof = await createVerificationProof({
        bundle,
        verification,
        workspacePath: tempDir,
      });

      expect(proof.id).toMatch(/^proof_/);
      expect(proof.verdict).toBe('verified');
      expect(proof.signature).toBeDefined();
      expect(proof.signer.keyFingerprint).toMatch(/^[a-f0-9]{64}$/);

      // Verify proof signature against current bundle
      const check = verifyProofSignature(proof, bundle);
      expect(check.valid).toBe(true);
      expect(check.bundleDigestMatches).toBe(true);

      // Verify loaded proof from disk
      const loadedProof = await loadProof(proof.id, tempDir);
      expect(loadedProof.id).toBe(proof.id);
      expect(loadedProof.signature).toBe(proof.signature);

      // Tamper test: modify bundle assertion and check that bundleDigestMatches fails
      const tamperedBundle: EvidenceBundle = {
        ...bundle,
        task: 'Tampered task name',
      };
      const tamperedCheck = verifyProofSignature(proof, tamperedBundle);
      expect(tamperedCheck.valid).toBe(false);
      expect(tamperedCheck.bundleDigestMatches).toBe(false);
      expect(tamperedCheck.reason).toContain('Bundle digest mismatch');
    });

    it('fails verification if proof signature is forged or corrupted', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Forged proof test',
        workspacePath: tempDir,
        status: 'verified',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      const verification = {
        bundleId: bundle.id,
        status: 'verified' as const,
        verifiedAt: new Date().toISOString(),
        summary: 'All good',
        reasons: [],
        items: [],
      };

      const proof = await createVerificationProof({
        bundle,
        verification,
        workspacePath: tempDir,
      });

      // Corrupt signature
      const forgedProof = {
        ...proof,
        signature: Buffer.from('bad_signature_data').toString('base64'),
      };

      const check = verifyProofSignature(forgedProof, bundle);
      expect(check.valid).toBe(false);
      expect(check.reason).toContain('Proof signature verification failed');
    });
  });

  describe('replayEvidenceBundle', () => {
    it('replays all evidence items sequentially and flags divergence when file changes', async () => {
      // Initialize Git repo
      execSync('git init -b main', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.name "Test"', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.email "test@example.com"', { cwd: tempDir, stdio: 'ignore' });

      const testFile = path.join(tempDir, 'main.ts');
      fs.writeFileSync(testFile, 'export function run(): void {}\n');
      const hashInfo = await computeFileSha256AndSize(testFile);
      execSync('git add main.ts', { cwd: tempDir, stdio: 'ignore' });
      execSync('git commit -m "initial commit"', { cwd: tempDir, stdio: 'ignore' });

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Replay test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          git: [
            {
              id: generateId('git'),
              type: 'git',
              capturedAt: '2026-11-08T10:00:00.000Z',
              branch: 'main',
              headCommit: execSync('git rev-parse HEAD', { cwd: tempDir, encoding: 'utf8' }).trim(),
              statusShort: '',
              diffCheck: '',
              isClean: true,
            },
          ],
          fileSnapshots: [
            {
              id: generateId('file'),
              type: 'file_snapshot',
              capturedAt: '2026-11-08T10:05:00.000Z',
              path: 'main.ts',
              absolutePath: testFile,
              sha256: hashInfo.sha256,
              sizeBytes: hashInfo.sizeBytes,
            },
          ],
          commands: [
            {
              id: generateId('cmd'),
              type: 'command',
              recordedAt: '2026-11-08T10:10:00.000Z',
              command: 'node --version',
              exitCode: 0,
              stdout: 'v20.0.0',
              stderr: '',
              provenance: 'server_executed',
            },
          ],
        },
        assertions: [],
      };
      await saveBundle(bundle);

      // Replay clean bundle
      const replay1 = await replayEvidenceBundle(bundle, { workspacePath: tempDir });
      expect(replay1.totalSteps).toBe(3);
      expect(replay1.passedSteps).toBe(3);
      expect(replay1.divergedSteps).toBe(0);
      expect(replay1.isReproducible).toBe(true);
      expect(replay1.steps.every((s) => s.status === 'passed')).toBe(true);

      // Now alter file on disk
      fs.writeFileSync(testFile, 'export function run(): boolean { return true; }\n');

      // Replay again: should detect file step divergence
      const replay2 = await replayEvidenceBundle(bundle, { workspacePath: tempDir });
      expect(replay2.divergedSteps).toBe(1);
      expect(replay2.isReproducible).toBe(false);
      const fileStep = replay2.steps.find((s) => s.type === 'file');
      expect(fileStep?.status).toBe('diverged');
    });

    it('re-executes server_executed commands when reExecuteCommands is enabled', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Re-execute command test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          commands: [
            {
              id: generateId('cmd'),
              type: 'command',
              recordedAt: new Date().toISOString(),
              command: 'node',
              args: ['-e', 'process.stdout.write("deterministic-test")'],
              exitCode: 0,
              stdout: 'deterministic-test',
              stderr: '',
              provenance: 'server_executed',
            },
          ],
        },
        assertions: [],
      };
      await saveBundle(bundle);

      const replay = await replayEvidenceBundle(bundle, {
        reExecuteCommands: true,
        workspacePath: tempDir,
      });

      expect(replay.steps.length).toBe(1);
      expect(replay.steps[0].status).toBe('passed');
      expect(replay.steps[0].reproducedExecution?.exitCodeMatches).toBe(true);
      expect(replay.isReproducible).toBe(true);
    });
  });

  describe('MCP Tools: export_verification_proof & verify_replay_proof', () => {
    it('creates and verifies proofs end-to-end via MCP tools', async () => {
      const testFile = path.join(tempDir, 'app.ts');
      fs.writeFileSync(testFile, 'export const alive = true;\n');

      const server = createEvidenceServer();

      // Create bundle
      const createRes = await (server as any)._registeredTools['create_evidence_bundle'].handler({
        task: 'MCP Proof Lifecycle Test',
        workspacePath: tempDir,
      });
      const bundleId = JSON.parse(createRes.content[0].text).bundleId;

      // Snapshot file
      const snapRes = await (server as any)._registeredTools['snapshot_files'].handler({
        bundleId,
        paths: ['app.ts'],
        workspacePath: tempDir,
      });
      const fileId = JSON.parse(snapRes.content[0].text).snapshots[0].evidenceId;

      // Add assertion
      await (server as any)._registeredTools['add_assertion'].handler({
        bundleId,
        claim: 'app.ts is alive',
        evidenceIds: [fileId],
        workspacePath: tempDir,
      });

      // Export verification proof via Tool 12
      const proofRes = await (server as any)._registeredTools['export_verification_proof'].handler({
        bundleId,
        workspacePath: tempDir,
      });
      expect(proofRes.isError).toBeUndefined();
      const proofData = JSON.parse(proofRes.content[0].text);
      expect(proofData.proofId).toMatch(/^proof_/);
      expect(proofData.verdict).toBe('verified');
      expect(proofData.bundleDigest).toBeDefined();

      // Verify proof via Tool 13 with proofId
      const verifyRes = await (server as any)._registeredTools['verify_replay_proof'].handler({
        proofId: proofData.proofId,
        workspacePath: tempDir,
      });
      expect(verifyRes.isError).toBeUndefined();
      const verifyData = JSON.parse(verifyRes.content[0].text);
      expect(verifyData.valid).toBe(true);
      expect(verifyData.bundleDigestMatches).toBe(true);
      expect(verifyData.verdict).toBe('verified');
    });
  });

  describe('CLI Commands: proof & replay', () => {
    it('executes proof create, proof verify, and replay commands successfully via CLI', async () => {
      const testFile = path.join(tempDir, 'module.ts');
      fs.writeFileSync(testFile, 'export const magic = 100;\n');
      const hashInfo = await computeFileSha256AndSize(testFile);

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'CLI Proof & Replay Task',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          fileSnapshots: [
            {
              id: generateId('file'),
              type: 'file_snapshot',
              capturedAt: new Date().toISOString(),
              path: 'module.ts',
              absolutePath: testFile,
              sha256: hashInfo.sha256,
              sizeBytes: hashInfo.sizeBytes,
            },
          ],
        },
        assertions: [],
      };
      bundle.assertions.push({
        id: generateId('assert'),
        claim: 'module.ts verified',
        evidenceIds: [bundle.evidence.fileSnapshots![0].id],
        createdAt: new Date().toISOString(),
      });
      await saveBundle(bundle);

      const proofOut = path.join(tempDir, 'proof.json');

      // 1. CLI proof create
      const createCode = await runCli([
        'proof',
        'create',
        bundle.id,
        '--workspace',
        tempDir,
        '--output',
        proofOut,
      ]);
      expect(createCode).toBe(0);
      expect(fs.existsSync(proofOut)).toBe(true);

      // 2. CLI proof verify
      const verifyCode = await runCli([
        'proof',
        'verify',
        proofOut,
        '--workspace',
        tempDir,
      ]);
      expect(verifyCode).toBe(0);

      // 3. CLI replay
      const replayCode = await runCli([
        'replay',
        bundle.id,
        '--workspace',
        tempDir,
      ]);
      expect(replayCode).toBe(0);
    });
  });
});
