import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  createPeerEndorsement,
  verifyPeerEndorsement,
  checkBundleQuorum,
} from '../src/consensus.js';
import { generateGitHubStepSummary, writeToGitHubStepSummary } from '../src/github-summary.js';
import { createEvidenceServer } from '../src/server.js';
import { saveBundle, loadBundle, generateId } from '../src/storage.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle } from '../src/types.js';

describe('Multi-Agent Consensus & Quorum Endorsement Protocol', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-consensus-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error on Windows
    }
    vi.restoreAllMocks();
  });

  describe('createPeerEndorsement & verifyPeerEndorsement', () => {
    it('creates, cryptographically signs, and verifies a peer endorsement', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Consensus review task',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      const endorsement = await createPeerEndorsement({
        bundle,
        agentId: 'agent:qa-tester-01',
        role: 'tester',
        verdict: 'approved',
        comment: 'All unit and integration tests passed with 100% coverage.',
        workspacePath: tempDir,
      });

      expect(endorsement.id).toMatch(/^endorse_/);
      expect(endorsement.agentId).toBe('agent:qa-tester-01');
      expect(endorsement.role).toBe('tester');
      expect(endorsement.verdict).toBe('approved');
      expect(endorsement.signature).toBeDefined();
      expect(endorsement.signer.keyFingerprint).toMatch(/^[a-f0-9]{64}$/);

      // Verify endorsement against bundle
      const check = verifyPeerEndorsement(endorsement, bundle);
      expect(check.valid).toBe(true);
      expect(check.bundleDigestMatches).toBe(true);

      // Tamper test: bundle modified after endorsement
      const tamperedBundle: EvidenceBundle = {
        ...bundle,
        task: 'Altered task',
      };
      const checkTampered = verifyPeerEndorsement(endorsement, tamperedBundle);
      expect(checkTampered.valid).toBe(false);
      expect(checkTampered.bundleDigestMatches).toBe(false);
      expect(checkTampered.reason).toContain('Bundle digest mismatch');
    });

    it('rejects an endorsement with corrupted signature', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Invalid endorsement test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      const endorsement = await createPeerEndorsement({
        bundle,
        agentId: 'agent:peer-reviewer',
        role: 'peer_reviewer',
        verdict: 'approved',
        comment: 'Looks good.',
        workspacePath: tempDir,
      });

      const corrupted = {
        ...endorsement,
        signature: Buffer.from('forged_sig').toString('base64'),
      };

      const check = verifyPeerEndorsement(corrupted, bundle);
      expect(check.valid).toBe(false);
      expect(check.reason).toContain('Cryptographic signature mismatch');
    });
  });

  describe('checkBundleQuorum', () => {
    it('satisfies quorum when minimum approved endorsements and required roles are met', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Quorum satisfaction test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      // Endorsement 1: Tester
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:tester-v1',
        role: 'tester',
        verdict: 'approved',
        comment: 'Tests verified.',
        workspacePath: tempDir,
      });

      // Endorsement 2: Security Auditor
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:security-auditor-v1',
        role: 'security_auditor',
        verdict: 'approved',
        comment: 'No vulnerabilities or secrets detected.',
        workspacePath: tempDir,
      });

      const quorum = checkBundleQuorum(bundle, {
        minEndorsements: 2,
        requiredRoles: ['tester', 'security_auditor'],
        requireUniqueSigners: false, // In test they use the workspace local key
      });

      expect(quorum.satisfied).toBe(true);
      expect(quorum.approvedCount).toBe(2);
      expect(quorum.rejectionsCount).toBe(0);
      expect(quorum.verifiedSignatures).toBe(2);
      expect(quorum.reasons.length).toBe(0);
    });

    it('fails quorum if an explicit rejection exists', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Quorum rejection veto test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      // Endorsement 1: Approved by tester
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:tester',
        role: 'tester',
        verdict: 'approved',
        comment: 'Tests pass.',
        workspacePath: tempDir,
      });

      // Endorsement 2: Rejected by security auditor
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:security',
        role: 'security_auditor',
        verdict: 'rejected',
        comment: 'Hardcoded secret found in config.',
        workspacePath: tempDir,
      });

      const quorum = checkBundleQuorum(bundle, {
        minEndorsements: 1,
        disallowRejections: true,
        requireUniqueSigners: false,
      });

      expect(quorum.satisfied).toBe(false);
      expect(quorum.rejectionsCount).toBe(1);
      expect(quorum.reasons.some((r) => r.includes('explicit rejection'))).toBe(true);
    });

    it('fails quorum if required role is missing', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Missing role test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      await createPeerEndorsement({
        bundle,
        agentId: 'agent:architect',
        role: 'architect',
        verdict: 'approved',
        comment: 'Architecture matches specification.',
        workspacePath: tempDir,
      });

      const quorum = checkBundleQuorum(bundle, {
        minEndorsements: 1,
        requiredRoles: ['security_auditor'],
        requireUniqueSigners: false,
      });

      expect(quorum.satisfied).toBe(false);
      expect(quorum.reasons.some((r) => r.includes('Missing required endorsement role'))).toBe(true);
    });
  });

  describe('MCP Tools: endorse_evidence_bundle & check_bundle_quorum', () => {
    it('records endorsement and checks quorum through MCP server tools', async () => {
      const server = createEvidenceServer();

      // Create bundle
      const createRes = await (server as any)._registeredTools['create_evidence_bundle'].handler({
        task: 'MCP Consensus Lifecycle Test',
        workspacePath: tempDir,
      });
      const bundleId = JSON.parse(createRes.content[0].text).bundleId;

      // Endorse bundle via Tool 14
      const endorseRes = await (server as any)._registeredTools['endorse_evidence_bundle'].handler({
        bundleId,
        agentId: 'agent:mcp-peer-reviewer',
        role: 'peer_reviewer',
        verdict: 'approved',
        comment: 'Verified cleanly via tool.',
        workspacePath: tempDir,
      });
      expect(endorseRes.isError).toBeUndefined();
      const endorseData = JSON.parse(endorseRes.content[0].text);
      expect(endorseData.endorsementId).toMatch(/^endorse_/);
      expect(endorseData.verdict).toBe('approved');

      // Check quorum via Tool 15
      const quorumRes = await (server as any)._registeredTools['check_bundle_quorum'].handler({
        bundleId,
        minEndorsements: 1,
        requireUniqueSigners: false,
        workspacePath: tempDir,
      });
      expect(quorumRes.isError).toBeUndefined();
      const quorumData = JSON.parse(quorumRes.content[0].text);
      expect(quorumData.satisfied).toBe(true);
      expect(quorumData.approvedCount).toBe(1);
    });
  });

  describe('GitHub Step Summary & Reporting', () => {
    it('generates rich GitHub Actions markdown summary with quorum and endorsements', async () => {
      const testFile = path.join(tempDir, 'service.ts');
      fs.writeFileSync(testFile, 'export function compute(): number { return 100; }\n');
      const hashInfo = await computeFileSha256AndSize(testFile);

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Deploy high-availability cache service',
        workspacePath: tempDir,
        status: 'verified',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          fileSnapshots: [
            {
              id: generateId('file'),
              type: 'file_snapshot',
              capturedAt: new Date().toISOString(),
              path: 'service.ts',
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
        claim: 'service.ts verified',
        evidenceIds: [bundle.evidence.fileSnapshots![0].id],
        createdAt: new Date().toISOString(),
      });

      await createPeerEndorsement({
        bundle,
        agentId: 'agent:lead-architect',
        role: 'architect',
        verdict: 'approved',
        comment: 'High availability design verified.',
        workspacePath: tempDir,
      });

      const verification = await verifyEvidenceBundle(bundle);
      const quorum = checkBundleQuorum(bundle, { minEndorsements: 1, requireUniqueSigners: false });

      const summary = generateGitHubStepSummary({
        bundle,
        verification,
        quorum,
      });

      expect(summary).toContain('Evidence MCP — Audit Summary');
      expect(summary).toContain('Deploy high-availability cache service');
      expect(summary).toContain('Multi-Agent Peer Endorsements');
      expect(summary).toContain('agent:lead-architect');
      expect(summary).toContain('Consensus Quorum');
      expect(summary).toContain('SATISFIED');

      // Test writing to GitHub Step Summary file
      const summaryFile = path.join(tempDir, 'step_summary.md');
      process.env.GITHUB_STEP_SUMMARY = summaryFile;

      const wrote = await writeToGitHubStepSummary(summary);
      expect(wrote).toBe(true);
      expect(fs.existsSync(summaryFile)).toBe(true);
      const fileContent = fs.readFileSync(summaryFile, 'utf8');
      expect(fileContent).toContain('Evidence MCP — Audit Summary');
      delete process.env.GITHUB_STEP_SUMMARY;
    });

    it('supports evidence-mcp endorse, quorum, and summary CLI commands', async () => {
      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'CLI Consensus & Summary Test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      // 1. CLI endorse
      const endorseCode = await runCli([
        'endorse',
        bundle.id,
        '--agent',
        'agent:qa-bot',
        '--role',
        'tester',
        '--verdict',
        'approved',
        '--comment',
        'Tests pass cleanly via CLI',
        '--workspace',
        tempDir,
      ]);
      expect(endorseCode).toBe(0);

      // 2. CLI quorum
      const quorumCode = await runCli([
        'quorum',
        bundle.id,
        '--min',
        '1',
        '--workspace',
        tempDir,
      ]);
      expect(quorumCode).toBe(0);

      // 3. CLI summary output
      const summaryOut = path.join(tempDir, 'summary.md');
      const summaryCode = await runCli([
        'summary',
        bundle.id,
        '--output',
        summaryOut,
        '--workspace',
        tempDir,
      ]);
      expect(summaryCode).toBe(0);
      expect(fs.existsSync(summaryOut)).toBe(true);
    });
  });
});
