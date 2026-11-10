import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  registerTrustedAgent,
  revokeTrustedAgent,
  getAgentKeyStatus,
  verifyAgentKeyStatusSync,
  listTrustedAgents,
  loadAgentRegistry,
} from '../src/registry.js';
import { generateAgentKeyPair, signEvidenceBundle } from '../src/attestation.js';
import { createPeerEndorsement, checkBundleQuorum } from '../src/consensus.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { evaluateEvidencePolicy } from '../src/policy.js';
import { saveBundle, generateId } from '../src/storage.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { EvidenceBundle, EvidencePolicy } from '../src/types.js';
import { runCli } from '../src/cli.js';

describe('Distributed Agent Key Registry', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-registry-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('Agent Key Registration & Lookup', () => {
    it('registers an agent with valid PEM public key and verifies its active status', async () => {
      const keys = generateAgentKeyPair();

      const registered = await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:qa-auditor',
        name: 'Quality Assurance Agent',
        role: 'tester',
        publicKeyPem: keys.publicKeyPem,
      });

      expect(registered.agentId).toBe('agent:qa-auditor');
      expect(registered.status).toBe('active');
      expect(registered.keyFingerprint).toBe(keys.fingerprint);

      // Verify status by agentId and by fingerprint
      const byId = await getAgentKeyStatus(tempWorkspace, 'agent:qa-auditor');
      expect(byId.registered).toBe(true);
      expect(byId.active).toBe(true);
      expect(byId.agent?.name).toBe('Quality Assurance Agent');

      const byFp = await getAgentKeyStatus(tempWorkspace, keys.fingerprint);
      expect(byFp.registered).toBe(true);
      expect(byFp.active).toBe(true);
    });

    it('rejects registration with invalid public key PEM', async () => {
      await expect(
        registerTrustedAgent({
          workspacePath: tempWorkspace,
          agentId: 'agent:invalid',
          name: 'Invalid Agent',
          role: 'tester',
          publicKeyPem: 'NOT-A-REAL-PEM-KEY',
        })
      ).rejects.toThrow(/Invalid PEM public key/);
    });

    it('flags expired agent keys as inactive', async () => {
      const keys = generateAgentKeyPair();
      const pastDate = new Date(Date.now() - 60000).toISOString();

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:expired-bot',
        name: 'Expired Agent',
        role: 'peer_reviewer',
        publicKeyPem: keys.publicKeyPem,
        expiresAt: pastDate,
      });

      const status = await getAgentKeyStatus(tempWorkspace, 'agent:expired-bot');
      expect(status.registered).toBe(true);
      expect(status.active).toBe(false);
      expect(status.reason).toContain('expired');
    });
  });

  describe('Agent Key Revocation', () => {
    it('revokes an agent key with reason and verifies inactive status', async () => {
      const keys = generateAgentKeyPair();

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:compromised',
        name: 'Compromised Bot',
        role: 'tester',
        publicKeyPem: keys.publicKeyPem,
      });

      const revoked = await revokeTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:compromised',
        reason: 'Private key compromised in external breach',
      });

      expect(revoked.status).toBe('revoked');
      expect(revoked.revokedAt).toBeDefined();
      expect(revoked.revocationReason).toBe('Private key compromised in external breach');

      const status = await getAgentKeyStatus(tempWorkspace, 'agent:compromised');
      expect(status.registered).toBe(true);
      expect(status.active).toBe(false);
      expect(status.reason).toContain('Private key compromised');
    });

    it('throws when revoking an unregistered agent', async () => {
      await expect(
        revokeTrustedAgent({
          workspacePath: tempWorkspace,
          agentId: 'agent:unknown-bot',
          reason: 'Testing',
        })
      ).rejects.toThrow(/not registered/);
    });
  });

  describe('Registry Listing & Filtering', () => {
    it('lists and filters agents by status', async () => {
      const keys1 = generateAgentKeyPair();
      const keys2 = generateAgentKeyPair();

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:active1',
        name: 'Active Agent',
        role: 'tester',
        publicKeyPem: keys1.publicKeyPem,
      });

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:revoked1',
        name: 'Revoked Agent',
        role: 'security_auditor',
        publicKeyPem: keys2.publicKeyPem,
      });

      await revokeTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:revoked1',
        reason: 'Key rotation',
      });

      const all = await listTrustedAgents(tempWorkspace, 'all');
      expect(all.length).toBe(2);

      const active = await listTrustedAgents(tempWorkspace, 'active');
      expect(active.length).toBe(1);
      expect(active[0].agentId).toBe('agent:active1');

      const revoked = await listTrustedAgents(tempWorkspace, 'revoked');
      expect(revoked.length).toBe(1);
      expect(revoked[0].agentId).toBe('agent:revoked1');
    });
  });

  describe('CLI Registry Commands', () => {
    it('supports registry add, list, and revoke CLI commands', async () => {
      const keys = generateAgentKeyPair();
      const pubKeyFile = path.join(tempWorkspace, 'agent.pub');
      await fs.promises.writeFile(pubKeyFile, keys.publicKeyPem, 'utf8');

      // 1. Add agent
      let exitCode = await runCli([
        'registry',
        'add',
        'agent:cli-bot',
        pubKeyFile,
        '--name',
        'CLI Test Bot',
        '--role',
        'architect',
        '--workspace',
        tempWorkspace,
      ]);
      expect(exitCode).toBe(0);

      // 2. List agents
      exitCode = await runCli(['registry', 'list', '--workspace', tempWorkspace]);
      expect(exitCode).toBe(0);

      // 3. Revoke agent
      exitCode = await runCli([
        'registry',
        'revoke',
        'agent:cli-bot',
        'Decommissioned after sprint',
        '--workspace',
        tempWorkspace,
      ]);
      expect(exitCode).toBe(0);

      // Verify revoked state in registry file
      const registry = await loadAgentRegistry(tempWorkspace);
      expect(registry.agents['agent:cli-bot'].status).toBe('revoked');
    });
  });

  describe('Registry Verification & Policy Enforcement', () => {
    async function createSignedBundleForTest(
      signerPrivateKeyPem?: string
    ): Promise<EvidenceBundle> {
      const targetFile = path.join(tempWorkspace, 'app.ts');
      await fs.promises.writeFile(targetFile, 'export const version = 1;\n', 'utf8');
      const { sha256, sizeBytes } = await computeFileSha256AndSize(targetFile);
      const now = new Date().toISOString();
      const fileId = generateId('file');

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'Registry security check',
        workspacePath: tempWorkspace,
        status: 'in_progress',
        createdAt: now,
        updatedAt: now,
        evidence: {
          fileSnapshots: [
            {
              id: fileId,
              type: 'file_snapshot',
              capturedAt: now,
              path: 'app.ts',
              absolutePath: targetFile,
              sha256,
              sizeBytes,
            },
          ],
        },
        assertions: [
          {
            id: generateId('assert'),
            claim: 'app.ts snapshot valid',
            evidenceIds: [fileId],
            createdAt: now,
          },
        ],
      };

      if (signerPrivateKeyPem) {
        bundle.attestation = await signEvidenceBundle(bundle, signerPrivateKeyPem);
      }

      await saveBundle(bundle);
      return bundle;
    }

    it('rejects bundle attestation signed by a revoked or expired key in verifyEvidenceBundle', async () => {
      const coderKeys = generateAgentKeyPair();

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:coder',
        name: 'Coder Agent',
        role: 'architect',
        publicKeyPem: coderKeys.publicKeyPem,
      });

      const bundle = await createSignedBundleForTest(coderKeys.privateKeyPem);

      // Active key passes verification
      const activeVerify = await verifyEvidenceBundle(bundle);
      expect(activeVerify.status).toBe('verified');

      // Revoke the key and re-verify
      await revokeTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:coder',
        reason: 'Key leaked',
      });

      const revokedVerify = await verifyEvidenceBundle(bundle);
      expect(revokedVerify.status).toBe('failed');
      expect(
        revokedVerify.items.find((i) => i.id === 'attestation')?.details
      ).toContain('revoked');
    });

    it('blocks revoked keys, fingerprint spoofing, and enforces strict registry mode in checkBundleQuorum', async () => {
      const qaKeys = generateAgentKeyPair();
      const rogueKeys = generateAgentKeyPair();

      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:qa-trusted',
        name: 'QA Trusted',
        role: 'tester',
        publicKeyPem: qaKeys.publicKeyPem,
      });

      const bundle = await createSignedBundleForTest();

      // 1. Impersonation attack: claiming registered agent:qa-trusted with rogue key
      const spoofedEndorsement = await createPeerEndorsement({
        bundle,
        agentId: 'agent:qa-trusted',
        role: 'tester',
        verdict: 'approved',
        comment: 'Spoofed key attempt',
        privateKeyPem: rogueKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });

      const spoofQuorum = checkBundleQuorum(bundle, { minEndorsements: 1 });
      expect(spoofQuorum.satisfied).toBe(false);
      expect(spoofQuorum.reasons.some((r) => r.includes('does not match registered fingerprint'))).toBe(
        true
      );

      // Replace with unregistered agentId signed by rogueKeys
      bundle.endorsements = [];
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:unregistered-bot',
        role: 'tester',
        verdict: 'approved',
        comment: 'Unregistered approval',
        privateKeyPem: rogueKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });

      // Permissive mode allows unregistered keys if not revoked
      expect(checkBundleQuorum(bundle, { minEndorsements: 1 }).satisfied).toBe(true);

      // Strict registry mode rejects unregistered keys
      const strictQuorum = checkBundleQuorum(bundle, {
        minEndorsements: 1,
        requireTrustedRegistry: true,
      });
      expect(strictQuorum.satisfied).toBe(false);
      expect(strictQuorum.reasons.some((r) => r.includes('not registered'))).toBe(true);

      // 2. Revoke QA key, then test both direct agentId and spoofed alias reuse of revoked key
      await revokeTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:qa-trusted',
        reason: 'Rotated out',
      });

      bundle.endorsements = [];
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:alias-attacker',
        role: 'tester',
        verdict: 'approved',
        comment: 'Reusing revoked key under new alias',
        privateKeyPem: qaKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });

      const revokedAliasQuorum = checkBundleQuorum(bundle, {
        minEndorsements: 1,
        requireTrustedRegistry: false,
      });
      expect(revokedAliasQuorum.satisfied).toBe(false);
      expect(revokedAliasQuorum.reasons.some((r) => r.includes('revoked'))).toBe(true);

      expect(spoofedEndorsement.id).toBeDefined();
    });

    it('enforces attestation.requireTrustedRegistry and consensus.requireTrustedRegistry in evaluateEvidencePolicy', async () => {
      const coderKeys = generateAgentKeyPair();
      const reviewerKeys = generateAgentKeyPair();

      const bundle = await createSignedBundleForTest(coderKeys.privateKeyPem);
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:sec-reviewer',
        role: 'security_auditor',
        verdict: 'approved',
        comment: 'Reviewed securely',
        privateKeyPem: reviewerKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });
      await saveBundle(bundle);

      const policy: EvidencePolicy = {
        attestation: {
          requireSignature: true,
          requireTrustedRegistry: true,
        },
        consensus: {
          minEndorsements: 1,
          requireTrustedRegistry: true,
        },
      };

      // Neither signer is registered yet -> fails
      const initialEval = evaluateEvidencePolicy({ bundle, policy });
      expect(initialEval.passed).toBe(false);
      expect(
        initialEval.evaluations.find((e) => e.rule === 'attestation.requireTrustedRegistry')?.passed
      ).toBe(false);
      expect(initialEval.evaluations.find((e) => e.rule === 'consensus.quorum')?.passed).toBe(false);

      // Register both agents
      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:coder',
        name: 'Coder',
        role: 'architect',
        publicKeyPem: coderKeys.publicKeyPem,
      });
      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:sec-reviewer',
        name: 'Sec Reviewer',
        role: 'security_auditor',
        publicKeyPem: reviewerKeys.publicKeyPem,
      });

      const passedEval = evaluateEvidencePolicy({ bundle, policy });
      expect(passedEval.passed).toBe(true);
      expect(
        passedEval.evaluations.find((e) => e.rule === 'attestation.requireTrustedRegistry')?.passed
      ).toBe(true);

      // Revoke coder key -> attestation fails even with requireTrustedRegistry false
      await revokeTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:coder',
        reason: 'Key rotated',
      });

      const revokedEval = evaluateEvidencePolicy({
        bundle,
        policy: {
          attestation: { requireSignature: true, requireTrustedRegistry: false },
        },
      });
      expect(revokedEval.passed).toBe(false);
    });

    it('supports --require-registry flag in evidence-mcp quorum CLI command', async () => {
      const reviewerKeys = generateAgentKeyPair();
      const bundle = await createSignedBundleForTest();
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:cli-reviewer',
        role: 'tester',
        verdict: 'approved',
        comment: 'CLI approved',
        privateKeyPem: reviewerKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });
      await saveBundle(bundle);

      // Fails when --require-registry is set and agent not registered
      const unregisteredCode = await runCli([
        'quorum',
        bundle.id,
        '--require-registry',
        '--workspace',
        tempWorkspace,
      ]);
      expect(unregisteredCode).toBe(1);

      // Register and retry -> passes
      await registerTrustedAgent({
        workspacePath: tempWorkspace,
        agentId: 'agent:cli-reviewer',
        name: 'CLI Reviewer',
        role: 'tester',
        publicKeyPem: reviewerKeys.publicKeyPem,
      });

      const registeredCode = await runCli([
        'quorum',
        bundle.id,
        '--require-registry',
        '--workspace',
        tempWorkspace,
      ]);
      expect(registeredCode).toBe(0);

      // Verify sync helper directly handles missing workspace gracefully
      const missingStatus = verifyAgentKeyStatusSync({
        workspacePath: path.join(tempWorkspace, 'non-existent-dir'),
        keyFingerprint: reviewerKeys.fingerprint,
      });
      expect(missingStatus.registryExists).toBe(false);
      expect(missingStatus.registered).toBe(false);
    });
  });
});

