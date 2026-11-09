import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  registerTrustedAgent,
  revokeTrustedAgent,
  getAgentKeyStatus,
  listTrustedAgents,
  loadAgentRegistry,
} from '../src/registry.js';
import { generateAgentKeyPair } from '../src/attestation.js';
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
});

