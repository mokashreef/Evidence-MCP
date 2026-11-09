/**
 * Multi-Agent Consensus Orchestration Example
 *
 * Demonstrates a complete verifiable workflow across 3 AI agents:
 * 1. Coder Agent: Writes code and creates a signed evidence bundle.
 * 2. Security Auditor: Reviews code for secrets/vulnerabilities and signs endorsement.
 * 3. QA Tester: Verifies test suite execution and signs endorsement.
 *
 * Quorum is evaluated and verified cryptographically before merging.
 */

import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  saveBundle,
  loadBundle,
  generateId,
} from '../../src/storage.js';
import {
  generateAgentKeyPair,
  signEvidenceBundle,
} from '../../src/attestation.js';
import {
  createPeerEndorsement,
  checkBundleQuorum,
} from '../../src/consensus.js';
import {
  registerTrustedAgent,
} from '../../src/registry.js';
import {
  computeFileSha256AndSize,
} from '../../src/hasher.js';
import {
  evaluateEvidencePolicy,
} from '../../src/policy.js';
import {
  EvidencePolicy,
  EvidenceBundle,
} from '../../src/types.js';

export async function runConsensusScenario(workspaceDir?: string): Promise<{
  bundleId: string;
  quorumPassed: boolean;
  policyPassed: boolean;
}> {
  const tempDir = workspaceDir || (await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-demo-')));
  console.log(`[Consensus Demo] Initializing workspace: ${tempDir}`);

  // Step 1: Generate agent cryptographic identities
  const coderKeys = generateAgentKeyPair();
  const secKeys = generateAgentKeyPair();
  const qaKeys = generateAgentKeyPair();

  // Step 2: Register trusted reviewer keys in workspace registry
  await registerTrustedAgent({
    workspacePath: tempDir,
    agentId: 'agent:sec-auditor',
    name: 'Autonomous Security Auditor',
    role: 'security_auditor',
    publicKeyPem: secKeys.publicKeyPem,
  });

  await registerTrustedAgent({
    workspacePath: tempDir,
    agentId: 'agent:qa-bot',
    name: 'CI/CD QA Verification Bot',
    role: 'tester',
    publicKeyPem: qaKeys.publicKeyPem,
  });

  // Step 3: Coder Agent generates evidence bundle & writes source file
  const srcFile = path.join(tempDir, 'auth.ts');
  await fs.promises.writeFile(
    srcFile,
    'export function verifyToken(token: string): boolean { return token.startsWith("ey"); }\n',
    'utf8'
  );
  const hashInfo = await computeFileSha256AndSize(srcFile);

  const bundle: EvidenceBundle = {
    id: generateId('bundle'),
    task: 'feat(auth): add JWT bearer token validation middleware',
    workspacePath: tempDir,
    status: 'in_progress',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    evidence: {},
    assertions: [],
  };

  bundle.evidence.fileSnapshots = [
    {
      id: 'file_auth_ts',
      type: 'file_snapshot',
      capturedAt: new Date().toISOString(),
      path: 'auth.ts',
      absolutePath: srcFile,
      sha256: hashInfo.sha256,
      sizeBytes: hashInfo.sizeBytes,
    },
  ];

  bundle.assertions = [
    {
      id: 'assert_jwt_check',
      claim: 'verifyToken safely validates bearer tokens',
      evidenceIds: ['file_auth_ts'],
      createdAt: new Date().toISOString(),
    },
  ];

  // Step 4: Coder Agent signs the bundle attestation
  bundle.attestation = await signEvidenceBundle(bundle, coderKeys.privateKeyPem);
  await saveBundle(bundle);
  console.log(`[Consensus Demo] Bundle ${bundle.id} created and attested by Coder Agent.`);

  // Step 5: Security Auditor Agent inspects and endorses
  const secEndorsement = await createPeerEndorsement({
    bundle,
    agentId: 'agent:sec-auditor',
    role: 'security_auditor',
    verdict: 'approved',
    comment: 'Static security audit passed. No plaintext secrets or unsafe regexes found.',
    privateKeyPem: secKeys.privateKeyPem,
    workspacePath: tempDir,
  });

  // Step 6: QA Tester Agent runs tests and endorses
  const qaEndorsement = await createPeerEndorsement({
    bundle,
    agentId: 'agent:qa-bot',
    role: 'tester',
    verdict: 'approved',
    comment: 'Unit tests passed 100% with full coverage on token validation.',
    privateKeyPem: qaKeys.privateKeyPem,
    workspacePath: tempDir,
  });

  // Attach endorsements to bundle
  const activeBundle = await loadBundle(bundle.id, tempDir);
  activeBundle.endorsements = [secEndorsement, qaEndorsement];
  await saveBundle(activeBundle);

  // Step 7: Check Quorum Requirements
  const quorum = checkBundleQuorum(activeBundle, {
    minEndorsements: 2,
    requiredRoles: ['security_auditor', 'tester'],
    requireUniqueSigners: true,
    disallowRejections: true,
  });

  console.log(`[Consensus Demo] Quorum Satisfied: ${quorum.satisfied} (${quorum.approvedCount}/2 approvals)`);

  // Step 8: Evaluate Workspace Policy Compliance
  const policy: EvidencePolicy = {
    version: '1.0',
    description: 'Autonomous PR Approval Policy',
    commands: {
      disallowNonZeroExitCodes: true,
    },
    assertions: {
      minAssertions: 1,
      disallowUnverifiable: true,
    },
    attestation: {
      requireSignature: true,
    },
    consensus: {
      minEndorsements: 2,
      requiredRoles: ['security_auditor', 'tester'],
      requireUniqueSigners: true,
      disallowRejections: true,
    },
  };

  const policyResult = evaluateEvidencePolicy({
    bundle: activeBundle,
    policy,
  });

  console.log(`[Consensus Demo] Policy Verdict: ${policyResult.passed ? 'PASSED' : 'FAILED'}`);

  return {
    bundleId: activeBundle.id,
    quorumPassed: quorum.satisfied,
    policyPassed: policyResult.passed,
  };
}

// Allow running directly via tsx / node
if (process.argv[1] && process.argv[1].includes('orchestrate')) {
  runConsensusScenario()
    .then((res) => {
      console.log('[Consensus Demo] Scenario completed successfully:', res);
    })
    .catch((err) => {
      console.error('[Consensus Demo] Scenario failed:', err);
      process.exit(1);
    });
}
