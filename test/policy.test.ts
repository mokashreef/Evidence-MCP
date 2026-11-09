import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  matchesFilePattern,
  matchesCommandPattern,
  loadPolicyFile,
  evaluateEvidencePolicy,
} from '../src/policy.js';
import {
  EvidenceBundle,
  EvidencePolicy,
} from '../src/types.js';
import { saveBundle } from '../src/storage.js';
import { runCli } from '../src/cli.js';
import { signEvidenceBundle, generateAgentKeyPair } from '../src/attestation.js';
import { createPeerEndorsement } from '../src/consensus.js';

describe('Automated Evidence Policy Engine', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-policy-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('Pattern Matchers', () => {
    it('matches file patterns with glob-like wildcards accurately', () => {
      expect(matchesFilePattern('src/index.ts', '*.ts')).toBe(true);
      expect(matchesFilePattern('src/utils/math.ts', 'src/**/*.ts')).toBe(true);
      expect(matchesFilePattern('packages/core/src/api.ts', 'packages/**/api.ts')).toBe(true);
      expect(matchesFilePattern('secret.env', '*.env')).toBe(true);
      expect(matchesFilePattern('.env.local', '.env*')).toBe(true);
      expect(matchesFilePattern('README.md', '*.ts')).toBe(false);
      expect(matchesFilePattern('src/index.js', 'src/*.ts')).toBe(false);
    });

    it('matches command patterns using substring and wildcards', () => {
      expect(matchesCommandPattern('npm test -- core.test.ts', 'npm test')).toBe(true);
      expect(matchesCommandPattern('vitest run --coverage', 'vitest*coverage')).toBe(true);
      expect(matchesCommandPattern('cargo check', 'npm')).toBe(false);
    });
  });

  describe('Policy File Loading', () => {
    it('loads policy from evidence.policy.json in workspace root', async () => {
      const policyContent: EvidencePolicy = {
        version: '1',
        description: 'Standard CI Policy',
        git: { requireCleanWorkingTree: true },
      };
      const policyFilePath = path.join(tempWorkspace, 'evidence.policy.json');
      await fs.promises.writeFile(policyFilePath, JSON.stringify(policyContent, null, 2), 'utf8');

      const loaded = await loadPolicyFile(undefined, tempWorkspace);
      expect(loaded).not.toBeNull();
      expect(loaded?.policy.version).toBe('1');
      expect(loaded?.policy.git?.requireCleanWorkingTree).toBe(true);
      expect(loaded?.sourcePath).toBe(policyFilePath);
    });

    it('loads custom policy file path and throws if missing', async () => {
      await expect(
        loadPolicyFile('non-existent-policy.json', tempWorkspace)
      ).rejects.toThrow(/Specified policy file not found/);
    });
  });

  describe('Policy Evaluation Dimensions', () => {
    function createMockBundle(): EvidenceBundle {
      const now = new Date().toISOString();
      return {
        id: 'bundle_mock1234',
        task: 'Implement Policy Check',
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
              headCommit: 'abcdef1234567890',
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
              path: 'src/index.ts',
              absolutePath: path.join(tempWorkspace, 'src/index.ts'),
              sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              sizeBytes: 100,
            },
          ],
          commands: [
            {
              id: 'cmd_1',
              type: 'command',
              recordedAt: now,
              command: 'npm test',
              exitCode: 0,
              stdout: 'PASS',
              stderr: '',
              provenance: 'server_executed',
            },
          ],
          ast: [
            {
              id: 'ast_1',
              type: 'ast',
              capturedAt: now,
              filePath: 'src/index.ts',
              language: 'typescript',
              symbolsCount: 2,
              symbols: [],
              diff: {
                filePath: 'src/index.ts',
                hasChanges: true,
                isBreakingChange: false,
                addedSymbols: [],
                removedSymbols: [],
                modifiedSymbols: [],
              },
            },
          ],
        },
        assertions: [
          {
            id: 'assert_1',
            claim: 'Tests pass and code compiles',
            evidenceIds: ['cmd_1', 'file_1'],
            createdAt: now,
          },
        ],
      };
    }

    it('passes clean bundle when all policy rules are satisfied', () => {
      const bundle = createMockBundle();
      const policy: EvidencePolicy = {
        git: {
          requireCleanWorkingTree: true,
          allowedBranches: ['main', 'feat/*'],
          disallowDetachedHead: true,
        },
        files: {
          maxSnapshots: 10,
          requiredPatterns: ['src/**/*.ts'],
          disallowedPatterns: ['*.env*'],
        },
        commands: {
          requireServerExecutedCommands: true,
          disallowNonZeroExitCodes: true,
          requiredCommandPatterns: ['npm test'],
        },
        ast: {
          requireAstEvidence: true,
          disallowBreakingChanges: true,
        },
        assertions: {
          minAssertions: 1,
        },
      };

      const result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(true);
      expect(result.failedCount).toBe(0);
      expect(result.rulesEvaluated).toBeGreaterThan(5);
    });

    it('fails when Git working tree is dirty or branch is unauthorized', () => {
      const bundle = createMockBundle();
      bundle.evidence.git![0].isClean = false;
      bundle.evidence.git![0].branch = 'experimental-hack';

      const policy: EvidencePolicy = {
        git: {
          requireCleanWorkingTree: true,
          allowedBranches: ['main', 'release/*'],
        },
      };

      const result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.failedCount).toBe(2);
      expect(result.evaluations.find((e) => e.rule === 'git.requireCleanWorkingTree')?.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'git.allowedBranches')?.passed).toBe(false);
    });

    it('fails when AST breaking changes are detected', () => {
      const bundle = createMockBundle();
      bundle.evidence.ast![0].diff!.isBreakingChange = true;

      const policy: EvidencePolicy = {
        ast: {
          disallowBreakingChanges: true,
        },
      };

      const result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'ast.disallowBreakingChanges')?.passed).toBe(false);
    });

    it('fails when disallowed file patterns are snapshotted', () => {
      const bundle = createMockBundle();
      bundle.evidence.fileSnapshots!.push({
        id: 'file_leak',
        type: 'file_snapshot',
        capturedAt: new Date().toISOString(),
        path: '.env.production',
        absolutePath: path.join(tempWorkspace, '.env.production'),
        sha256: 'abc123',
        sizeBytes: 50,
      });

      const policy: EvidencePolicy = {
        files: {
          disallowedPatterns: ['.env*'],
        },
      };

      const result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'files.disallowedPatterns')?.passed).toBe(false);
    });

    it('validates consensus quorum within the policy engine', async () => {
      const bundle = createMockBundle();
      await saveBundle(bundle);

      const policy: EvidencePolicy = {
        consensus: {
          minEndorsements: 2,
          requiredRoles: ['tester', 'security_auditor'],
          disallowRejections: true,
        },
      };

      // Initially no endorsements -> fails
      let result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);

      const qaKeys = generateAgentKeyPair();
      const secKeys = generateAgentKeyPair();

      // Add 1st endorsement (tester) with distinct key
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:qa',
        role: 'tester',
        verdict: 'approved',
        comment: 'Tests pass',
        privateKeyPem: qaKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });

      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false); // missing security_auditor

      // Add 2nd endorsement (security_auditor) with distinct key
      await createPeerEndorsement({
        bundle,
        agentId: 'agent:sec',
        role: 'security_auditor',
        verdict: 'approved',
        comment: 'No vulnerabilities',
        privateKeyPem: secKeys.privateKeyPem,
        workspacePath: tempWorkspace,
      });

      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(true);
      expect(result.evaluations.find((e) => e.rule === 'consensus.quorum')?.passed).toBe(true);
    });

    it('enforces package license compliance rules in workspace', async () => {
      const bundle = createMockBundle();
      await saveBundle(bundle);

      // 1. Without package.json, requireLicenseField fails
      let policy: EvidencePolicy = {
        license: {
          requireLicenseField: true,
        },
      };
      let result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'license.requireLicenseField')?.passed).toBe(false);

      // 2. Add package.json with GPL-3.0
      const pkgPath = path.join(tempWorkspace, 'package.json');
      await fs.promises.writeFile(
        pkgPath,
        JSON.stringify({ name: 'my-app', version: '1.0.0', license: 'GPL-3.0' }, null, 2),
        'utf8'
      );

      // 3. Test allowedLicenses requiring MIT or Apache-2.0 -> fails for GPL-3.0
      policy = {
        license: {
          requireLicenseField: true,
          allowedLicenses: ['MIT', 'Apache-2.0'],
        },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'license.allowedLicenses')?.passed).toBe(false);

      // 4. Test disallowedLicenses containing GPL-3.0 -> fails
      policy = {
        license: {
          disallowedLicenses: ['GPL-3.0', 'AGPL-3.0'],
        },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(false);
      expect(result.evaluations.find((e) => e.rule === 'license.disallowedLicenses')?.passed).toBe(false);

      // 5. Update package.json to MIT -> satisfies allowedLicenses & disallowedLicenses
      await fs.promises.writeFile(
        pkgPath,
        JSON.stringify({ name: 'my-app', version: '1.0.0', license: 'MIT' }, null, 2),
        'utf8'
      );

      policy = {
        license: {
          requireLicenseField: true,
          allowedLicenses: ['MIT', 'Apache-2.0'],
          disallowedLicenses: ['GPL-3.0', 'AGPL-3.0'],
        },
      };
      result = evaluateEvidencePolicy({ bundle, policy });
      expect(result.passed).toBe(true);
      expect(result.evaluations.filter((e) => e.category === 'license').every((e) => e.passed)).toBe(true);
    });
  });

  describe('CLI Integration', () => {
    it('executes evidence-mcp policy CLI command successfully', async () => {
      const now = new Date().toISOString();
      const bundle: EvidenceBundle = {
        id: 'bundle_clipol1',
        task: 'CLI Policy Task',
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
              headCommit: '123456',
              statusShort: '',
              diffCheck: '',
              isClean: true,
            },
          ],
        },
        assertions: [],
      };
      await saveBundle(bundle);

      const policy: EvidencePolicy = {
        git: { requireCleanWorkingTree: true },
      };
      const policyFile = path.join(tempWorkspace, 'evidence.policy.json');
      await fs.promises.writeFile(policyFile, JSON.stringify(policy, null, 2), 'utf8');

      const exitCode = await runCli([
        'policy',
        bundle.id,
        '--policy',
        policyFile,
        '--workspace',
        tempWorkspace,
      ]);

      expect(exitCode).toBe(0);
    });
  });
});
