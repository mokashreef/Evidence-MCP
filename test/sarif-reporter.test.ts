import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { exportEvidenceReport, formatSarifReport } from '../src/reporter.js';
import { createEvidenceServer } from '../src/server.js';
import { runCli } from '../src/cli.js';
import { saveBundle } from '../src/storage.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import {
  EvidenceBundle,
  PolicyEvaluationResult,
  SarifReport,
  VerificationResult,
} from '../src/types.js';

describe('SARIF v2.1.0 Report Export', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-sarif-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it('produces compliant empty-results SARIF 2.1.0 report for verified bundles', () => {
    const now = new Date().toISOString();
    const bundle: EvidenceBundle = {
      id: 'bundle_sarif_ok',
      task: 'Verified release check',
      workspacePath: tempWorkspace,
      status: 'verified',
      createdAt: now,
      updatedAt: now,
      evidence: {},
      assertions: [],
    };

    const verification: VerificationResult = {
      bundleId: bundle.id,
      status: 'verified',
      verifiedAt: now,
      summary: 'All assertions verified.',
      reasons: [],
      items: [
        {
          id: 'file_1',
          type: 'file',
          status: 'verified',
          details: 'Matches disk SHA-256.',
        },
      ],
    };

    const sarifJson = exportEvidenceReport(bundle, 'sarif', verification);
    const parsed = JSON.parse(sarifJson) as SarifReport;

    expect(parsed.version).toBe('2.1.0');
    expect(parsed.$schema).toContain('sarif-2.1.0.json');
    expect(parsed.runs.length).toBe(1);
    expect(parsed.runs[0].tool.driver.name).toBe('Evidence MCP');
    expect(parsed.runs[0].invocations?.[0].executionSuccessful).toBe(true);
    expect(parsed.runs[0].results).toEqual([]);
  });

  it('maps verification failures, stale snapshots, AST breaking changes, and policy violations with locations', () => {
    const now = new Date().toISOString();
    const bundle: EvidenceBundle = {
      id: 'bundle_sarif_issues',
      task: 'Detect failures and breaking AST changes',
      workspacePath: tempWorkspace,
      status: 'failed',
      createdAt: now,
      updatedAt: now,
      evidence: {
        fileSnapshots: [
          {
            id: 'file_stale',
            type: 'file_snapshot',
            capturedAt: now,
            path: 'src\\auth\\token.ts',
            absolutePath: path.join(tempWorkspace, 'src', 'auth', 'token.ts'),
            sha256: 'abc',
            sizeBytes: 120,
          },
        ],
        ast: [
          {
            id: 'ast_go_1',
            type: 'ast',
            capturedAt: now,
            filePath: 'pkg/server/handler.go',
            language: 'go',
            symbolsCount: 1,
            symbols: [],
            diff: {
              filePath: 'pkg/server/handler.go',
              hasChanges: true,
              isBreakingChange: true,
              addedSymbols: [],
              removedSymbols: [
                {
                  name: 'HandleAuth',
                  kind: 'function',
                  isExported: true,
                  startLine: 42,
                  endLine: 42,
                },
              ],
              modifiedSymbols: [
                {
                  symbol: {
                    name: 'Server.Validate',
                    kind: 'method',
                    isExported: true,
                    startLine: 77,
                    endLine: 77,
                  },
                  previous: {
                    name: 'Server.Validate',
                    kind: 'method',
                    isExported: true,
                    startLine: 77,
                    endLine: 77,
                  },
                  changes: ['New required parameter added to exported signature.'],
                },
              ],
            },
          },
        ],
      },
      assertions: [],
    };

    const verification: VerificationResult = {
      bundleId: bundle.id,
      status: 'stale',
      verifiedAt: now,
      summary: 'Stale snapshot found.',
      reasons: ['File modified'],
      items: [
        {
          id: 'file_stale',
          type: 'file',
          status: 'stale',
          details: 'SHA-256 mismatch on token.ts',
        },
        {
          id: 'assert_1',
          type: 'assertion',
          status: 'unverifiable',
          details: 'Relies on agent-reported output',
        },
      ],
    };

    const policyEval: PolicyEvaluationResult = {
      bundleId: bundle.id,
      passed: false,
      evaluatedAt: now,
      policySummary: 'Failed policy rules',
      rulesEvaluated: 2,
      passedCount: 0,
      failedCount: 2,
      warningCount: 0,
      evaluations: [
        {
          rule: 'git.requireCleanWorkingTree',
          category: 'git',
          passed: false,
          severity: 'error',
          message: 'Working tree has uncommitted changes.',
        },
        {
          rule: 'license.disallowedLicenses',
          category: 'license',
          passed: false,
          severity: 'error',
          message: 'License "AGPL-3.0" is disallowed by policy.',
        },
      ],
    };

    const sarifStr = formatSarifReport(bundle, verification, policyEval);
    const sarif = JSON.parse(sarifStr) as SarifReport;
    const run = sarif.runs[0];

    expect(run.invocations?.[0].executionSuccessful).toBe(false);
    // Deduplicated rules count
    expect(run.tool.driver.rules.map((r) => r.id)).toContain('AST-BREAKING-CHANGE');
    expect(run.tool.driver.rules.map((r) => r.id)).toContain('EVIDENCE-STALE-FILE');
    expect(run.tool.driver.rules.map((r) => r.id)).toContain('EVIDENCE-UNVERIFIABLE-ASSERTION');
    expect(run.tool.driver.rules.map((r) => r.id)).toContain('POLICY-GIT-REQUIRECLEANWORKINGTREE');
    expect(run.tool.driver.rules.map((r) => r.id)).toContain('POLICY-LICENSE-DISALLOWEDLICENSES');

    // Normalized POSIX paths and exact line numbers on AST results
    const staleResult = run.results.find((r) => r.ruleId === 'EVIDENCE-STALE-FILE');
    expect(staleResult?.level).toBe('warning');
    expect(staleResult?.locations?.[0].physicalLocation.artifactLocation.uri).toBe(
      'src/auth/token.ts'
    );

    const astRemovedResult = run.results.find(
      (r) => r.ruleId === 'AST-BREAKING-CHANGE' && r.message.text.includes('HandleAuth')
    );
    expect(astRemovedResult?.level).toBe('error');
    expect(astRemovedResult?.locations?.[0].physicalLocation.region?.startLine).toBe(42);

    const astModResult = run.results.find(
      (r) => r.ruleId === 'AST-BREAKING-CHANGE' && r.message.text.includes('Server.Validate')
    );
    expect(astModResult?.locations?.[0].physicalLocation.region?.startLine).toBe(77);

    const licensePolicyRes = run.results.find(
      (r) => r.ruleId === 'POLICY-LICENSE-DISALLOWEDLICENSES'
    );
    expect(licensePolicyRes?.locations?.[0].physicalLocation.artifactLocation.uri).toBe(
      'package.json'
    );
  });

  it('exports SARIF report via MCP export_evidence_report tool and CLI --format sarif', async () => {
    const filePath = path.join(tempWorkspace, 'app.ts');
    await fs.promises.writeFile(filePath, 'export const ok = true;\n', 'utf8');
    const hash = await computeFileSha256AndSize(filePath);
    const now = new Date().toISOString();

    const bundle: EvidenceBundle = {
      id: 'bundle_sarif_e2e',
      task: 'SARIF CLI & MCP test',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        fileSnapshots: [
          {
            id: 'file_app',
            type: 'file_snapshot',
            capturedAt: now,
            path: 'app.ts',
            absolutePath: filePath,
            sha256: hash.sha256,
            sizeBytes: hash.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_app',
          claim: 'app.ts verified',
          evidenceIds: ['file_app'],
          createdAt: now,
        },
      ],
    };
    await saveBundle(bundle);

    // Create a failing license policy to ensure SARIF picks up policy findings
    await fs.promises.writeFile(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'test-app', license: 'GPL-3.0' }),
      'utf8'
    );
    const policyFile = path.join(tempWorkspace, 'evidence.policy.json');
    await fs.promises.writeFile(
      policyFile,
      JSON.stringify({ license: { allowedLicenses: ['MIT'] } }),
      'utf8'
    );

    // 1. Test MCP Tool
    const server = createEvidenceServer();
    const toolRes = await (server as any)._registeredTools['export_evidence_report'].handler({
      bundleId: bundle.id,
      format: 'sarif',
      policyPath: policyFile,
      workspacePath: tempWorkspace,
    });
    expect(toolRes.isError).toBeUndefined();
    const mcpSarif = JSON.parse(toolRes.content[0].text) as SarifReport;
    expect(mcpSarif.version).toBe('2.1.0');
    expect(mcpSarif.runs[0].results.some((r) => r.ruleId === 'POLICY-LICENSE-ALLOWEDLICENSES')).toBe(
      true
    );

    // 2. Test CLI
    const outFile = path.join(tempWorkspace, 'reports', 'evidence.sarif');
    const exitCode = await runCli([
      'report',
      bundle.id,
      '--format',
      'sarif',
      '--policy',
      policyFile,
      '--output',
      outFile,
      '--workspace',
      tempWorkspace,
    ]);
    expect(exitCode).toBe(0);
    expect(fs.existsSync(outFile)).toBe(true);
    const cliSarif = JSON.parse(await fs.promises.readFile(outFile, 'utf8')) as SarifReport;
    expect(cliSarif.version).toBe('2.1.0');
    expect(cliSarif.runs[0].results.length).toBeGreaterThan(0);
  });
});
