import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { saveBundle } from '../src/storage.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { EvidenceBundle } from '../src/types.js';

describe('Evidence Verification Engine', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-verify-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  it('marks bundle as verified when files match and assertions are supported by independently verified evidence', async () => {
    const filePath = path.join(tempWorkspace, 'src', 'app.ts');
    await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
    await fs.promises.writeFile(filePath, 'export const version = "1.0.0";\n', 'utf8');

    const hashInfo = await computeFileSha256AndSize(filePath);
    const bundle: EvidenceBundle = {
      id: 'bundle_valid_1',
      task: 'Add version export',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_app_ts',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'src/app.ts',
            absolutePath: filePath,
            sha256: hashInfo.sha256,
            sizeBytes: hashInfo.sizeBytes,
          },
        ],
        commands: [
          {
            id: 'cmd_test',
            type: 'command',
            recordedAt: new Date().toISOString(),
            command: 'npm test',
            exitCode: 0,
            stdout: 'All tests passed',
            stderr: '',
            provenance: 'agent_reported',
          },
        ],
      },
      assertions: [
        {
          id: 'assert_1',
          claim: 'Exported version and tests pass',
          evidenceIds: ['file_app_ts', 'cmd_test'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('verified');
    expect(result.reasons.length).toBe(0);

    const fileItem = result.items.find((i) => i.id === 'file_app_ts');
    expect(fileItem?.status).toBe('verified');

    const cmdItem = result.items.find((i) => i.id === 'cmd_test');
    expect(cmdItem?.status).toBe('unverifiable');

    const assertItem = result.items.find((i) => i.id === 'assert_1');
    expect(assertItem?.status).toBe('verified');
  });

  it('reports assertion and bundle as unverifiable when relying solely on agent-reported command evidence', async () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_only_commands',
      task: 'Run external smoke test',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        commands: [
          {
            id: 'cmd_only',
            type: 'command',
            recordedAt: new Date().toISOString(),
            command: 'pytest tests/test_smoke.py',
            exitCode: 0,
            stdout: '1 passed in 0.12s',
            stderr: '',
            provenance: 'agent_reported',
          },
        ],
      },
      assertions: [
        {
          id: 'assert_smoke',
          claim: 'Smoke tests executed and passed',
          evidenceIds: ['cmd_only'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('unverifiable');
    expect(result.reasons.some((r) => r.includes('agent-reported command evidence (unverifiable)'))).toBe(true);

    const assertItem = result.items.find((i) => i.id === 'assert_smoke');
    expect(assertItem?.status).toBe('unverifiable');

    const cmdItem = result.items.find((i) => i.id === 'cmd_only');
    expect(cmdItem?.status).toBe('unverifiable');
  });

  it('detects stale evidence when file content is modified', async () => {
    const filePath = path.join(tempWorkspace, 'data.json');
    await fs.promises.writeFile(filePath, '{"count": 1}', 'utf8');

    const originalHash = await computeFileSha256AndSize(filePath);

    const bundle: EvidenceBundle = {
      id: 'bundle_stale_file',
      task: 'Update counter',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_data',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'data.json',
            absolutePath: filePath,
            sha256: originalHash.sha256,
            sizeBytes: originalHash.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_count',
          claim: 'Counter initialized to 1',
          evidenceIds: ['file_data'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    // Modify the file on disk!
    await fs.promises.writeFile(filePath, '{"count": 999}', 'utf8');

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('stale');
    expect(result.reasons.some((r) => r.includes('SHA-256 has changed'))).toBe(true);

    const fileItem = result.items.find((i) => i.id === 'file_data');
    expect(fileItem?.status).toBe('stale');

    const assertionItem = result.items.find((i) => i.id === 'assert_count');
    expect(assertionItem?.status).toBe('stale');
  });

  it('fails verification if snapshotted file is deleted', async () => {
    const filePath = path.join(tempWorkspace, 'temporary.txt');
    await fs.promises.writeFile(filePath, 'to be deleted', 'utf8');

    const originalHash = await computeFileSha256AndSize(filePath);

    const bundle: EvidenceBundle = {
      id: 'bundle_missing_file',
      task: 'Clean up temporary file',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_temp',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'temporary.txt',
            absolutePath: filePath,
            sha256: originalHash.sha256,
            sizeBytes: originalHash.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_temp',
          claim: 'Temporary file exists and verified',
          evidenceIds: ['file_temp'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    // Delete the file!
    await fs.promises.unlink(filePath);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('failed');
    expect(result.reasons.some((r) => r.includes('no longer exists on disk'))).toBe(true);
  });

  it('fails verification when bundle has no assertions', async () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_no_assertions',
      task: 'Empty claims task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        commands: [
          {
            id: 'cmd_1',
            type: 'command',
            recordedAt: new Date().toISOString(),
            command: 'echo ok',
            exitCode: 0,
            stdout: 'ok',
            stderr: '',
            provenance: 'agent_reported',
          },
        ],
      },
      assertions: [],
    };

    await saveBundle(bundle);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('failed');
    expect(result.reasons.some((r) => r.includes('no assertions'))).toBe(true);
  });

  it('fails verification when assertion references non-existent evidence IDs', async () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_bad_reference',
      task: 'Unsubstantiated claim task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        commands: [],
      },
      assertions: [
        {
          id: 'assert_phantom',
          claim: 'All tests pass flawlessly',
          evidenceIds: ['cmd_does_not_exist'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    const result = await verifyEvidenceBundle(bundle);
    expect(result.status).toBe('failed');
    expect(result.reasons.some((r) => r.includes('non-existent evidence IDs'))).toBe(true);
  });

  it('detects stale Git evidence when HEAD commit advances', async () => {
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execFileAsync = promisify(execFile);

    await execFileAsync('git', ['init', '-b', 'main'], { cwd: tempWorkspace });
    await execFileAsync('git', ['config', 'user.name', 'Test'], { cwd: tempWorkspace });
    await execFileAsync('git', ['config', 'user.email', 'test@example.com'], { cwd: tempWorkspace });
    await execFileAsync('git', ['commit', '--allow-empty', '-m', 'Initial commit'], { cwd: tempWorkspace });

    const { stdout: head1 } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: tempWorkspace });

    const bundle: EvidenceBundle = {
      id: 'bundle_git_stale',
      task: 'Git HEAD change test',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        git: [
          {
            id: 'git_ev_1',
            type: 'git',
            capturedAt: new Date().toISOString(),
            branch: 'main',
            headCommit: head1.trim(),
            statusShort: '',
            diffCheck: 'clean',
            isClean: true,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_git',
          claim: 'Repo is on initial commit',
          evidenceIds: ['git_ev_1'],
          createdAt: new Date().toISOString(),
        },
      ],
    };

    await saveBundle(bundle);

    const firstCheck = await verifyEvidenceBundle(bundle);
    expect(firstCheck.status).toBe('verified');

    // Create a second commit
    await execFileAsync('git', ['commit', '--allow-empty', '-m', 'Second commit'], { cwd: tempWorkspace });

    const secondCheck = await verifyEvidenceBundle(bundle);
    expect(secondCheck.status).toBe('stale');
    expect(secondCheck.reasons.some((r) => r.includes('HEAD commit moved'))).toBe(true);
  });

  describe('Post-capture Symlink Replacement Security Regressions', () => {
    it('fails verification safely if an initially snapshotted file is replaced with a symlink to an external file', async () => {
      const outsideDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-out-'));
      const outsideFile = path.join(outsideDir, 'external.txt');
      await fs.promises.writeFile(outsideFile, 'external sensitive content', 'utf8');

      const insideFile = path.join(tempWorkspace, 'config.json');
      await fs.promises.writeFile(insideFile, '{"setting": true}', 'utf8');
      const hashInfo = await computeFileSha256AndSize(insideFile);

      const bundle: EvidenceBundle = {
        id: 'bundle_symlink_external_regression',
        task: 'Symlink replacement regression test',
        workspacePath: tempWorkspace,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          fileSnapshots: [
            {
              id: 'file_config',
              type: 'file_snapshot',
              capturedAt: new Date().toISOString(),
              path: 'config.json',
              absolutePath: insideFile,
              sha256: hashInfo.sha256,
              sizeBytes: hashInfo.sizeBytes,
            },
          ],
        },
        assertions: [
          {
            id: 'assert_cfg',
            claim: 'Config file is valid',
            evidenceIds: ['file_config'],
            createdAt: new Date().toISOString(),
          },
        ],
      };
      await saveBundle(bundle);

      // Initial check must succeed
      const initialCheck = await verifyEvidenceBundle(bundle);
      expect(initialCheck.status).toBe('verified');

      // Replace normal internal file with a symlink pointing to external file
      await fs.promises.unlink(insideFile);
      let symlinkCreated = false;
      try {
        await fs.promises.symlink(outsideFile, insideFile);
        symlinkCreated = true;
      } catch (err: unknown) {
        const error = err as { code?: string };
        console.warn(`[SKIP] Symlink creation denied by OS (${error.code}). Skipping symlink check.`);
      }

      if (symlinkCreated) {
        // Re-verify bundle: must fail safely without reading or hashing external target
        const verifyResult = await verifyEvidenceBundle(bundle);
        expect(verifyResult.status).toBe('failed');
        const item = verifyResult.items.find((i) => i.id === 'file_config');
        expect(item?.status).toBe('failed');
        expect(item?.details).toMatch(/Security boundary violation/i);
        expect(verifyResult.reasons.some((r) => r.includes('Security violation on "config.json"'))).toBe(true);
      }

      await fs.promises.rm(outsideDir, { recursive: true, force: true });
    });

    it('fails verification safely if an initially snapshotted file is replaced with a symlink to a sensitive file', async () => {
      const outsideDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-env-out-'));
      const sensitiveFile = path.join(outsideDir, '.env');
      await fs.promises.writeFile(sensitiveFile, 'DATABASE_URL=postgres://secret', 'utf8');

      const insideFile = path.join(tempWorkspace, 'service-token.txt');
      await fs.promises.writeFile(insideFile, 'normal token', 'utf8');
      const hashInfo = await computeFileSha256AndSize(insideFile);

      const bundle: EvidenceBundle = {
        id: 'bundle_symlink_sensitive_regression',
        task: 'Symlink to sensitive file regression test',
        workspacePath: tempWorkspace,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {
          fileSnapshots: [
            {
              id: 'file_token',
              type: 'file_snapshot',
              capturedAt: new Date().toISOString(),
              path: 'service-token.txt',
              absolutePath: insideFile,
              sha256: hashInfo.sha256,
              sizeBytes: hashInfo.sizeBytes,
            },
          ],
        },
        assertions: [
          {
            id: 'assert_token',
            claim: 'Service token exists',
            evidenceIds: ['file_token'],
            createdAt: new Date().toISOString(),
          },
        ],
      };
      await saveBundle(bundle);

      // Initial check must succeed
      const initialCheck = await verifyEvidenceBundle(bundle);
      expect(initialCheck.status).toBe('verified');

      // Replace normal internal file with a symlink pointing to sensitive .env file
      await fs.promises.unlink(insideFile);
      let symlinkCreated = false;
      try {
        await fs.promises.symlink(sensitiveFile, insideFile);
        symlinkCreated = true;
      } catch (err: unknown) {
        const error = err as { code?: string };
        console.warn(`[SKIP] Symlink creation denied by OS (${error.code}). Skipping symlink check.`);
      }

      if (symlinkCreated) {
        const verifyResult = await verifyEvidenceBundle(bundle);
        expect(verifyResult.status).toBe('failed');
        const item = verifyResult.items.find((i) => i.id === 'file_token');
        expect(item?.status).toBe('failed');
        expect(item?.details).toMatch(/Security boundary violation/i);
        expect(verifyResult.reasons.some((r) => r.includes('Security violation on "service-token.txt"'))).toBe(true);
      }

      await fs.promises.rm(outsideDir, { recursive: true, force: true });
    });
  });
});
