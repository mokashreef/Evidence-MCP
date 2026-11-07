import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { runCli } from '../src/cli.js';
import { saveBundle } from '../src/storage.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { EvidenceBundle } from '../src/types.js';

describe('Evidence MCP Standalone CLI', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-cli-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
    vi.restoreAllMocks();
  });

  it('prints help and exits with code 0 on --help', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const exitCode = await runCli(['--help']);
    expect(exitCode).toBe(0);
    expect(logSpy).toHaveBeenCalled();
  });

  it('prints version and exits with code 0 on --version', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    const exitCode = await runCli(['--version']);
    expect(exitCode).toBe(0);
    expect(logSpy.mock.calls.some((c) => c[0].includes('evidence-mcp v'))).toBe(true);
  });

  it('lists bundles in workspace with list command', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    // Empty workspace list
    const emptyExit = await runCli(['list', '--workspace', tempWorkspace]);
    expect(emptyExit).toBe(0);
    expect(logSpy.mock.calls.some((c) => c[0].includes('No evidence bundles found'))).toBe(true);

    // Add a bundle
    const bundle: EvidenceBundle = {
      id: 'bundle_cli_list_1',
      task: 'CLI Listing Task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {},
      assertions: [],
    };
    await saveBundle(bundle);

    const listExit = await runCli(['list', '--workspace', tempWorkspace]);
    expect(listExit).toBe(0);
    expect(logSpy.mock.calls.some((c) => c[0].includes('bundle_cli_list_1'))).toBe(true);
  });

  it('verifies a valid bundle and exits with code 0', async () => {
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {});

    const testFile = path.join(tempWorkspace, 'lib.ts');
    await fs.promises.writeFile(testFile, 'export const active = true;\n', 'utf8');
    const hashInfo = await computeFileSha256AndSize(testFile);

    const bundle: EvidenceBundle = {
      id: 'bundle_cli_verify_ok',
      task: 'Verify via CLI',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_lib',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'lib.ts',
            absolutePath: testFile,
            sha256: hashInfo.sha256,
            sizeBytes: hashInfo.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_lib',
          claim: 'Lib file exists and valid',
          evidenceIds: ['file_lib'],
          createdAt: new Date().toISOString(),
        },
      ],
    };
    await saveBundle(bundle);

    const exitCode = await runCli(['verify', 'bundle_cli_verify_ok', '--workspace', tempWorkspace]);
    expect(exitCode).toBe(0);
    expect(logSpy.mock.calls.some((c) => c[0].includes('VERIFIED'))).toBe(true);
  });

  it('fails verification and exits with code 1 when bundle files are modified', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const testFile = path.join(tempWorkspace, 'config.json');
    await fs.promises.writeFile(testFile, '{"v": 1}', 'utf8');
    const hashInfo = await computeFileSha256AndSize(testFile);

    const bundle: EvidenceBundle = {
      id: 'bundle_cli_stale',
      task: 'Stale test via CLI',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_cfg',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'config.json',
            absolutePath: testFile,
            sha256: hashInfo.sha256,
            sizeBytes: hashInfo.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_cfg',
          claim: 'Config version 1',
          evidenceIds: ['file_cfg'],
          createdAt: new Date().toISOString(),
        },
      ],
    };
    await saveBundle(bundle);

    // Modify file
    await fs.promises.writeFile(testFile, '{"v": 2}', 'utf8');

    const exitCode = await runCli(['verify', 'bundle_cli_stale', '--workspace', tempWorkspace]);
    expect(exitCode).toBe(1);
  });

  it('exports report directly to file when --output is provided', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});

    const testFile = path.join(tempWorkspace, 'index.ts');
    await fs.promises.writeFile(testFile, 'console.log("cli");\n', 'utf8');
    const hashInfo = await computeFileSha256AndSize(testFile);

    const bundle: EvidenceBundle = {
      id: 'bundle_cli_report',
      task: 'Export report CLI',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      evidence: {
        fileSnapshots: [
          {
            id: 'file_idx',
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: 'index.ts',
            absolutePath: testFile,
            sha256: hashInfo.sha256,
            sizeBytes: hashInfo.sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: 'assert_idx',
          claim: 'Index file ready',
          evidenceIds: ['file_idx'],
          createdAt: new Date().toISOString(),
        },
      ],
    };
    await saveBundle(bundle);

    const outHtml = path.join(tempWorkspace, 'reports', 'evidence.html');
    const exitCode = await runCli([
      'report',
      'bundle_cli_report',
      '--format',
      'html',
      '--output',
      outHtml,
      '--workspace',
      tempWorkspace,
    ]);

    expect(exitCode).toBe(0);
    expect(fs.existsSync(outHtml)).toBe(true);
    const content = await fs.promises.readFile(outHtml, 'utf8');
    expect(content).toContain('<!DOCTYPE html>');
    expect(content).toContain('bundle_cli_report');
  });

  it('returns code 1 on unknown commands or missing parameters', async () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await runCli(['unknown-command-xyz'])).toBe(1);
    expect(await runCli(['verify'])).toBe(1);
    expect(await runCli(['report'])).toBe(1);
    expect(errSpy).toHaveBeenCalled();
  });
});
