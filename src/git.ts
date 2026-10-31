import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import fs from 'node:fs';

const execFileAsync = promisify(execFile);

export interface GitInspectionResult {
  branch: string;
  headCommit: string;
  statusShort: string;
  diffCheck: string;
  isClean: boolean;
}

/**
 * Executes a read-only git command safely within the given workspace.
 * Uses execFile directly (no shell injection risk) and applies a 5s timeout.
 */
async function runSafeGitCommand(workspacePath: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync('git', args, {
      cwd: workspacePath,
      timeout: 5000,
      encoding: 'utf8',
      windowsHide: true,
      maxBuffer: 10 * 1024 * 1024,
    });
    return (stdout || '').trim();
  } catch (err: unknown) {
    const error = err as { stdout?: string; stderr?: string; message?: string; code?: number };
    // git diff --check exits with code 2 if whitespace errors are found, but still produces stdout/stderr
    if (args.includes('--check') && error.stdout !== undefined) {
      return (error.stdout || error.stderr || '').trim();
    }
    throw new Error(`Git command failed [git ${args.join(' ')}]: ${error.stderr || error.message || 'Unknown error'}`);
  }
}

/**
 * Checks whether the workspace path is inside a Git repository.
 */
export async function isGitRepository(workspacePath: string): Promise<boolean> {
  try {
    const output = await runSafeGitCommand(workspacePath, ['rev-parse', '--is-inside-work-tree']);
    return output.toLowerCase() === 'true';
  } catch {
    // Also check if .git exists on disk directly as a fallback
    return fs.existsSync(path.join(workspacePath, '.git'));
  }
}

/**
 * Safely inspects the git state without modifying any repository data.
 */
export async function captureGitState(workspacePath: string): Promise<GitInspectionResult> {
  const isRepo = await isGitRepository(workspacePath);
  if (!isRepo) {
    throw new Error(`Workspace at "${workspacePath}" is not a Git repository.`);
  }

  // 1. Get current branch name
  let branch = '';
  try {
    branch = await runSafeGitCommand(workspacePath, ['rev-parse', '--abbrev-ref', 'HEAD']);
  } catch {
    branch = 'unknown';
  }

  // 2. Get HEAD commit hash
  let headCommit = '';
  try {
    headCommit = await runSafeGitCommand(workspacePath, ['rev-parse', 'HEAD']);
  } catch {
    headCommit = 'NONE'; // Empty repository without initial commit
  }

  // 3. Short status (excluding .evidence-mcp to prevent self-dirtying)
  let statusShort = '';
  try {
    statusShort = await runSafeGitCommand(workspacePath, ['status', '--short', '--', ':!.evidence-mcp']);
  } catch {
    statusShort = '';
  }

  // 4. Git diff check (checks for whitespace errors and conflict markers)
  let diffCheck = '';
  try {
    diffCheck = await runSafeGitCommand(workspacePath, ['diff', '--check', '--', ':!.evidence-mcp']);
  } catch (err: unknown) {
    diffCheck = (err as Error).message || '';
  }

  const isClean = statusShort.length === 0;

  return {
    branch,
    headCommit,
    statusShort,
    diffCheck: diffCheck || 'clean',
    isClean,
  };
}
