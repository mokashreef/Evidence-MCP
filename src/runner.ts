import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { validateWorkspacePath } from './security.js';

export const ALLOWED_COMMANDS = new Set<string>([
  'npm',
  'npx',
  'node',
  'git',
  'tsc',
  'vitest',
  'jest',
  'pnpm',
  'yarn',
  'bun',
  'deno',
  'cargo',
  'go',
  'python',
  'python3',
  'pip',
  'pytest',
  'mvn',
  'gradle',
]);

export const FORBIDDEN_COMMANDS = new Set<string>([
  'sh',
  'bash',
  'zsh',
  'csh',
  'fish',
  'powershell',
  'pwsh',
  'cmd',
  'cmd.exe',
  'rm',
  'del',
  'erase',
  'rmdir',
  'rd',
  'format',
  'dd',
  'mkfs',
  'curl',
  'wget',
  'nc',
  'ncat',
  'netcat',
  'ssh',
  'scp',
  'sftp',
  'ftp',
  'telnet',
  'sudo',
  'su',
  'chmod',
  'chown',
  'attrib',
]);

export const SECRET_PATTERNS = [
  /key/i,
  /secret/i,
  /token/i,
  /auth/i,
  /pass/i,
  /password/i,
  /credential/i,
  /private/i,
  /cert/i,
];

export const ALLOWED_ENV_VARS = new Set<string>([
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'COMSPEC',
  'TEMP',
  'TMP',
  'USERPROFILE',
  'HOMEDRIVE',
  'HOMEPATH',
  'HOME',
  'LANG',
  'LC_ALL',
  'TERM',
  'NODE_ENV',
  'NODE_PATH',
]);

export const MAX_OUTPUT_CHARS = 512 * 1024; // 512 KB
export const DEFAULT_TIMEOUT_MS = 30_000;   // 30 seconds
export const MAX_TIMEOUT_MS = 120_000;      // 2 minutes

export interface RunnerExecutionOptions {
  command: string;
  args?: string[];
  cwd?: string;
  timeoutMs?: number;
  env?: Record<string, string>;
  workspacePath: string;
}

export interface RunnerExecutionResult {
  command: string;
  args: string[];
  exitCode: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  executedAt: string;
  timedOut: boolean;
  provenance: 'server_executed';
}

/**
 * Validates whether a command executable is permitted under the runner policy.
 */
export function isCommandAllowed(command: string): boolean {
  const normalized = command.trim().toLowerCase();

  // Reject paths (slashes, backslashes, path traversal)
  if (normalized.includes('/') || normalized.includes('\\') || normalized.includes('..')) {
    return false;
  }

  // Strip .exe / .cmd extension if provided
  const baseName = normalized.replace(/\.(exe|cmd|bat)$/i, '');

  if (FORBIDDEN_COMMANDS.has(baseName)) {
    return false;
  }

  return ALLOWED_COMMANDS.has(baseName);
}

/**
 * Sanitizes process environment variables by scrubbing secrets and tokens.
 */
export function sanitizeEnvironment(customEnv?: Record<string, string>): NodeJS.ProcessEnv {
  const safeEnv: NodeJS.ProcessEnv = {};

  // Copy safe system env keys
  for (const [key, value] of Object.entries(process.env)) {
    if (!value) continue;
    const upperKey = key.toUpperCase();

    // Must be in safe list or not contain secret patterns
    if (ALLOWED_ENV_VARS.has(upperKey)) {
      safeEnv[key] = value;
      continue;
    }

    const isSensitive = SECRET_PATTERNS.some((pat) => pat.test(key));
    if (!isSensitive) {
      safeEnv[key] = value;
    }
  }

  // Merge custom caller env, strictly rejecting any sensitive keys
  if (customEnv) {
    for (const [key, value] of Object.entries(customEnv)) {
      const isSensitive = SECRET_PATTERNS.some((pat) => pat.test(key));
      if (isSensitive) {
        throw new Error(`Execution policy violation: custom environment variable "${key}" contains sensitive secret keywords.`);
      }
      safeEnv[key] = value;
    }
  }

  return safeEnv;
}

function getNpmCliPath(): string | null {
  const nodeDir = path.dirname(process.execPath);
  const candidates = [
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npm-cli.js'),
    path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npm-cli.js'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function getNpxCliPath(): string | null {
  const nodeDir = path.dirname(process.execPath);
  const candidates = [
    path.join(nodeDir, 'node_modules', 'npm', 'bin', 'npx-cli.js'),
    path.join(nodeDir, '..', 'lib', 'node_modules', 'npm', 'bin', 'npx-cli.js'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * Resolves the executable invocation safely without shell interpretation.
 */
export function resolveCommandInvocation(
  command: string,
  args: string[]
): { binary: string; finalArgs: string[] } {
  const normalized = command.trim().toLowerCase().replace(/\.(exe|cmd|bat)$/i, '');

  if (normalized === 'node') {
    return { binary: process.execPath, finalArgs: [...args] };
  }

  if (process.platform === 'win32') {
    if (normalized === 'npm') {
      const npmCli = getNpmCliPath();
      if (npmCli) {
        return { binary: process.execPath, finalArgs: [npmCli, ...args] };
      }
    }
    if (normalized === 'npx') {
      const npxCli = getNpxCliPath();
      if (npxCli) {
        return { binary: process.execPath, finalArgs: [npxCli, ...args] };
      }
    }
  }

  return { binary: command, finalArgs: [...args] };
}

let activeProcessCount = 0;
let maxConcurrency = 4;
const waitingQueue: Array<() => void> = [];

export function setMaxRunnerConcurrency(n: number): void {
  maxConcurrency = Math.max(1, n);
}

export function getActiveRunnerProcesses(): number {
  return activeProcessCount;
}

async function acquireExecutionSlot(): Promise<void> {
  if (activeProcessCount < maxConcurrency) {
    activeProcessCount++;
    return;
  }
  return new Promise<void>((resolve) => {
    waitingQueue.push(() => {
      activeProcessCount++;
      resolve();
    });
  });
}

function releaseExecutionSlot(): void {
  activeProcessCount--;
  if (waitingQueue.length > 0 && activeProcessCount < maxConcurrency) {
    const next = waitingQueue.shift();
    if (next) next();
  }
}

/**
 * Executes an approved command within a strictly bounded runner environment.
 */
export async function executeSandboxedCommand(
  options: RunnerExecutionOptions
): Promise<RunnerExecutionResult> {
  const { command, args = [], cwd, workspacePath } = options;
  const timeoutMs = Math.min(
    Math.max(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 500),
    MAX_TIMEOUT_MS
  );

  // 1. Check for null bytes in command and args
  if (command.includes('\0')) {
    throw new Error('Command contains forbidden null byte character.');
  }
  for (const arg of args) {
    if (arg.includes('\0')) {
      throw new Error(`Argument "${arg}" contains forbidden null byte character.`);
    }
  }

  // 2. Validate command security policy
  if (!isCommandAllowed(command)) {
    throw new Error(
      `Execution policy violation: Command "${command}" is not permitted by Evidence MCP. Allowed commands: [${Array.from(ALLOWED_COMMANDS).join(', ')}].`
    );
  }

  // 2. Validate workspace containment
  const resolvedWorkspace = validateWorkspacePath(workspacePath);
  let effectiveCwd = resolvedWorkspace;

  if (cwd) {
    const candidateCwd = path.resolve(resolvedWorkspace, cwd);
    // Ensure candidateCwd is within workspace
    const relative = path.relative(resolvedWorkspace, candidateCwd);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`Execution policy violation: Working directory "${cwd}" escapes workspace boundary.`);
    }
    if (!fs.existsSync(candidateCwd)) {
      throw new Error(`Working directory "${cwd}" does not exist in workspace.`);
    }
    const stat = fs.statSync(candidateCwd);
    if (!stat.isDirectory()) {
      throw new Error(`Working directory "${cwd}" is not a directory.`);
    }
    effectiveCwd = candidateCwd;
  }

  // 3. Prepare sanitized environment and invocation
  const env = sanitizeEnvironment(options.env);
  const { binary, finalArgs } = resolveCommandInvocation(command, args);

  await acquireExecutionSlot();
  const startTime = Date.now();
  const executedAt = new Date().toISOString();

  try {
    return await new Promise<RunnerExecutionResult>((resolve) => {
    let stdoutBuffer = '';
    let stderrBuffer = '';
    let timedOut = false;
    let killed = false;
    let stdoutTruncated = false;
    let stderrTruncated = false;

    let child;
    try {
      child = spawn(binary, finalArgs, {
        cwd: effectiveCwd,
        env,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    } catch (err: unknown) {
      const durationMs = Date.now() - startTime;
      return resolve({
        command,
        args,
        exitCode: 1,
        stdout: '',
        stderr: `Failed to spawn process "${command}": ${(err as Error).message}`,
        durationMs,
        executedAt,
        timedOut: false,
        provenance: 'server_executed',
      });
    }

    const timer = setTimeout(() => {
      timedOut = true;
      killed = true;
      try {
        child.kill('SIGTERM');
        // Force kill after 1 second if still running
        setTimeout(() => {
          try {
            child.kill('SIGKILL');
          } catch {
            // Process may already be dead
          }
        }, 1000).unref();
      } catch {
        // Ignore kill errors
      }
    }, timeoutMs);

    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      if (stdoutBuffer.length < MAX_OUTPUT_CHARS) {
        const remaining = MAX_OUTPUT_CHARS - stdoutBuffer.length;
        stdoutBuffer += chunk.slice(0, remaining);
      } else if (!stdoutTruncated) {
        stdoutTruncated = true;
        stdoutBuffer += '\n... [Evidence MCP: stdout truncated after 512KB]';
      }
    });

    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk: string) => {
      if (stderrBuffer.length < MAX_OUTPUT_CHARS) {
        const remaining = MAX_OUTPUT_CHARS - stderrBuffer.length;
        stderrBuffer += chunk.slice(0, remaining);
      } else if (!stderrTruncated) {
        stderrTruncated = true;
        stderrBuffer += '\n... [Evidence MCP: stderr truncated after 512KB]';
      }
    });

    child.on('error', (err: Error) => {
      clearTimeout(timer);
      const durationMs = Date.now() - startTime;
      resolve({
        command,
        args,
        exitCode: 1,
        stdout: stdoutBuffer,
        stderr: (stderrBuffer + `\nProcess execution error: ${err.message}`).trim(),
        durationMs,
        executedAt,
        timedOut: false,
        provenance: 'server_executed',
      });
    });

    child.on('close', (code: number | null) => {
      clearTimeout(timer);
      const durationMs = Date.now() - startTime;

      if (timedOut) {
        stderrBuffer += `\n[Evidence MCP: Process timed out after ${timeoutMs}ms]`;
      }

      resolve({
        command,
        args,
        exitCode: timedOut ? 124 : (code ?? 0),
        stdout: stdoutBuffer,
        stderr: stderrBuffer,
        durationMs,
        executedAt,
        timedOut,
        provenance: 'server_executed',
      });
    });
  });
} finally {
  releaseExecutionSlot();
}
}
