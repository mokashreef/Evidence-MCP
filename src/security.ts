import path from 'node:path';
import fs from 'node:fs';

/**
 * Common sensitive file patterns that should never be read or snapshotted.
 */
const SENSITIVE_FILE_PATTERNS: RegExp[] = [
  /^\.env(\..+)?$/i, // .env, .env.local, .env.production, etc.
  /\.env$/i,
  /^id_(rsa|dsa|ecdsa|ed25519)(\..+)?$/i,
  /\.(pem|key|pfx|p12|pkcs12|keystore)$/i,
  /^(credentials|client_secret|service[-_]account.*|token|auth|secrets?)\.(json|ya?ml)$/i,
  /^\.(npmrc|pypirc|netrc|htpasswd)$/i,
  /\.git[\/\\]config$/i,
  /(\.ssh|\.aws|\.gnupg)[\/\\]/i,
];

/**
 * Validates and normalizes the workspace path.
 * Checks that the directory exists and is a directory.
 */
export function validateWorkspacePath(workspacePath: string): string {
  if (!workspacePath || typeof workspacePath !== 'string' || workspacePath.trim() === '') {
    throw new Error('Workspace path must be a non-empty string.');
  }

  const resolved = path.resolve(workspacePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Workspace path does not exist: ${resolved}`);
  }

  const stats = fs.statSync(resolved);
  if (!stats.isDirectory()) {
    throw new Error(`Workspace path is not a directory: ${resolved}`);
  }

  return resolved;
}

/**
 * Checks whether a given path matches sensitive file or credential patterns.
 */
export function isSensitivePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  const basename = path.basename(normalized);

  // Template / example environment files are not sensitive secrets
  const lowerBase = basename.toLowerCase();
  if (lowerBase === '.env.example' || lowerBase === '.env.sample' || lowerBase === '.env.template') {
    return false;
  }

  for (const pattern of SENSITIVE_FILE_PATTERNS) {
    if (pattern.test(basename) || pattern.test(normalized)) {
      return true;
    }
  }

  return false;
}

export interface SafeFilePathResult {
  absolutePath: string;
  relativePath: string;
}

/**
 * Verifies that a target file path:
 * 1. Has no null bytes
 * 2. Stays strictly inside the workspace (no path traversal)
 * 3. Does not target sensitive files (like .env or private keys)
 */
export function assertSafeFilePath(workspacePath: string, inputPath: string): SafeFilePathResult {
  if (!inputPath || typeof inputPath !== 'string' || inputPath.trim() === '') {
    throw new Error('File path must be a non-empty string.');
  }

  if (inputPath.includes('\0')) {
    throw new Error('Invalid path: Null bytes detected.');
  }

  const resolvedWorkspace = path.resolve(workspacePath);
  const resolvedTarget = path.resolve(resolvedWorkspace, inputPath);

  // Path traversal check: target must be within workspace
  const relative = path.relative(resolvedWorkspace, resolvedTarget);
  const isOutside = relative.startsWith('..') || path.isAbsolute(relative);

  if (isOutside) {
    throw new Error(
      `Path traversal rejected: "${inputPath}" resolves outside workspace boundary "${resolvedWorkspace}".`
    );
  }

  // Check against sensitive file patterns using both relative path and basename
  const normalizedRelative = relative.replace(/\\/g, '/');
  if (isSensitivePath(normalizedRelative)) {
    throw new Error(
      `Access to sensitive file blocked: "${normalizedRelative}" matches restricted credential/secret patterns.`
    );
  }

  return {
    absolutePath: resolvedTarget,
    relativePath: normalizedRelative,
  };
}
