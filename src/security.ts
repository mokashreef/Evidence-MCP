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

  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
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
 * 2. Stays strictly inside the workspace boundary (both lexically and after canonical symlink resolution)
 * 3. Does not use symbolic links (rejected in v0.1 for clear security boundary)
 * 4. Does not target sensitive files (like .env, credentials, or private keys)
 */
export function assertSafeFilePath(workspacePath: string, inputPath: string): SafeFilePathResult {
  if (!inputPath || typeof inputPath !== 'string' || inputPath.trim() === '') {
    throw new Error('File path must be a non-empty string.');
  }

  if (inputPath.includes('\0')) {
    throw new Error('Invalid path: Null bytes detected.');
  }

  const resolvedWorkspace = path.resolve(workspacePath);
  let realWorkspace: string;
  try {
    realWorkspace = fs.realpathSync(resolvedWorkspace);
  } catch {
    realWorkspace = resolvedWorkspace;
  }

  const resolvedTarget = path.resolve(resolvedWorkspace, inputPath);

  // 1. Lexical path traversal check: target must be lexically within workspace
  const relativeLexical = path.relative(resolvedWorkspace, resolvedTarget);
  const isLexicalOutside = relativeLexical.startsWith('..') || path.isAbsolute(relativeLexical);

  if (isLexicalOutside) {
    throw new Error(
      `Path traversal rejected: "${inputPath}" resolves outside workspace boundary "${resolvedWorkspace}".`
    );
  }

  // 2. Upfront check for sensitive patterns on lexical path
  const normalizedLexical = relativeLexical.replace(/\\/g, '/');
  if (isSensitivePath(normalizedLexical)) {
    throw new Error(
      `Access to sensitive file blocked: "${inputPath}" matches restricted credential/secret patterns.`
    );
  }

  // 3. Reject symbolic links in v0.1 for clear security boundary
  try {
    const lstat = fs.lstatSync(resolvedTarget);
    if (lstat.isSymbolicLink()) {
      let targetReal = '';
      try {
        targetReal = fs.realpathSync(resolvedTarget);
      } catch {
        // broken symlink
      }
      throw new Error(
        `Symbolic links are rejected in v0.1 for file snapshots: "${inputPath}" is a symbolic link${
          targetReal ? ` pointing to "${targetReal}"` : ''
        }.`
      );
    }
  } catch (err: unknown) {
    if (err instanceof Error && err.message.includes('Symbolic links are rejected in v0.1')) {
      throw err;
    }
    // If file does not exist, realpathSync below will throw appropriate error
  }

  // 4. Resolve canonical filesystem realpath (resolves any intermediate directory symlinks)
  let realTarget: string;
  try {
    realTarget = fs.realpathSync(resolvedTarget);
  } catch {
    throw new Error(`File does not exist or cannot be resolved: ${resolvedTarget}`);
  }

  // 5. Verify canonical path stays strictly inside canonical workspace
  const relativeReal = path.relative(realWorkspace, realTarget);
  const isRealOutside = relativeReal.startsWith('..') || path.isAbsolute(relativeReal);

  if (isRealOutside) {
    throw new Error(
      `Symlink escape rejected: "${inputPath}" resolves outside workspace boundary "${realWorkspace}" to "${realTarget}".`
    );
  }

  // 6. Check against sensitive file patterns on real canonical path as well
  const normalizedReal = relativeReal.replace(/\\/g, '/');
  if (isSensitivePath(normalizedReal) || isSensitivePath(realTarget)) {
    throw new Error(
      `Access to sensitive file blocked: "${inputPath}" matches restricted credential/secret patterns.`
    );
  }

  return {
    absolutePath: realTarget,
    relativePath: normalizedReal,
  };
}

/**
 * Safely writes generated artifact content inside a workspace boundary, rejecting
 * path traversal, symlink escapes, and sensitive file overwrites.
 */
export async function writeWorkspaceOutputFile(
  workspacePath: string,
  outputPath: string,
  content: string
): Promise<string> {
  const absWorkspace = path.resolve(workspacePath);
  const resolvedOut = path.resolve(absWorkspace, outputPath);
  const relOut = path.relative(absWorkspace, resolvedOut);

  if (relOut.startsWith('..') || path.isAbsolute(relOut)) {
    throw new Error(`Path traversal rejected: outputPath "${outputPath}" escapes workspace.`);
  }

  const normalizedRel = relOut.replace(/\\/g, '/');
  if (isSensitivePath(normalizedRel) || isSensitivePath(resolvedOut)) {
    throw new Error(
      `Writing to sensitive path blocked: "${outputPath}" matches restricted file patterns.`
    );
  }

  await fs.promises.mkdir(path.dirname(resolvedOut), { recursive: true });
  const realParent = await fs.promises.realpath(path.dirname(resolvedOut));
  const realWs = await fs.promises.realpath(absWorkspace);
  const relRealParent = path.relative(realWs, realParent);

  if (relRealParent.startsWith('..') || path.isAbsolute(relRealParent)) {
    throw new Error(`Symlink escape rejected on outputPath "${outputPath}".`);
  }

  // If destination already exists as a symlink, ensure it resolves inside workspace
  if (fs.existsSync(resolvedOut)) {
    const stat = await fs.promises.lstat(resolvedOut);
    if (stat.isSymbolicLink()) {
      const realDest = await fs.promises.realpath(resolvedOut);
      const relDest = path.relative(realWs, realDest);
      if (relDest.startsWith('..') || path.isAbsolute(relDest)) {
        throw new Error(`Symlink escape rejected on outputPath "${outputPath}".`);
      }
    }
  }

  await fs.promises.writeFile(resolvedOut, content, 'utf8');
  return resolvedOut;
}
