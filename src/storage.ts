import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { EvidenceBundle, VerificationProof } from './types.js';
import { validateWorkspacePath } from './security.js';

// Global in-memory registry mapping bundleId to its workspacePath
const bundleWorkspaceRegistry = new Map<string, string>();

export function registerBundleWorkspace(bundleId: string, workspacePath: string): void {
  bundleWorkspaceRegistry.set(bundleId, path.resolve(workspacePath));
}

export function lookupBundleWorkspace(bundleId: string): string | undefined {
  return bundleWorkspaceRegistry.get(bundleId);
}

export function generateId(prefix: 'bundle' | 'git' | 'cmd' | 'file' | 'assert' | 'ast' | 'proof'): string {
  const shortId = crypto.randomUUID().slice(0, 8);
  return `${prefix}_${shortId}`;
}

export function getEvidenceDir(workspacePath: string): string {
  return path.join(path.resolve(workspacePath), '.evidence-mcp');
}

export function getBundlesDir(workspacePath: string): string {
  return path.join(getEvidenceDir(workspacePath), 'bundles');
}

export function getProofsDir(workspacePath: string): string {
  return path.join(getEvidenceDir(workspacePath), 'proofs');
}

export function getBundleFilePath(workspacePath: string, bundleId: string): string {
  // Guard bundleId to avoid traversal
  const sanitizedId = path.basename(bundleId);
  if (sanitizedId !== bundleId || bundleId.includes('..') || bundleId.includes('/') || bundleId.includes('\\')) {
    throw new Error(`Invalid bundleId format: ${bundleId}`);
  }
  return path.join(getBundlesDir(workspacePath), `${bundleId}.json`);
}

export function getProofFilePath(workspacePath: string, proofId: string): string {
  const sanitizedId = path.basename(proofId);
  if (sanitizedId !== proofId || proofId.includes('..') || proofId.includes('/') || proofId.includes('\\')) {
    throw new Error(`Invalid proofId format: ${proofId}`);
  }
  return path.join(getProofsDir(workspacePath), `${proofId}.json`);
}

/**
 * Persists an evidence bundle as a formatted JSON file atomically.
 */
export async function saveBundle(bundle: EvidenceBundle): Promise<void> {
  const workspacePath = validateWorkspacePath(bundle.workspacePath);
  const evidenceDir = getEvidenceDir(workspacePath);
  const bundlesDir = getBundlesDir(workspacePath);

  await fs.promises.mkdir(bundlesDir, { recursive: true });

  // Ensure .evidence-mcp/.gitignore exists so evidence files never pollute git status
  const gitignorePath = path.join(evidenceDir, '.gitignore');
  if (!fs.existsSync(gitignorePath)) {
    try {
      await fs.promises.writeFile(gitignorePath, '*\n', 'utf8');
    } catch {
      // Ignore if write fails
    }
  }

  const targetPath = getBundleFilePath(workspacePath, bundle.id);
  const tempPath = `${targetPath}.${crypto.randomUUID()}.tmp`;

  bundle.updatedAt = new Date().toISOString();
  const serialized = JSON.stringify(bundle, null, 2);

  await fs.promises.writeFile(tempPath, serialized, 'utf8');
  await fs.promises.rename(tempPath, targetPath);

  registerBundleWorkspace(bundle.id, workspacePath);
  if (bundle.workspaces) {
    for (const wsPath of Object.values(bundle.workspaces)) {
      registerBundleWorkspace(bundle.id, wsPath);
    }
  }
}

/**
 * Resolves the absolute directory path for a named workspace registered in the bundle.
 * Defaults to bundle.workspacePath if workspaceName is omitted, 'root', or 'default'.
 */
export function resolveWorkspaceForBundle(
  bundle: EvidenceBundle,
  workspaceName?: string
): string {
  if (!workspaceName || workspaceName === 'root' || workspaceName === 'default') {
    return path.resolve(bundle.workspacePath);
  }

  const customPath = bundle.workspaces?.[workspaceName];
  if (!customPath) {
    const available = ['root', ...Object.keys(bundle.workspaces || {})].join(', ');
    throw new Error(
      `Workspace "${workspaceName}" is not registered in bundle "${bundle.id}". Available workspaces: [${available}].`
    );
  }

  return path.resolve(customPath);
}

/**
 * Loads a bundle from disk. Resolves workspace from:
 * 1. workspaceHint if explicitly supplied
 * 2. In-memory registry
 * 3. Current working directory fallback
 */
export async function loadBundle(bundleId: string, workspaceHint?: string): Promise<EvidenceBundle> {
  if (!bundleId || typeof bundleId !== 'string' || bundleId.trim() === '') {
    throw new Error('bundleId is required and must be a non-empty string.');
  }

  const sanitizedId = path.basename(bundleId);
  if (sanitizedId !== bundleId) {
    throw new Error(`Invalid bundleId format: ${bundleId}`);
  }

  const candidateWorkspaces: string[] = [];

  if (workspaceHint) {
    candidateWorkspaces.push(path.resolve(workspaceHint));
  }

  const registered = lookupBundleWorkspace(bundleId);
  if (registered && !candidateWorkspaces.includes(registered)) {
    candidateWorkspaces.push(registered);
  }

  const cwd = path.resolve(process.cwd());
  if (!candidateWorkspaces.includes(cwd)) {
    candidateWorkspaces.push(cwd);
  }

  for (const candidate of candidateWorkspaces) {
    const candidateFile = getBundleFilePath(candidate, bundleId);
    if (fs.existsSync(candidateFile)) {
      try {
        const content = await fs.promises.readFile(candidateFile, 'utf8');
        const parsed = JSON.parse(content) as EvidenceBundle;
        registerBundleWorkspace(bundleId, parsed.workspacePath || candidate);
        return parsed;
      } catch (err: unknown) {
        throw new Error(
          `Corrupted evidence bundle file at "${candidateFile}": ${(err as Error).message}`
        );
      }
    }
  }

  throw new Error(
    `Evidence bundle "${bundleId}" was not found in checked workspaces: [${candidateWorkspaces.join(', ')}].`
  );
}

/**
 * Lists all bundles stored in the given workspace.
 */
export async function listBundles(workspacePath: string): Promise<EvidenceBundle[]> {
  const bundlesDir = getBundlesDir(workspacePath);
  if (!fs.existsSync(bundlesDir)) {
    return [];
  }

  const entries = await fs.promises.readdir(bundlesDir);
  const bundles: EvidenceBundle[] = [];

  for (const entry of entries) {
    if (entry.endsWith('.json') && !entry.endsWith('.tmp')) {
      const fullPath = path.join(bundlesDir, entry);
      try {
        const content = await fs.promises.readFile(fullPath, 'utf8');
        bundles.push(JSON.parse(content) as EvidenceBundle);
      } catch {
        // Ignore unreadable or corrupted files during directory listing
      }
    }
  }

  return bundles;
}

/**
 * Persists a verification proof as a formatted JSON file atomically under .evidence-mcp/proofs/
 */
export async function saveProof(proof: VerificationProof, workspacePath: string): Promise<void> {
  const ws = validateWorkspacePath(workspacePath);
  const proofsDir = getProofsDir(ws);

  if (!fs.existsSync(proofsDir)) {
    await fs.promises.mkdir(proofsDir, { recursive: true });
  }

  const proofFilePath = getProofFilePath(ws, proof.id);
  const tempFilePath = `${proofFilePath}.tmp`;

  const serialized = JSON.stringify(proof, null, 2);
  await fs.promises.writeFile(tempFilePath, serialized, 'utf8');
  await fs.promises.rename(tempFilePath, proofFilePath);
}

/**
 * Loads a verification proof from disk.
 */
export async function loadProof(proofId: string, workspaceHint?: string): Promise<VerificationProof> {
  if (!proofId || typeof proofId !== 'string' || proofId.trim() === '') {
    throw new Error('proofId is required and must be a non-empty string.');
  }

  const sanitizedId = path.basename(proofId);
  if (sanitizedId !== proofId) {
    throw new Error(`Invalid proofId format: ${proofId}`);
  }

  const candidateWorkspaces: string[] = [];
  if (workspaceHint) {
    candidateWorkspaces.push(path.resolve(workspaceHint));
  }
  const cwd = path.resolve(process.cwd());
  if (!candidateWorkspaces.includes(cwd)) {
    candidateWorkspaces.push(cwd);
  }

  for (const candidate of candidateWorkspaces) {
    const candidateFile = getProofFilePath(candidate, proofId);
    if (fs.existsSync(candidateFile)) {
      try {
        const content = await fs.promises.readFile(candidateFile, 'utf8');
        return JSON.parse(content) as VerificationProof;
      } catch (err: unknown) {
        throw new Error(`Corrupted proof file at "${candidateFile}": ${(err as Error).message}`);
      }
    }
  }

  throw new Error(`Verification proof "${proofId}" was not found in checked workspaces: [${candidateWorkspaces.join(', ')}].`);
}

/**
 * Lists all verification proofs stored in the given workspace.
 */
export async function listProofs(workspacePath: string): Promise<VerificationProof[]> {
  const proofsDir = getProofsDir(workspacePath);
  if (!fs.existsSync(proofsDir)) {
    return [];
  }

  const entries = await fs.promises.readdir(proofsDir);
  const proofs: VerificationProof[] = [];

  for (const entry of entries) {
    if (entry.endsWith('.json') && !entry.endsWith('.tmp')) {
      const fullPath = path.join(proofsDir, entry);
      try {
        const content = await fs.promises.readFile(fullPath, 'utf8');
        proofs.push(JSON.parse(content) as VerificationProof);
      } catch {
        // Ignore unreadable or corrupted files during directory listing
      }
    }
  }

  return proofs;
}
