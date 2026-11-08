import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import {
  EvidenceBundle,
  VerificationResult,
  VerificationProof,
  ReplayResult,
  ReplayStepResult,
  GitEvidence,
  FileSnapshotEvidence,
  CommandEvidence,
  AstEvidence,
} from './types.js';
import {
  getCanonicalPayload,
  canonicalStringify,
  computeKeyFingerprint,
  getOrCreateLocalKeyPair,
} from './attestation.js';
import { generateId, saveProof, resolveWorkspaceForBundle } from './storage.js';
import { computeFileSha256AndSize } from './hasher.js';
import { captureGitState } from './git.js';
import { assertSafeFilePath } from './security.js';
import { parseSourceSymbols } from './ast.js';
import { executeSandboxedCommand } from './runner.js';

/**
 * Computes a deterministic SHA-256 digest of the canonical bundle representation.
 */
export function computeBundleDigest(bundle: EvidenceBundle): string {
  const canonicalPayload = getCanonicalPayload(bundle);
  return crypto.createHash('sha256').update(canonicalPayload).digest('hex');
}

/**
 * Computes canonical payload buffer of a proof object (excluding signature) for cryptographic signing/verification.
 */
export function getCanonicalProofPayload(proof: Omit<VerificationProof, 'signature'>): Buffer {
  const canonicalObject: Record<string, unknown> = {
    id: proof.id,
    bundleId: proof.bundleId,
    bundleDigest: proof.bundleDigest,
    verdict: proof.verdict,
    summary: proof.summary,
    verifiedAt: proof.verifiedAt,
    signer: {
      algorithm: proof.signer.algorithm,
      publicKeyPem: proof.signer.publicKeyPem.trim(),
      keyFingerprint: proof.signer.keyFingerprint,
    },
    itemCount: proof.itemCount,
    environment: {
      platform: proof.environment.platform,
      nodeVersion: proof.environment.nodeVersion,
      arch: proof.environment.arch,
    },
  };

  const jsonString = canonicalStringify(canonicalObject);
  return Buffer.from(jsonString, 'utf8');
}

/**
 * Creates and cryptographically signs a portable verification proof for an evidence bundle.
 */
export async function createVerificationProof(options: {
  bundle: EvidenceBundle;
  verification: VerificationResult;
  workspacePath: string;
  privateKeyPem?: string;
}): Promise<VerificationProof> {
  const { bundle, verification, workspacePath, privateKeyPem } = options;

  let privKey: string;
  let pubKey: string;
  let fingerprint: string;

  if (privateKeyPem) {
    privKey = privateKeyPem;
    const pubObj = crypto.createPublicKey(privKey);
    pubKey = pubObj.export({ type: 'spki', format: 'pem' }) as string;
    fingerprint = computeKeyFingerprint(pubKey);
  } else {
    const keyPair = await getOrCreateLocalKeyPair(workspacePath);
    privKey = keyPair.privateKeyPem;
    pubKey = keyPair.publicKeyPem;
    fingerprint = keyPair.fingerprint;
  }

  const bundleDigest = computeBundleDigest(bundle);
  const proofId = generateId('proof');

  const unsignedProof: Omit<VerificationProof, 'signature'> = {
    id: proofId,
    bundleId: bundle.id,
    bundleDigest,
    verdict: verification.status,
    summary: verification.summary,
    verifiedAt: verification.verifiedAt || new Date().toISOString(),
    signer: {
      algorithm: 'ed25519',
      publicKeyPem: pubKey,
      keyFingerprint: fingerprint,
    },
    itemCount: verification.items.length,
    environment: {
      platform: os.platform(),
      nodeVersion: process.version,
      arch: os.arch(),
    },
  };

  const canonicalPayload = getCanonicalProofPayload(unsignedProof);
  const signatureBuffer = crypto.sign(null, canonicalPayload, privKey);
  const signature = signatureBuffer.toString('base64');

  const completeProof: VerificationProof = {
    ...unsignedProof,
    signature,
  };

  await saveProof(completeProof, workspacePath);
  return completeProof;
}

/**
 * Verifies the cryptographic signature and bundle consistency of an exported proof.
 */
export function verifyProofSignature(
  proof: VerificationProof,
  expectedBundle?: EvidenceBundle
): {
  valid: boolean;
  reason?: string;
  bundleDigestMatches?: boolean;
} {
  try {
    const { signature, ...unsignedProof } = proof;
    const canonicalPayload = getCanonicalProofPayload(unsignedProof);
    const signatureBuffer = Buffer.from(signature, 'base64');

    const isSigValid = crypto.verify(
      null,
      canonicalPayload,
      proof.signer.publicKeyPem,
      signatureBuffer
    );

    if (!isSigValid) {
      return {
        valid: false,
        reason: 'Proof signature verification failed: cryptographic signature does not match.',
      };
    }

    // Optional check: verify computed fingerprint matches embedded key
    const computedFingerprint = computeKeyFingerprint(proof.signer.publicKeyPem);
    if (computedFingerprint !== proof.signer.keyFingerprint) {
      return {
        valid: false,
        reason: `Signer key fingerprint mismatch: embedded ${proof.signer.keyFingerprint} != computed ${computedFingerprint}`,
      };
    }

    let bundleDigestMatches: boolean | undefined;
    if (expectedBundle) {
      const currentDigest = computeBundleDigest(expectedBundle);
      bundleDigestMatches = currentDigest === proof.bundleDigest;
      if (!bundleDigestMatches) {
        return {
          valid: false,
          bundleDigestMatches: false,
          reason: `Bundle digest mismatch: current bundle has changed since proof was issued (proof: ${proof.bundleDigest.slice(0, 16)}..., current: ${currentDigest.slice(0, 16)}...).`,
        };
      }
    }

    return {
      valid: true,
      bundleDigestMatches,
    };
  } catch (err: unknown) {
    return {
      valid: false,
      reason: `Proof verification error: ${(err as Error).message}`,
    };
  }
}

interface ReplayChronologicalItem {
  id: string;
  type: 'git' | 'file' | 'command' | 'ast';
  timestamp: string;
  data: GitEvidence | FileSnapshotEvidence | CommandEvidence | AstEvidence;
}

/**
 * Replays evidence chronologically, validating consistency and optionally re-executing server-executed commands.
 */
export async function replayEvidenceBundle(
  bundle: EvidenceBundle,
  options: {
    reExecuteCommands?: boolean;
    workspacePath?: string;
  } = {}
): Promise<ReplayResult> {
  const { reExecuteCommands = false, workspacePath } = options;
  const rootWorkspace = path.resolve(workspacePath || bundle.workspacePath);

  // 1. Gather all evidence items with their timestamps
  const chronologicalItems: ReplayChronologicalItem[] = [];

  if (bundle.evidence.git) {
    for (const g of bundle.evidence.git) {
      chronologicalItems.push({
        id: g.id,
        type: 'git',
        timestamp: g.capturedAt,
        data: g,
      });
    }
  }

  if (bundle.evidence.fileSnapshots) {
    for (const f of bundle.evidence.fileSnapshots) {
      chronologicalItems.push({
        id: f.id,
        type: 'file',
        timestamp: f.capturedAt,
        data: f,
      });
    }
  }

  if (bundle.evidence.commands) {
    for (const c of bundle.evidence.commands) {
      chronologicalItems.push({
        id: c.id,
        type: 'command',
        timestamp: c.executedAt || c.recordedAt,
        data: c,
      });
    }
  }

  if (bundle.evidence.ast) {
    for (const a of bundle.evidence.ast) {
      chronologicalItems.push({
        id: a.id,
        type: 'ast',
        timestamp: a.capturedAt,
        data: a,
      });
    }
  }

  // Sort chronologically ascending
  chronologicalItems.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

  const steps: ReplayStepResult[] = [];
  let passedSteps = 0;
  let divergedSteps = 0;

  for (let index = 0; index < chronologicalItems.length; index++) {
    const item = chronologicalItems[index];
    const stepNumber = index + 1;

    if (item.type === 'git') {
      const gitData = item.data as GitEvidence;
      const targetWs = resolveWorkspaceForBundle(bundle, gitData.workspaceName);
      try {
        const liveGit = await captureGitState(targetWs);
        const branchMatches = liveGit.branch === gitData.branch;
        const commitMatches = liveGit.headCommit === gitData.headCommit;

        if (branchMatches && commitMatches) {
          steps.push({
            index: stepNumber,
            evidenceId: gitData.id,
            type: 'git',
            description: `Git state: ${gitData.branch}@${gitData.headCommit.slice(0, 7)}`,
            originalTimestamp: item.timestamp,
            status: 'passed',
            details: `Git state matches recorded HEAD and branch.`,
          });
          passedSteps++;
        } else {
          steps.push({
            index: stepNumber,
            evidenceId: gitData.id,
            type: 'git',
            description: `Git state: ${gitData.branch}@${gitData.headCommit.slice(0, 7)}`,
            originalTimestamp: item.timestamp,
            status: 'diverged',
            details: `Git state diverged: live branch is ${liveGit.branch}, HEAD is ${liveGit.headCommit.slice(0, 7)}.`,
          });
          divergedSteps++;
        }
      } catch (err: unknown) {
        steps.push({
          index: stepNumber,
          evidenceId: gitData.id,
          type: 'git',
          description: `Git inspection error`,
          originalTimestamp: item.timestamp,
          status: 'failed',
          details: (err as Error).message,
        });
        divergedSteps++;
      }
    } else if (item.type === 'file') {
      const fileData = item.data as FileSnapshotEvidence;
      const targetWs = resolveWorkspaceForBundle(bundle, fileData.workspaceName);
      try {
        const safePath = assertSafeFilePath(targetWs, fileData.path);
        if (!fs.existsSync(safePath.absolutePath)) {
          steps.push({
            index: stepNumber,
            evidenceId: fileData.id,
            type: 'file',
            description: `File snapshot: ${fileData.path}`,
            originalTimestamp: item.timestamp,
            status: 'failed',
            details: `Target file no longer exists on disk.`,
          });
          divergedSteps++;
          continue;
        }

        const liveHash = await computeFileSha256AndSize(safePath.absolutePath);
        if (liveHash.sha256 === fileData.sha256 && liveHash.sizeBytes === fileData.sizeBytes) {
          steps.push({
            index: stepNumber,
            evidenceId: fileData.id,
            type: 'file',
            description: `File snapshot: ${fileData.path}`,
            originalTimestamp: item.timestamp,
            status: 'passed',
            details: `SHA-256 and size match recorded snapshot (${fileData.sizeBytes} bytes).`,
          });
          passedSteps++;
        } else {
          steps.push({
            index: stepNumber,
            evidenceId: fileData.id,
            type: 'file',
            description: `File snapshot: ${fileData.path}`,
            originalTimestamp: item.timestamp,
            status: 'diverged',
            details: `File content has changed on disk since snapshot.`,
          });
          divergedSteps++;
        }
      } catch (err: unknown) {
        steps.push({
          index: stepNumber,
          evidenceId: fileData.id,
          type: 'file',
          description: `File snapshot check error: ${fileData.path}`,
          originalTimestamp: item.timestamp,
          status: 'failed',
          details: (err as Error).message,
        });
        divergedSteps++;
      }
    } else if (item.type === 'command') {
      const cmdData = item.data as CommandEvidence;
      const targetWs = resolveWorkspaceForBundle(bundle, cmdData.workspaceName);
      const isServer = cmdData.provenance === 'server_executed';

      if (isServer && reExecuteCommands) {
        try {
          const runRes = await executeSandboxedCommand({
            command: cmdData.command,
            args: cmdData.args || [],
            cwd: cmdData.cwd,
            timeoutMs: cmdData.durationMs ? Math.max(cmdData.durationMs * 2, 10000) : 30000,
            workspacePath: targetWs,
          });

          const exitCodeMatches = runRes.exitCode === cmdData.exitCode;
          if (exitCodeMatches) {
            steps.push({
              index: stepNumber,
              evidenceId: cmdData.id,
              type: 'command',
              description: `Command: ${cmdData.command} ${(cmdData.args || []).join(' ')}`,
              originalTimestamp: item.timestamp,
              status: 'passed',
              details: `Command re-executed deterministically with exit code ${runRes.exitCode}.`,
              reproducedExecution: {
                exitCode: runRes.exitCode,
                exitCodeMatches: true,
                durationMs: runRes.durationMs,
              },
            });
            passedSteps++;
          } else {
            steps.push({
              index: stepNumber,
              evidenceId: cmdData.id,
              type: 'command',
              description: `Command: ${cmdData.command} ${(cmdData.args || []).join(' ')}`,
              originalTimestamp: item.timestamp,
              status: 'diverged',
              details: `Re-execution exit code mismatch: original was ${cmdData.exitCode}, reproduced was ${runRes.exitCode}.`,
              reproducedExecution: {
                exitCode: runRes.exitCode,
                exitCodeMatches: false,
                durationMs: runRes.durationMs,
              },
            });
            divergedSteps++;
          }
        } catch (err: unknown) {
          steps.push({
            index: stepNumber,
            evidenceId: cmdData.id,
            type: 'command',
            description: `Command re-execution error`,
            originalTimestamp: item.timestamp,
            status: 'failed',
            details: (err as Error).message,
          });
          divergedSteps++;
        }
      } else {
        // Recorded or un-reexecuted command step
        steps.push({
          index: stepNumber,
          evidenceId: cmdData.id,
          type: 'command',
          description: `Command record: ${cmdData.command} (${cmdData.provenance})`,
          originalTimestamp: item.timestamp,
          status: 'passed',
          details: `Command log verified in sequence (Exit ${cmdData.exitCode}, provenance: ${cmdData.provenance}).`,
        });
        passedSteps++;
      }
    } else if (item.type === 'ast') {
      const astData = item.data as AstEvidence;
      const targetWs = resolveWorkspaceForBundle(bundle, astData.workspaceName);
      try {
        const safePath = assertSafeFilePath(targetWs, astData.filePath);
        if (!fs.existsSync(safePath.absolutePath)) {
          steps.push({
            index: stepNumber,
            evidenceId: astData.id,
            type: 'ast',
            description: `AST symbols: ${astData.filePath}`,
            originalTimestamp: item.timestamp,
            status: 'failed',
            details: `File deleted or moved on disk.`,
          });
          divergedSteps++;
          continue;
        }

        const liveContent = await fs.promises.readFile(safePath.absolutePath, 'utf8');
        const liveSymbols = parseSourceSymbols(liveContent, astData.filePath);
        const liveSymbolKeys = new Set(liveSymbols.map((s) => `${s.kind}:${s.name}`));

        let missing = false;
        for (const recorded of astData.symbols) {
          if (!liveSymbolKeys.has(`${recorded.kind}:${recorded.name}`)) {
            missing = true;
            break;
          }
        }

        if (!missing) {
          steps.push({
            index: stepNumber,
            evidenceId: astData.id,
            type: 'ast',
            description: `AST symbols: ${astData.filePath}`,
            originalTimestamp: item.timestamp,
            status: 'passed',
            details: `All ${astData.symbolsCount} AST symbols verified intact.`,
          });
          passedSteps++;
        } else {
          steps.push({
            index: stepNumber,
            evidenceId: astData.id,
            type: 'ast',
            description: `AST symbols: ${astData.filePath}`,
            originalTimestamp: item.timestamp,
            status: 'diverged',
            details: `Symbols altered or removed on disk.`,
          });
          divergedSteps++;
        }
      } catch (err: unknown) {
        steps.push({
          index: stepNumber,
          evidenceId: astData.id,
          type: 'ast',
          description: `AST check error: ${astData.filePath}`,
          originalTimestamp: item.timestamp,
          status: 'failed',
          details: (err as Error).message,
        });
        divergedSteps++;
      }
    }
  }

  return {
    bundleId: bundle.id,
    replayedAt: new Date().toISOString(),
    totalSteps: chronologicalItems.length,
    passedSteps,
    divergedSteps,
    isReproducible: divergedSteps === 0,
    steps,
  };
}
