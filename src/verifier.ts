import fs from 'node:fs';
import path from 'node:path';
import {
  EvidenceBundle,
  GitEvidence,
  VerificationItemResult,
  VerificationResult,
  VerificationStatus,
} from './types.js';
import { computeFileSha256AndSize } from './hasher.js';
import { captureGitState, isGitRepository, GitInspectionResult } from './git.js';
import { saveBundle, resolveWorkspaceForBundle } from './storage.js';
import { assertSafeFilePath, SafeFilePathResult } from './security.js';
import { verifyBundleAttestation } from './attestation.js';

/**
 * Re-evaluates all captured evidence inside a bundle against the workspace's current live state.
 *
 * Trust Model:
 * - Git state & File snapshots: Independently verified against disk and repository state.
 *   File snapshots re-apply strict safe-path & symlink boundary checks before any disk read.
 * - Command results: Agent-reported execution records; marked as 'unverifiable'.
 * - Assertions: If an assertion relies only on command evidence, it is marked as 'unverifiable'
 *   and cannot receive 'verified' status.
 */
export async function verifyEvidenceBundle(bundle: EvidenceBundle): Promise<VerificationResult> {
  const items: VerificationItemResult[] = [];
  const reasons: string[] = [];
  const workspacePath = path.resolve(bundle.workspacePath);

  // Map to track verification status and evidence type of individual evidence IDs
  const evidenceStatusMap = new Map<string, 'verified' | 'stale' | 'failed' | 'unverifiable'>();
  const evidenceTypeMap = new Map<string, 'git' | 'command' | 'file'>();

  // 1. Verify Git Evidence (Independently verified against Git repository)
  if (bundle.evidence.git && bundle.evidence.git.length > 0) {
    const gitStateCache = new Map<string, GitInspectionResult>();

    for (const gitEv of bundle.evidence.git) {
      evidenceTypeMap.set(gitEv.id, 'git');
      let targetWs: string;
      try {
        targetWs = resolveWorkspaceForBundle(bundle, gitEv.workspaceName);
      } catch (err: unknown) {
        items.push({
          id: gitEv.id,
          type: 'git',
          status: 'failed',
          details: `Workspace error: ${(err as Error).message}`,
        });
        evidenceStatusMap.set(gitEv.id, 'failed');
        reasons.push(`Git verification failed on (${gitEv.id}): ${(err as Error).message}`);
        continue;
      }

      const isRepo = await isGitRepository(targetWs);
      if (!isRepo) {
        items.push({
          id: gitEv.id,
          type: 'git',
          status: 'failed',
          details: `Workspace "${gitEv.workspaceName || 'root'}" is not a valid Git repository: ${targetWs}`,
        });
        evidenceStatusMap.set(gitEv.id, 'failed');
        reasons.push(`Git verification failed: Workspace "${gitEv.workspaceName || 'root'}" is not a Git repository.`);
        continue;
      }

      let currentGitState = gitStateCache.get(targetWs);
      if (!currentGitState) {
        try {
          currentGitState = await captureGitState(targetWs);
          gitStateCache.set(targetWs, currentGitState);
        } catch (err: unknown) {
          const errorMsg = (err as Error).message;
          items.push({
            id: gitEv.id,
            type: 'git',
            status: 'failed',
            details: `Failed to inspect Git status in workspace "${gitEv.workspaceName || 'root'}": ${errorMsg}`,
          });
          evidenceStatusMap.set(gitEv.id, 'failed');
          reasons.push(`Git inspection failed: ${errorMsg}`);
          continue;
        }
      }

      if (!currentGitState) {
        continue;
      }

      const headMatches = gitEv.headCommit === currentGitState.headCommit;
      const statusMatches = gitEv.statusShort === currentGitState.statusShort;
      const wsTag = gitEv.workspaceName ? ` [workspace: ${gitEv.workspaceName}]` : '';

      if (!headMatches || !statusMatches) {
        const diffReason = !headMatches
          ? `HEAD commit moved from ${gitEv.headCommit.slice(0, 7)} to ${currentGitState.headCommit.slice(0, 7)}`
          : `Working tree status changed (captured: "${gitEv.statusShort}", current: "${currentGitState.statusShort}")`;

        items.push({
          id: gitEv.id,
          type: 'git',
          status: 'stale',
          details: `${diffReason}${wsTag}`,
          expected: `HEAD: ${gitEv.headCommit}, status: "${gitEv.statusShort}"`,
          actual: `HEAD: ${currentGitState.headCommit}, status: "${currentGitState.statusShort}"`,
        });
        evidenceStatusMap.set(gitEv.id, 'stale');
        reasons.push(`Git evidence (${gitEv.id})${wsTag} is stale: ${diffReason}`);
      } else {
        items.push({
          id: gitEv.id,
          type: 'git',
          status: 'verified',
          details: `Git state strictly matches (HEAD: ${gitEv.headCommit.slice(0, 7)}, branch: ${gitEv.branch})${wsTag}`,
        });
        evidenceStatusMap.set(gitEv.id, 'verified');
      }
    }
  }

  // 2. Command Evidence (Differentiate agent-reported logs vs server-executed records)
  if (bundle.evidence.commands && bundle.evidence.commands.length > 0) {
    for (const cmdEv of bundle.evidence.commands) {
      evidenceTypeMap.set(cmdEv.id, 'command');

      if (cmdEv.provenance === 'server_executed') {
        const fullCmdStr = cmdEv.args && cmdEv.args.length > 0
          ? `${cmdEv.command} ${cmdEv.args.join(' ')}`
          : cmdEv.command;

        if (cmdEv.exitCode === 0 && !cmdEv.timedOut) {
          evidenceStatusMap.set(cmdEv.id, 'verified');
          items.push({
            id: cmdEv.id,
            type: 'command',
            status: 'verified',
            details: `Server-executed verified command succeeded (exit 0, ${cmdEv.durationMs ?? 0}ms): "${fullCmdStr}"`,
          });
        } else {
          evidenceStatusMap.set(cmdEv.id, 'failed');
          const failReason = cmdEv.timedOut
            ? `Process timed out after ${cmdEv.durationMs ?? 0}ms`
            : `Exited with code ${cmdEv.exitCode}`;

          items.push({
            id: cmdEv.id,
            type: 'command',
            status: 'failed',
            details: `Server-executed command failed (${failReason}, ${cmdEv.durationMs ?? 0}ms): "${fullCmdStr}"`,
            expected: 'exit code 0',
            actual: `exit code ${cmdEv.exitCode}`,
          });
          reasons.push(`Server-executed command (${cmdEv.id}) failed: "${fullCmdStr}" (${failReason})`);
        }
      } else {
        // Agent-reported execution record
        evidenceStatusMap.set(cmdEv.id, 'unverifiable');
        items.push({
          id: cmdEv.id,
          type: 'command',
          status: 'unverifiable',
          details: `Agent-reported execution record (${cmdEv.command}, exit ${cmdEv.exitCode}); not independently verified.`,
        });
      }
    }
  }

  // 3. Verify File Snapshots (Independently verified against on-disk files)
  if (bundle.evidence.fileSnapshots && bundle.evidence.fileSnapshots.length > 0) {
    for (const snapshot of bundle.evidence.fileSnapshots) {
      evidenceTypeMap.set(snapshot.id, 'file');

      let targetWs: string;
      try {
        targetWs = resolveWorkspaceForBundle(bundle, snapshot.workspaceName);
      } catch (err: unknown) {
        items.push({
          id: snapshot.id,
          type: 'file',
          status: 'failed',
          target: snapshot.path,
          details: `Workspace error: ${(err as Error).message}`,
        });
        evidenceStatusMap.set(snapshot.id, 'failed');
        reasons.push(`File snapshot (${snapshot.id}) failed: ${(err as Error).message}`);
        continue;
      }

      // Security boundary validation before checking existence or reading/hashing target
      let safePath: SafeFilePathResult;
      try {
        safePath = assertSafeFilePath(targetWs, snapshot.path);
      } catch (err: unknown) {
        const errorMsg = (err as Error).message;
        const isSecurityViolation =
          errorMsg.includes('Symbolic links are rejected') ||
          errorMsg.includes('Symlink escape rejected') ||
          errorMsg.includes('sensitive file blocked') ||
          errorMsg.includes('Path traversal rejected') ||
          errorMsg.includes('Null bytes');

        if (isSecurityViolation) {
          items.push({
            id: snapshot.id,
            type: 'file',
            status: 'failed',
            target: snapshot.path,
            details: `Security boundary violation: ${errorMsg}`,
          });
          evidenceStatusMap.set(snapshot.id, 'failed');
          reasons.push(`Security violation on "${snapshot.path}": ${errorMsg}`);
        } else {
          // Normal file missing/deleted
          items.push({
            id: snapshot.id,
            type: 'file',
            status: 'failed',
            target: snapshot.path,
            details: `Target file was deleted or moved: ${snapshot.path}`,
          });
          evidenceStatusMap.set(snapshot.id, 'failed');
          reasons.push(`File missing: "${snapshot.path}" no longer exists on disk.`);
        }
        continue;
      }

      // Safe path confirmed: compute hash on verified regular file
      try {
        const currentHash = await computeFileSha256AndSize(safePath.absolutePath);
        if (currentHash.sha256 !== snapshot.sha256) {
          items.push({
            id: snapshot.id,
            type: 'file',
            status: 'stale',
            target: snapshot.path,
            details: `Content modified since snapshot (SHA-256 mismatch)`,
            expected: snapshot.sha256,
            actual: currentHash.sha256,
          });
          evidenceStatusMap.set(snapshot.id, 'stale');
          reasons.push(`File modified: "${snapshot.path}" SHA-256 has changed.`);
        } else {
          items.push({
            id: snapshot.id,
            type: 'file',
            status: 'verified',
            target: snapshot.path,
            details: `SHA-256 match (${snapshot.sha256.slice(0, 12)}...) and size (${snapshot.sizeBytes} bytes)`,
          });
          evidenceStatusMap.set(snapshot.id, 'verified');
        }
      } catch (err: unknown) {
        const errorMsg = (err as Error).message;
        items.push({
          id: snapshot.id,
          type: 'file',
          status: 'failed',
          target: snapshot.path,
          details: `Could not hash file: ${errorMsg}`,
        });
        evidenceStatusMap.set(snapshot.id, 'failed');
        reasons.push(`File read error: "${snapshot.path}" (${errorMsg})`);
      }
    }
  }

  // 4. Verify Assertions & Supporting Evidence Linkages
  if (!bundle.assertions || bundle.assertions.length === 0) {
    reasons.push('Bundle has no assertions. At least one assertion with supporting evidence is required.');
    items.push({
      id: 'assertions-empty',
      type: 'assertion',
      status: 'failed',
      details: 'Bundle does not contain any assertions.',
    });
  } else {
    for (const assertion of bundle.assertions) {
      if (!assertion.evidenceIds || assertion.evidenceIds.length === 0) {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'failed',
          details: `Assertion "${assertion.claim}" does not reference any evidence IDs.`,
        });
        reasons.push(`Assertion "${assertion.claim}" lacks supporting evidence.`);
        continue;
      }

      const missingEvidence: string[] = [];
      const staleEvidence: string[] = [];
      let hasFailedEvidence = false;
      let hasVerifiableEvidence = false;

      for (const evId of assertion.evidenceIds) {
        const status = evidenceStatusMap.get(evId);
        const type = evidenceTypeMap.get(evId);

        if (!status) {
          missingEvidence.push(evId);
        } else if (status === 'failed') {
          hasFailedEvidence = true;
        } else if (status === 'stale') {
          staleEvidence.push(evId);
        } else if (status === 'verified') {
          if (type === 'git' || type === 'file' || type === 'command') {
            hasVerifiableEvidence = true;
          }
        }
      }

      if (missingEvidence.length > 0) {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'failed',
          details: `Referenced evidence IDs do not exist in bundle: [${missingEvidence.join(', ')}]`,
        });
        reasons.push(
          `Assertion "${assertion.claim}" references non-existent evidence IDs: [${missingEvidence.join(', ')}].`
        );
      } else if (hasFailedEvidence) {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'failed',
          details: `Supporting evidence check failed for assertion.`,
        });
        reasons.push(`Assertion "${assertion.claim}" failed because its supporting evidence failed.`);
      } else if (staleEvidence.length > 0) {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'stale',
          details: `Supported by stale evidence: [${staleEvidence.join(', ')}]`,
        });
        reasons.push(`Assertion "${assertion.claim}" relies on stale evidence.`);
      } else if (!hasVerifiableEvidence) {
        // Relies solely on agent-reported command results!
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'unverifiable',
          details: `Assertion "${assertion.claim}" relies exclusively on agent-reported command execution records and cannot be independently verified.`,
        });
        reasons.push(
          `Assertion "${assertion.claim}" relies solely on agent-reported command evidence (unverifiable).`
        );
      } else {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'verified',
          details: `Supported by independently verified evidence (${assertion.evidenceIds.length} item(s)).`,
        });
      }
    }
  }

  // 5. Verify Cryptographic Attestation (if present)
  if (bundle.attestation) {
    const attestationCheck = verifyBundleAttestation(bundle);
    if (attestationCheck.valid) {
      items.push({
        id: 'attestation',
        type: 'attestation',
        status: 'verified',
        details: `Ed25519 signature verified (Key: ${bundle.attestation.keyFingerprint.slice(0, 16)}...)`,
      });
    } else {
      items.push({
        id: 'attestation',
        type: 'attestation',
        status: 'failed',
        details: attestationCheck.reason || 'Cryptographic signature mismatch: bundle was tampered with.',
      });
      reasons.push(
        `Attestation failure: ${attestationCheck.reason || 'Signature mismatch: bundle content was tampered with.'}`
      );
    }
  }

  // 6. Determine Overall Status
  let overallStatus: VerificationStatus = 'verified';
  if (
    items.some((item) => item.status === 'failed') ||
    reasons.some((r) => r.includes('failed') || r.includes('missing') || r.includes('lacks'))
  ) {
    overallStatus = 'failed';
  } else if (items.some((item) => item.status === 'stale')) {
    overallStatus = 'stale';
  } else if (items.some((item) => item.type === 'assertion' && item.status === 'unverifiable')) {
    overallStatus = 'unverifiable';
  }

  const summary =
    overallStatus === 'verified'
      ? `All assertions are backed by independently verified evidence.`
      : overallStatus === 'unverifiable'
      ? `Bundle assertions rely solely on agent-reported command results and cannot be independently verified.`
      : overallStatus === 'stale'
      ? `Evidence bundle is stale: workspace or tracked files have changed since bundle was created.`
      : `Evidence verification failed: one or more critical evidence components or files are missing or invalid.`;

  const result: VerificationResult = {
    bundleId: bundle.id,
    status: overallStatus,
    verifiedAt: new Date().toISOString(),
    summary,
    reasons,
    items,
  };

  // Update bundle status on disk
  bundle.status = overallStatus;
  await saveBundle(bundle);

  return result;
}
