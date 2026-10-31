import fs from 'node:fs';
import path from 'node:path';
import { EvidenceBundle, VerificationItemResult, VerificationResult, VerificationStatus } from './types.js';
import { computeFileSha256AndSize } from './hasher.js';
import { captureGitState, isGitRepository } from './git.js';
import { saveBundle } from './storage.js';

/**
 * Re-evaluates all captured evidence inside a bundle against the workspace's current live state.
 */
export async function verifyEvidenceBundle(bundle: EvidenceBundle): Promise<VerificationResult> {
  const items: VerificationItemResult[] = [];
  const reasons: string[] = [];
  const workspacePath = path.resolve(bundle.workspacePath);

  // Map to track the verification status of individual evidence IDs
  const evidenceStatusMap = new Map<string, 'verified' | 'stale' | 'failed'>();

  // 1. Verify Git Evidence
  if (bundle.evidence.git && bundle.evidence.git.length > 0) {
    const isRepo = await isGitRepository(workspacePath);
    if (!isRepo) {
      for (const gitEv of bundle.evidence.git) {
        items.push({
          id: gitEv.id,
          type: 'git',
          status: 'failed',
          details: `Workspace is not a valid Git repository: ${workspacePath}`,
        });
        evidenceStatusMap.set(gitEv.id, 'failed');
        reasons.push(`Git verification failed: Workspace is not a Git repository.`);
      }
    } else {
      let currentGitState;
      try {
        currentGitState = await captureGitState(workspacePath);
      } catch (err: unknown) {
        const errorMsg = (err as Error).message;
        for (const gitEv of bundle.evidence.git) {
          items.push({
            id: gitEv.id,
            type: 'git',
            status: 'failed',
            details: `Failed to inspect Git status: ${errorMsg}`,
          });
          evidenceStatusMap.set(gitEv.id, 'failed');
          reasons.push(`Git inspection failed: ${errorMsg}`);
        }
      }

      if (currentGitState) {
        for (const gitEv of bundle.evidence.git) {
          const headMatches = gitEv.headCommit === currentGitState.headCommit;
          const statusMatches = gitEv.statusShort === currentGitState.statusShort;

          if (!headMatches || !statusMatches) {
            const diffReason = !headMatches
              ? `HEAD commit moved from ${gitEv.headCommit.slice(0, 7)} to ${currentGitState.headCommit.slice(0, 7)}`
              : `Working tree status changed (captured: "${gitEv.statusShort}", current: "${currentGitState.statusShort}")`;

            items.push({
              id: gitEv.id,
              type: 'git',
              status: 'stale',
              details: diffReason,
              expected: `HEAD: ${gitEv.headCommit}, status: "${gitEv.statusShort}"`,
              actual: `HEAD: ${currentGitState.headCommit}, status: "${currentGitState.statusShort}"`,
            });
            evidenceStatusMap.set(gitEv.id, 'stale');
            reasons.push(`Git evidence (${gitEv.id}) is stale: ${diffReason}`);
          } else {
            items.push({
              id: gitEv.id,
              type: 'git',
              status: 'verified',
              details: `Git state strictly matches (HEAD: ${gitEv.headCommit.slice(0, 7)}, branch: ${gitEv.branch})`,
            });
            evidenceStatusMap.set(gitEv.id, 'verified');
          }
        }
      }
    }
  }

  // 2. Commands are immutable records of prior execution.
  // Validate that their records exist and mark them as verified records.
  if (bundle.evidence.commands) {
    for (const cmdEv of bundle.evidence.commands) {
      evidenceStatusMap.set(cmdEv.id, 'verified');
    }
  }

  // 3. Verify File Snapshots
  if (bundle.evidence.fileSnapshots && bundle.evidence.fileSnapshots.length > 0) {
    for (const snapshot of bundle.evidence.fileSnapshots) {
      // Re-resolve target file from workspacePath to handle moving/relative contexts safely
      const targetPath = path.resolve(workspacePath, snapshot.path);

      if (!fs.existsSync(targetPath)) {
        items.push({
          id: snapshot.id,
          type: 'file',
          status: 'failed',
          target: snapshot.path,
          details: `Target file was deleted or moved: ${snapshot.path}`,
        });
        evidenceStatusMap.set(snapshot.id, 'failed');
        reasons.push(`File missing: "${snapshot.path}" no longer exists on disk.`);
        continue;
      }

      try {
        const currentHash = await computeFileSha256AndSize(targetPath);
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

      let assertionStatus: 'verified' | 'stale' | 'failed' = 'verified';
      const missingEvidence: string[] = [];
      const staleEvidence: string[] = [];

      for (const evId of assertion.evidenceIds) {
        const status = evidenceStatusMap.get(evId);
        if (!status) {
          missingEvidence.push(evId);
          assertionStatus = 'failed';
        } else if (status === 'failed') {
          assertionStatus = 'failed';
        } else if (status === 'stale' && assertionStatus !== 'failed') {
          staleEvidence.push(evId);
          assertionStatus = 'stale';
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
      } else if (assertionStatus === 'stale') {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'stale',
          details: `Supported by stale evidence: [${staleEvidence.join(', ')}]`,
        });
        reasons.push(`Assertion "${assertion.claim}" relies on stale evidence.`);
      } else if (assertionStatus === 'failed') {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'failed',
          details: `Supporting evidence check failed for assertion.`,
        });
        reasons.push(`Assertion "${assertion.claim}" failed because its supporting evidence failed.`);
      } else {
        items.push({
          id: assertion.id,
          type: 'assertion',
          status: 'verified',
          details: `All ${assertion.evidenceIds.length} supporting evidence item(s) are valid and verified.`,
        });
      }
    }
  }

  // 5. Determine Overall Status
  let overallStatus: VerificationStatus = 'verified';
  if (items.some((item) => item.status === 'failed') || reasons.some((r) => r.includes('failed') || r.includes('missing') || r.includes('lacks'))) {
    overallStatus = 'failed';
  } else if (items.some((item) => item.status === 'stale')) {
    overallStatus = 'stale';
  }

  const summary =
    overallStatus === 'verified'
      ? `All ${items.length} evidence items and assertions are verified and fresh.`
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
