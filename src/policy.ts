import path from 'node:path';
import fs from 'node:fs';
import {
  EvidenceBundle,
  EvidencePolicy,
  PolicyEvaluationResult,
  PolicyRuleEvaluation,
  VerificationResult,
} from './types.js';
import { checkBundleQuorum } from './consensus.js';
import { verifyBundleAttestation } from './attestation.js';

/**
 * Matches a relative or absolute file path against a glob-like pattern.
 * Supports:
 * - `*` matches any characters within a directory segment (excluding `/` or `\`)
 * - `**` matches any characters across directory boundaries
 * - Single extensions: `*.ts`, `*.json`
 * - Prefix directories: `src/**`, `packages/backend/*`
 */
export function matchesFilePattern(filePath: string, pattern: string): boolean {
  if (!filePath || !pattern) {
    return false;
  }

  const normalizedPath = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
  const normalizedPattern = pattern.replace(/\\/g, '/').replace(/^\.\//, '');

  if (normalizedPattern === '*' || normalizedPattern === '**/*') {
    return true;
  }

  // Exact match
  if (normalizedPath === normalizedPattern) {
    return true;
  }

  // Build regular expression from pattern
  let regexStr = '';
  let i = 0;
  while (i < normalizedPattern.length) {
    const char = normalizedPattern[i];
    if (char === '*') {
      if (normalizedPattern[i + 1] === '*') {
        if (normalizedPattern[i + 2] === '/') {
          regexStr += '(?:.*/)?';
          i += 3;
          continue;
        } else {
          regexStr += '.*';
          i += 2;
          continue;
        }
      } else {
        regexStr += '[^/]*';
        i += 1;
        continue;
      }
    } else if (char === '?') {
      regexStr += '[^/]';
      i += 1;
      continue;
    } else if (['.', '(', ')', '[', ']', '{', '}', '+', '^', '$', '|'].includes(char)) {
      regexStr += `\\${char}`;
      i += 1;
      continue;
    } else {
      regexStr += char;
      i += 1;
      continue;
    }
  }

  // If pattern does not include a slash, match basename or full path
  if (!normalizedPattern.includes('/')) {
    const regex = new RegExp(`(^|/)${regexStr}$`, 'i');
    return regex.test(normalizedPath);
  }

  const regex = new RegExp(`^${regexStr}$`, 'i');
  return regex.test(normalizedPath);
}

/**
 * Checks if a command string satisfies a pattern (substring or wildcard match).
 */
export function matchesCommandPattern(command: string, pattern: string): boolean {
  if (!command || !pattern) {
    return false;
  }
  const cleanCmd = command.trim().toLowerCase();
  const cleanPat = pattern.trim().toLowerCase();

  if (cleanCmd.includes(cleanPat)) {
    return true;
  }

  // Try wildcard regex
  try {
    const regexStr = cleanPat
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*/g, '.*');
    const regex = new RegExp(regexStr, 'i');
    return regex.test(cleanCmd);
  } catch {
    return false;
  }
}

/**
 * Locates and loads an EvidencePolicy from disk.
 * Searches:
 * 1. Specified policyPath (if provided)
 * 2. <workspacePath>/evidence.policy.json
 * 3. <workspacePath>/.evidence-policy.json
 */
export async function loadPolicyFile(
  policyPath?: string,
  workspacePath?: string
): Promise<{ policy: EvidencePolicy; sourcePath: string } | null> {
  const baseDir = workspacePath ? path.resolve(workspacePath) : process.cwd();

  const candidates: string[] = [];
  if (policyPath) {
    candidates.push(path.isAbsolute(policyPath) ? policyPath : path.resolve(baseDir, policyPath));
  } else {
    candidates.push(path.join(baseDir, 'evidence.policy.json'));
    candidates.push(path.join(baseDir, '.evidence-policy.json'));
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      try {
        const content = await fs.promises.readFile(candidate, 'utf8');
        const policy = JSON.parse(content) as EvidencePolicy;
        return { policy, sourcePath: candidate };
      } catch (err: unknown) {
        throw new Error(
          `Failed to parse policy file at "${candidate}": ${(err as Error).message}`
        );
      }
    }
  }

  if (policyPath) {
    throw new Error(`Specified policy file not found at: "${policyPath}".`);
  }

  return null;
}

/**
 * Evaluates an EvidenceBundle against a declarative EvidencePolicy.
 */
export function evaluateEvidencePolicy(options: {
  bundle: EvidenceBundle;
  policy: EvidencePolicy;
  strict?: boolean;
  verificationResult?: VerificationResult;
}): PolicyEvaluationResult {
  const { bundle, policy, strict = false, verificationResult } = options;
  const evaluations: PolicyRuleEvaluation[] = [];
  const evaluatedAt = new Date().toISOString();

  // 1. Git Rules
  if (policy.git) {
    const gitEvidenceList = bundle.evidence.git || [];

    if (policy.git.requireCleanWorkingTree) {
      if (gitEvidenceList.length === 0) {
        evaluations.push({
          rule: 'git.requireCleanWorkingTree',
          category: 'git',
          passed: false,
          severity: 'error',
          message: 'Policy requires a clean working tree, but no Git evidence was recorded in bundle.',
        });
      } else {
        const dirtyEntries = gitEvidenceList.filter((g) => !g.isClean);
        if (dirtyEntries.length > 0) {
          evaluations.push({
            rule: 'git.requireCleanWorkingTree',
            category: 'git',
            passed: false,
            severity: 'error',
            message: `Working tree is dirty in ${dirtyEntries.length} recorded Git snapshot(s): [${dirtyEntries.map((g) => g.workspaceName || 'root').join(', ')}].`,
            details: { dirtyWorkspaces: dirtyEntries.map((g) => g.workspaceName || 'root') },
          });
        } else {
          evaluations.push({
            rule: 'git.requireCleanWorkingTree',
            category: 'git',
            passed: true,
            severity: 'error',
            message: 'All recorded Git snapshots report a clean working tree.',
          });
        }
      }
    }

    if (policy.git.allowedBranches && policy.git.allowedBranches.length > 0) {
      if (gitEvidenceList.length === 0) {
        evaluations.push({
          rule: 'git.allowedBranches',
          category: 'git',
          passed: false,
          severity: 'error',
          message: `Branch check failed: no Git evidence recorded to verify against allowed branches: [${policy.git.allowedBranches.join(', ')}].`,
        });
      } else {
        const invalidBranches: string[] = [];
        for (const g of gitEvidenceList) {
          const isAllowed = policy.git.allowedBranches.some((pattern) =>
            matchesCommandPattern(g.branch, pattern)
          );
          if (!isAllowed) {
            invalidBranches.push(`${g.workspaceName || 'root'}:${g.branch}`);
          }
        }

        if (invalidBranches.length > 0) {
          evaluations.push({
            rule: 'git.allowedBranches',
            category: 'git',
            passed: false,
            severity: 'error',
            message: `Git branch [${invalidBranches.join(', ')}] is not allowed by policy [${policy.git.allowedBranches.join(', ')}].`,
            details: { invalidBranches },
          });
        } else {
          evaluations.push({
            rule: 'git.allowedBranches',
            category: 'git',
            passed: true,
            severity: 'error',
            message: `All recorded Git branches match allowed branch policy [${policy.git.allowedBranches.join(', ')}].`,
          });
        }
      }
    }

    if (policy.git.disallowDetachedHead) {
      const detachedEntries = gitEvidenceList.filter(
        (g) => g.branch === 'HEAD' || g.branch.toLowerCase().includes('detached')
      );
      if (detachedEntries.length > 0) {
        evaluations.push({
          rule: 'git.disallowDetachedHead',
          category: 'git',
          passed: false,
          severity: 'error',
          message: `Detached HEAD state detected in: [${detachedEntries.map((g) => g.workspaceName || 'root').join(', ')}].`,
        });
      } else if (gitEvidenceList.length > 0) {
        evaluations.push({
          rule: 'git.disallowDetachedHead',
          category: 'git',
          passed: true,
          severity: 'error',
          message: 'No detached HEAD states detected across Git snapshots.',
        });
      }
    }
  }

  // 2. File Snapshot Rules
  if (policy.files) {
    const snapshots = bundle.evidence.fileSnapshots || [];

    if (typeof policy.files.maxSnapshots === 'number') {
      if (snapshots.length > policy.files.maxSnapshots) {
        evaluations.push({
          rule: 'files.maxSnapshots',
          category: 'files',
          passed: false,
          severity: 'error',
          message: `File snapshots count (${snapshots.length}) exceeds policy maximum limit (${policy.files.maxSnapshots}).`,
          details: { currentCount: snapshots.length, maxLimit: policy.files.maxSnapshots },
        });
      } else {
        evaluations.push({
          rule: 'files.maxSnapshots',
          category: 'files',
          passed: true,
          severity: 'error',
          message: `File snapshots count (${snapshots.length}) is within policy limit (${policy.files.maxSnapshots}).`,
        });
      }
    }

    if (policy.files.requiredPatterns && policy.files.requiredPatterns.length > 0) {
      for (const pattern of policy.files.requiredPatterns) {
        const hasMatch = snapshots.some((s) => matchesFilePattern(s.path, pattern));
        if (!hasMatch) {
          evaluations.push({
            rule: `files.requiredPattern:${pattern}`,
            category: 'files',
            passed: false,
            severity: 'error',
            message: `Policy requires at least one file snapshot matching pattern "${pattern}", but none was recorded.`,
          });
        } else {
          evaluations.push({
            rule: `files.requiredPattern:${pattern}`,
            category: 'files',
            passed: true,
            severity: 'error',
            message: `Required file pattern "${pattern}" satisfied by recorded snapshot(s).`,
          });
        }
      }
    }

    if (policy.files.disallowedPatterns && policy.files.disallowedPatterns.length > 0) {
      const violatedFiles: string[] = [];
      for (const pattern of policy.files.disallowedPatterns) {
        for (const s of snapshots) {
          if (matchesFilePattern(s.path, pattern)) {
            violatedFiles.push(`${s.path} (matched "${pattern}")`);
          }
        }
      }

      if (violatedFiles.length > 0) {
        evaluations.push({
          rule: 'files.disallowedPatterns',
          category: 'files',
          passed: false,
          severity: 'error',
          message: `File snapshots include disallowed file patterns: [${violatedFiles.join(', ')}].`,
          details: { violatedFiles },
        });
      } else {
        evaluations.push({
          rule: 'files.disallowedPatterns',
          category: 'files',
          passed: true,
          severity: 'error',
          message: 'No recorded file snapshots match disallowed patterns.',
        });
      }
    }
  }

  // 3. Command Execution Rules
  if (policy.commands) {
    const commands = bundle.evidence.commands || [];

    if (policy.commands.requireServerExecutedCommands) {
      const serverExecuted = commands.filter((c) => c.provenance === 'server_executed');
      if (serverExecuted.length === 0) {
        evaluations.push({
          rule: 'commands.requireServerExecutedCommands',
          category: 'commands',
          passed: false,
          severity: 'error',
          message: 'Policy requires at least one server-executed command (sandboxed runner), but none was recorded.',
        });
      } else {
        evaluations.push({
          rule: 'commands.requireServerExecutedCommands',
          category: 'commands',
          passed: true,
          severity: 'error',
          message: `Bundle includes ${serverExecuted.length} server-executed command(s).`,
        });
      }
    }

    if (typeof policy.commands.minServerExecutedCommands === 'number') {
      const serverExecuted = commands.filter((c) => c.provenance === 'server_executed');
      if (serverExecuted.length < policy.commands.minServerExecutedCommands) {
        evaluations.push({
          rule: 'commands.minServerExecutedCommands',
          category: 'commands',
          passed: false,
          severity: 'error',
          message: `Server-executed commands count (${serverExecuted.length}) is below required minimum (${policy.commands.minServerExecutedCommands}).`,
          details: { current: serverExecuted.length, required: policy.commands.minServerExecutedCommands },
        });
      } else {
        evaluations.push({
          rule: 'commands.minServerExecutedCommands',
          category: 'commands',
          passed: true,
          severity: 'error',
          message: `Server-executed commands count (${serverExecuted.length}) meets requirement (>= ${policy.commands.minServerExecutedCommands}).`,
        });
      }
    }

    if (policy.commands.disallowNonZeroExitCodes) {
      const nonZeroCommands = commands.filter((c) => c.exitCode !== 0);
      if (nonZeroCommands.length > 0) {
        evaluations.push({
          rule: 'commands.disallowNonZeroExitCodes',
          category: 'commands',
          passed: false,
          severity: 'error',
          message: `Bundle contains ${nonZeroCommands.length} command(s) with non-zero exit codes: [${nonZeroCommands.map((c) => `${c.id}:${c.command} (exit ${c.exitCode})`).join(', ')}].`,
          details: { nonZeroCommands: nonZeroCommands.map((c) => ({ id: c.id, cmd: c.command, exitCode: c.exitCode })) },
        });
      } else if (commands.length > 0) {
        evaluations.push({
          rule: 'commands.disallowNonZeroExitCodes',
          category: 'commands',
          passed: true,
          severity: 'error',
          message: 'All recorded commands completed with exit code 0.',
        });
      }
    }

    if (policy.commands.requiredCommandPatterns && policy.commands.requiredCommandPatterns.length > 0) {
      for (const pattern of policy.commands.requiredCommandPatterns) {
        const hasMatch = commands.some((c) => matchesCommandPattern(c.command, pattern));
        if (!hasMatch) {
          evaluations.push({
            rule: `commands.requiredPattern:${pattern}`,
            category: 'commands',
            passed: false,
            severity: 'error',
            message: `Policy requires at least one command matching pattern "${pattern}", but none was recorded.`,
          });
        } else {
          evaluations.push({
            rule: `commands.requiredPattern:${pattern}`,
            category: 'commands',
            passed: true,
            severity: 'error',
            message: `Required command pattern "${pattern}" satisfied.`,
          });
        }
      }
    }
  }

  // 4. AST & Semantic Rules
  if (policy.ast) {
    const astEvidence = bundle.evidence.ast || [];

    if (policy.ast.requireAstEvidence) {
      if (astEvidence.length === 0) {
        evaluations.push({
          rule: 'ast.requireAstEvidence',
          category: 'ast',
          passed: false,
          severity: 'error',
          message: 'Policy requires AST structural evidence, but no AST entries were captured in bundle.',
        });
      } else {
        evaluations.push({
          rule: 'ast.requireAstEvidence',
          category: 'ast',
          passed: true,
          severity: 'error',
          message: `AST evidence present (${astEvidence.length} file(s) analyzed).`,
        });
      }
    }

    if (policy.ast.disallowBreakingChanges) {
      const breakingEntries = astEvidence.filter((a) => a.diff?.isBreakingChange);
      if (breakingEntries.length > 0) {
        evaluations.push({
          rule: 'ast.disallowBreakingChanges',
          category: 'ast',
          passed: false,
          severity: 'error',
          message: `AST breaking changes detected in ${breakingEntries.length} file(s): [${breakingEntries.map((a) => a.filePath).join(', ')}].`,
          details: { breakingFiles: breakingEntries.map((a) => a.filePath) },
        });
      } else {
        evaluations.push({
          rule: 'ast.disallowBreakingChanges',
          category: 'ast',
          passed: true,
          severity: 'error',
          message: 'No AST breaking changes detected.',
        });
      }
    }
  }

  // 5. Assertion Rules
  if (policy.assertions) {
    const assertions = bundle.assertions || [];

    if (typeof policy.assertions.minAssertions === 'number') {
      if (assertions.length < policy.assertions.minAssertions) {
        evaluations.push({
          rule: 'assertions.minAssertions',
          category: 'assertions',
          passed: false,
          severity: 'error',
          message: `Assertions count (${assertions.length}) is below required minimum (${policy.assertions.minAssertions}).`,
        });
      } else {
        evaluations.push({
          rule: 'assertions.minAssertions',
          category: 'assertions',
          passed: true,
          severity: 'error',
          message: `Assertions count (${assertions.length}) satisfies requirement (>= ${policy.assertions.minAssertions}).`,
        });
      }
    }

    if (policy.assertions.disallowUnverifiable && verificationResult) {
      if (verificationResult.status === 'unverifiable') {
        evaluations.push({
          rule: 'assertions.disallowUnverifiable',
          category: 'assertions',
          passed: false,
          severity: 'error',
          message: 'Bundle status is unverifiable (assertions depend solely on agent-reported unverified evidence).',
        });
      } else {
        evaluations.push({
          rule: 'assertions.disallowUnverifiable',
          category: 'assertions',
          passed: true,
          severity: 'error',
          message: `Bundle verification status (${verificationResult.status}) satisfies unverifiable check.`,
        });
      }
    }
  }

  // 6. Attestation Rules
  if (policy.attestation) {
    if (policy.attestation.requireSignature) {
      if (!bundle.attestation) {
        evaluations.push({
          rule: 'attestation.requireSignature',
          category: 'attestation',
          passed: false,
          severity: 'error',
          message: 'Policy requires bundle to be cryptographically signed, but bundle is unsigned.',
        });
      } else {
        const verifyRes = verifyBundleAttestation(bundle);
        if (!verifyRes.valid) {
          evaluations.push({
            rule: 'attestation.requireSignature',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `Bundle signature is invalid: ${verifyRes.reason}`,
          });
        } else {
          evaluations.push({
            rule: 'attestation.requireSignature',
            category: 'attestation',
            passed: true,
            severity: 'error',
            message: `Bundle signature verified successfully (Fingerprint: ${bundle.attestation.keyFingerprint}).`,
          });
        }
      }
    }

    if (policy.attestation.allowedFingerprints && policy.attestation.allowedFingerprints.length > 0) {
      if (!bundle.attestation) {
        evaluations.push({
          rule: 'attestation.allowedFingerprints',
          category: 'attestation',
          passed: false,
          severity: 'error',
          message: 'Bundle is unsigned; cannot verify signer fingerprint against allowed fingerprints.',
        });
      } else {
        const fp = bundle.attestation.keyFingerprint;
        const isAllowed = policy.attestation.allowedFingerprints.includes(fp);
        if (!isAllowed) {
          evaluations.push({
            rule: 'attestation.allowedFingerprints',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `Signer key fingerprint "${fp}" is not in policy allowed list: [${policy.attestation.allowedFingerprints.join(', ')}].`,
          });
        } else {
          evaluations.push({
            rule: 'attestation.allowedFingerprints',
            category: 'attestation',
            passed: true,
            severity: 'error',
            message: `Signer key fingerprint "${fp}" is authorized by policy.`,
          });
        }
      }
    }
  }

  // 7. Consensus / Quorum Rules
  if (policy.consensus) {
    const quorumRes = checkBundleQuorum(bundle, policy.consensus);
    if (!quorumRes.satisfied) {
      evaluations.push({
        rule: 'consensus.quorum',
        category: 'consensus',
        passed: false,
        severity: 'error',
        message: `Consensus quorum not satisfied: ${quorumRes.reasons.join('; ')}`,
        details: {
          approvedCount: quorumRes.approvedCount,
          rejectionsCount: quorumRes.rejectionsCount,
          totalEndorsements: quorumRes.totalEndorsements,
        },
      });
    } else {
      evaluations.push({
        rule: 'consensus.quorum',
        category: 'consensus',
        passed: true,
        severity: 'error',
        message: `Consensus quorum satisfied (${quorumRes.approvedCount} approval(s), 0 rejections, ${quorumRes.verifiedSignatures} verified signature(s)).`,
      });
    }
  }

  const rulesEvaluated = evaluations.length;
  const passedCount = evaluations.filter((e) => e.passed).length;
  const failedCount = evaluations.filter((e) => !e.passed && e.severity === 'error').length;
  const warningCount = evaluations.filter((e) => !e.passed && e.severity === 'warning').length;

  const passed = failedCount === 0 && (!strict || warningCount === 0);

  const policySummary = passed
    ? `Policy compliance PASSED (${passedCount}/${rulesEvaluated} rules satisfied).`
    : `Policy compliance FAILED (${failedCount} error(s), ${warningCount} warning(s) out of ${rulesEvaluated} rules).`;

  return {
    bundleId: bundle.id,
    passed,
    evaluatedAt,
    policySummary,
    rulesEvaluated,
    passedCount,
    failedCount,
    warningCount,
    evaluations,
  };
}
