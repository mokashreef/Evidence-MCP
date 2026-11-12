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
import { verifyAgentKeyStatusSync, RegistryVerificationStatus } from './registry.js';
import { verifyNotaryReceipt } from './notary.js';

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
    let registryStatus: RegistryVerificationStatus | undefined;
    let registryError: string | undefined;
    let registryFailureReported = false;

    if (bundle.attestation) {
      try {
        registryStatus = verifyAgentKeyStatusSync({
          workspacePath: bundle.workspacePath,
          keyFingerprint: bundle.attestation.keyFingerprint,
        });
      } catch (err: unknown) {
        registryError = (err as Error).message;
      }
    }

    const inactiveRegistryReason =
      registryError ||
      (registryStatus && registryStatus.registered && !registryStatus.active
        ? registryStatus.reason || 'Signer key is revoked or inactive in agent registry.'
        : undefined);

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
        } else if (inactiveRegistryReason) {
          registryFailureReported = true;
          evaluations.push({
            rule: 'attestation.requireSignature',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `Bundle signer key rejected by trusted registry: ${inactiveRegistryReason}`,
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
        } else if (inactiveRegistryReason) {
          registryFailureReported = true;
          evaluations.push({
            rule: 'attestation.allowedFingerprints',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `Signer key fingerprint "${fp}" is inactive in registry: ${inactiveRegistryReason}`,
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

    if (policy.attestation.requireTrustedRegistry) {
      if (!bundle.attestation) {
        evaluations.push({
          rule: 'attestation.requireTrustedRegistry',
          category: 'attestation',
          passed: false,
          severity: 'error',
          message: 'Bundle is unsigned; cannot verify signer in trusted agent registry.',
        });
      } else if (registryError) {
        registryFailureReported = true;
        evaluations.push({
          rule: 'attestation.requireTrustedRegistry',
          category: 'attestation',
          passed: false,
          severity: 'error',
          message: `Failed to verify signer in agent registry: ${registryError}`,
        });
      } else if (!registryStatus?.registered || !registryStatus.active) {
        registryFailureReported = true;
        evaluations.push({
          rule: 'attestation.requireTrustedRegistry',
          category: 'attestation',
          passed: false,
          severity: 'error',
          message: registryStatus?.reason || 'Signer key is not active in the trusted agent registry.',
          details: { keyFingerprint: bundle.attestation.keyFingerprint },
        });
      } else {
        evaluations.push({
          rule: 'attestation.requireTrustedRegistry',
          category: 'attestation',
          passed: true,
          severity: 'error',
          message: `Signer key verified as active in trusted agent registry (${registryStatus.agent?.agentId || bundle.attestation.keyFingerprint}).`,
          details: {
            agentId: registryStatus.agent?.agentId,
            keyFingerprint: bundle.attestation.keyFingerprint,
          },
        });
      }
    } else if (inactiveRegistryReason && !registryFailureReported) {
      evaluations.push({
        rule: 'attestation.registryStatus',
        category: 'attestation',
        passed: false,
        severity: 'error',
        message: `Signer key rejected by workspace agent registry: ${inactiveRegistryReason}`,
      });
    }

    if (
      policy.attestation.requireNotary ||
      (policy.attestation.allowedNotaryFingerprints &&
        policy.attestation.allowedNotaryFingerprints.length > 0) ||
      typeof policy.attestation.minNotaryCount === 'number'
    ) {
      const receipts = bundle.notaryReceipts || [];
      const validReceipts = receipts.filter((r) => verifyNotaryReceipt(r, bundle).valid);
      const allowed = policy.attestation.allowedNotaryFingerprints;
      const hasAllowlist = Array.isArray(allowed) && allowed.length > 0;
      const eligibleReceipts = hasAllowlist
        ? validReceipts.filter((r) => allowed.includes(r.notaryKeyFingerprint))
        : validReceipts;
      const distinctNotaryKeys = Array.from(
        new Set(eligibleReceipts.map((r) => r.notaryKeyFingerprint))
      );

      if (policy.attestation.requireNotary) {
        if (validReceipts.length === 0) {
          evaluations.push({
            rule: 'attestation.requireNotary',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message:
              receipts.length === 0
                ? 'Policy requires remote transparency notary receipt, but none is attached.'
                : 'Attached notary receipt(s) failed signature or bundle digest verification.',
          });
        } else {
          evaluations.push({
            rule: 'attestation.requireNotary',
            category: 'attestation',
            passed: true,
            severity: 'error',
            message: `Verified ${validReceipts.length} remote notary receipt(s) matching current bundle digest.`,
          });
        }
      }

      if (hasAllowlist) {
        if (eligibleReceipts.length === 0) {
          evaluations.push({
            rule: 'attestation.allowedNotaryFingerprints',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `No valid remote notary receipt signed by allowed notary fingerprint(s): [${allowed.join(', ')}].`,
          });
        } else {
          evaluations.push({
            rule: 'attestation.allowedNotaryFingerprints',
            category: 'attestation',
            passed: true,
            severity: 'error',
            message: `Remote notary receipt authorized by trusted notary key (${eligibleReceipts[0].notaryKeyFingerprint}).`,
          });
        }
      }

      if (typeof policy.attestation.minNotaryCount === 'number') {
        const requiredCount = policy.attestation.minNotaryCount;
        if (!Number.isInteger(requiredCount) || requiredCount < 1) {
          evaluations.push({
            rule: 'attestation.minNotaryCount',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: `Invalid minNotaryCount policy threshold (${requiredCount}); must be a positive integer >= 1.`,
            details: { requiredMinNotaryCount: requiredCount },
          });
        } else if (distinctNotaryKeys.length < requiredCount) {
          evaluations.push({
            rule: 'attestation.minNotaryCount',
            category: 'attestation',
            passed: false,
            severity: 'error',
            message: hasAllowlist
              ? `Multi-notary quorum not met: found ${distinctNotaryKeys.length} distinct allowed notary key(s) (${validReceipts.length} total valid receipt(s)), require at least ${requiredCount}.`
              : `Multi-notary quorum not met: found ${distinctNotaryKeys.length} distinct valid notary key(s) (${validReceipts.length} total valid receipt(s)), require at least ${requiredCount}.`,
            details: {
              distinctNotaryCount: distinctNotaryKeys.length,
              validReceiptCount: validReceipts.length,
              requiredMinNotaryCount: requiredCount,
              fingerprints: distinctNotaryKeys,
            },
          });
        } else {
          evaluations.push({
            rule: 'attestation.minNotaryCount',
            category: 'attestation',
            passed: true,
            severity: 'error',
            message: `Multi-notary quorum satisfied: ${distinctNotaryKeys.length} distinct valid notary key(s) attested the bundle (required >= ${requiredCount}).`,
            details: {
              distinctNotaryCount: distinctNotaryKeys.length,
              validReceiptCount: validReceipts.length,
              requiredMinNotaryCount: requiredCount,
              fingerprints: distinctNotaryKeys,
            },
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

  // 8. License Compliance Rules
  if (policy.license) {
    const { requireLicenseField, allowedLicenses, disallowedLicenses } = policy.license;

    const workspacesToCheck = new Set<string>();
    if (bundle.workspacePath) {
      workspacesToCheck.add(path.resolve(bundle.workspacePath));
    }
    if (bundle.workspaces) {
      for (const p of Object.values(bundle.workspaces)) {
        workspacesToCheck.add(path.resolve(p));
      }
    }

    for (const ws of workspacesToCheck) {
      const pkgJsonPath = path.join(ws, 'package.json');
      let pkgLicense: string | undefined;
      let pkgFound = false;

      if (fs.existsSync(pkgJsonPath)) {
        try {
          const content = fs.readFileSync(pkgJsonPath, 'utf8');
          const pkg = JSON.parse(content) as Record<string, unknown>;
          pkgFound = true;
          if (typeof pkg.license === 'string') {
            pkgLicense = pkg.license.trim();
          } else if (
            pkg.license &&
            typeof (pkg.license as Record<string, unknown>).type === 'string'
          ) {
            pkgLicense = ((pkg.license as Record<string, unknown>).type as string).trim();
          }
        } catch {
          evaluations.push({
            rule: 'license.syntax',
            category: 'license',
            passed: false,
            severity: 'error',
            message: `Failed to parse package.json at ${pkgJsonPath}`,
            details: { workspace: ws },
          });
          continue;
        }
      }

      if (requireLicenseField) {
        if (!pkgFound || !pkgLicense) {
          evaluations.push({
            rule: 'license.requireLicenseField',
            category: 'license',
            passed: false,
            severity: 'error',
            message: `Workspace "${ws}" lacks a required license declaration in package.json.`,
            details: { workspace: ws, packageJsonExists: pkgFound },
          });
        } else {
          evaluations.push({
            rule: 'license.requireLicenseField',
            category: 'license',
            passed: true,
            severity: 'error',
            message: `Workspace "${ws}" declares license "${pkgLicense}".`,
            details: { workspace: ws, license: pkgLicense },
          });
        }
      }

      if (pkgLicense) {
        if (allowedLicenses && allowedLicenses.length > 0) {
          const isAllowed = allowedLicenses.some(
            (al) => al.toLowerCase() === pkgLicense!.toLowerCase()
          );
          if (!isAllowed) {
            evaluations.push({
              rule: 'license.allowedLicenses',
              category: 'license',
              passed: false,
              severity: 'error',
              message: `License "${pkgLicense}" in workspace "${ws}" is not in approved list [${allowedLicenses.join(', ')}].`,
              details: { workspace: ws, license: pkgLicense, allowedLicenses },
            });
          } else {
            evaluations.push({
              rule: 'license.allowedLicenses',
              category: 'license',
              passed: true,
              severity: 'error',
              message: `License "${pkgLicense}" in workspace "${ws}" is compliant with allowed licenses.`,
              details: { workspace: ws, license: pkgLicense },
            });
          }
        }

        if (disallowedLicenses && disallowedLicenses.length > 0) {
          const isDisallowed = disallowedLicenses.some(
            (dl) => dl.toLowerCase() === pkgLicense!.toLowerCase()
          );
          if (isDisallowed) {
            evaluations.push({
              rule: 'license.disallowedLicenses',
              category: 'license',
              passed: false,
              severity: 'error',
              message: `License "${pkgLicense}" in workspace "${ws}" is disallowed by policy.`,
              details: { workspace: ws, license: pkgLicense, disallowedLicenses },
            });
          } else {
            evaluations.push({
              rule: 'license.disallowedLicenses',
              category: 'license',
              passed: true,
              severity: 'error',
              message: `License "${pkgLicense}" in workspace "${ws}" does not match any disallowed licenses.`,
              details: { workspace: ws, license: pkgLicense },
            });
          }
        }
      }
    }
  }

  // 9. SBOM Compliance Rules
  if (policy.sbom) {
    const sbomList = bundle.evidence.sbom || [];
    const { requireSbom, disallowComponentLicenses, blockedPackages, maxComponents } = policy.sbom;

    if (requireSbom) {
      if (sbomList.length === 0) {
        evaluations.push({
          rule: 'sbom.requireSbom',
          category: 'sbom',
          passed: false,
          severity: 'error',
          message: 'Policy requires CycloneDX SBOM evidence, but none was recorded in this bundle.',
        });
      } else {
        evaluations.push({
          rule: 'sbom.requireSbom',
          category: 'sbom',
          passed: true,
          severity: 'error',
          message: `Bundle includes ${sbomList.length} SBOM snapshot(s).`,
        });
      }
    }

    if (disallowComponentLicenses && disallowComponentLicenses.length > 0 && sbomList.length > 0) {
      const lowerDisallowed = disallowComponentLicenses.map((l) => l.toLowerCase());
      const violations: Array<{ name: string; version: string; license: string }> = [];

      for (const sbomEv of sbomList) {
        for (const comp of sbomEv.components) {
          if (comp.license && lowerDisallowed.includes(comp.license.toLowerCase())) {
            violations.push({ name: comp.name, version: comp.version, license: comp.license });
          }
        }
      }

      if (violations.length > 0) {
        evaluations.push({
          rule: 'sbom.disallowComponentLicenses',
          category: 'sbom',
          passed: false,
          severity: 'error',
          message: `SBOM contains ${violations.length} dependency component(s) with disallowed licenses: ${violations
            .slice(0, 5)
            .map((v) => `${v.name}@${v.version} (${v.license})`)
            .join(', ')}`,
          details: { violations },
        });
      } else {
        evaluations.push({
          rule: 'sbom.disallowComponentLicenses',
          category: 'sbom',
          passed: true,
          severity: 'error',
          message: 'All SBOM component licenses are compliant with policy.',
        });
      }
    }

    if (blockedPackages && blockedPackages.length > 0 && sbomList.length > 0) {
      const lowerBlocked = blockedPackages.map((p) => p.toLowerCase());
      const matched: string[] = [];

      for (const sbomEv of sbomList) {
        for (const comp of sbomEv.components) {
          const id = `${comp.name}@${comp.version}`.toLowerCase();
          if (lowerBlocked.includes(comp.name.toLowerCase()) || lowerBlocked.includes(id)) {
            matched.push(`${comp.name}@${comp.version}`);
          }
        }
      }

      if (matched.length > 0) {
        evaluations.push({
          rule: 'sbom.blockedPackages',
          category: 'sbom',
          passed: false,
          severity: 'error',
          message: `SBOM includes blocked package(s): [${matched.join(', ')}]`,
          details: { blockedFound: matched },
        });
      } else {
        evaluations.push({
          rule: 'sbom.blockedPackages',
          category: 'sbom',
          passed: true,
          severity: 'error',
          message: 'No blocked packages found in recorded SBOMs.',
        });
      }
    }

    if (typeof maxComponents === 'number' && sbomList.length > 0) {
      const exceeding = sbomList.filter((s) => s.componentCount > maxComponents);
      if (exceeding.length > 0) {
        evaluations.push({
          rule: 'sbom.maxComponents',
          category: 'sbom',
          passed: false,
          severity: 'warning',
          message: `SBOM exceeds maximum allowed components (${exceeding[0].componentCount} > ${maxComponents}).`,
          details: { maxComponents, observed: exceeding[0].componentCount },
        });
      } else {
        evaluations.push({
          rule: 'sbom.maxComponents',
          category: 'sbom',
          passed: true,
          severity: 'warning',
          message: `SBOM component count within limit (${maxComponents}).`,
        });
      }
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

// ==========================================
// Policy Presets & Bootstrapping Wizard
// ==========================================

export type PolicyPreset = 'recommended' | 'strict' | 'permissive';

export const POLICY_PRESETS: Record<PolicyPreset, EvidencePolicy> = {
  recommended: {
    version: '1.0',
    description: 'Recommended policy balance for high-integrity agentic coding',
    git: {
      requireCleanWorkingTree: false,
      disallowDetachedHead: true,
    },
    files: {
      disallowedPatterns: ['.env', '.env.*', '*.pem', 'id_rsa*', '**/secrets/**', '**/*.key'],
    },
    commands: {
      requireServerExecutedCommands: true,
      disallowNonZeroExitCodes: true,
    },
    assertions: {
      disallowUnverifiable: true,
    },
  },
  strict: {
    version: '1.0',
    description: 'Strict production policy requiring clean git, signed attestations, and consensus',
    git: {
      requireCleanWorkingTree: true,
      disallowDetachedHead: true,
      allowedBranches: ['main', 'master', 'release/*'],
    },
    files: {
      disallowedPatterns: ['.env', '.env.*', '*.pem', 'id_rsa*', '**/secrets/**', '**/*.key', 'credentials.json'],
    },
    commands: {
      requireServerExecutedCommands: true,
      minServerExecutedCommands: 1,
      disallowNonZeroExitCodes: true,
    },
    ast: {
      requireAstEvidence: true,
      disallowBreakingChanges: true,
    },
    assertions: {
      minAssertions: 1,
      disallowUnverifiable: true,
    },
    attestation: {
      requireSignature: true,
      requireTrustedRegistry: true,
    },
    consensus: {
      minEndorsements: 1,
      requireUniqueSigners: true,
      disallowRejections: true,
      requireTrustedRegistry: true,
    },
  },
  permissive: {
    version: '1.0',
    description: 'Permissive development policy with minimal constraints for experimentation',
    git: {
      requireCleanWorkingTree: false,
      disallowDetachedHead: false,
    },
    files: {
      disallowedPatterns: ['.env', '*.key', '*.pem'],
    },
  },
};

export interface InitPolicyOptions {
  workspacePath?: string;
  preset?: PolicyPreset;
  force?: boolean;
  updateGitignore?: boolean;
}

export interface InitPolicyResult {
  policyPath: string;
  created: boolean;
  gitignoreUpdated: boolean;
  preset: PolicyPreset;
  policy: EvidencePolicy;
}

/**
 * Bootstraps an evidence.policy.json in the workspace with standard presets
 * and optionally updates .gitignore to ignore .evidence-mcp storage.
 */
export async function initWorkspacePolicy(
  options: InitPolicyOptions = {}
): Promise<InitPolicyResult> {
  const baseDir = options.workspacePath ? path.resolve(options.workspacePath) : process.cwd();
  const policyFile = path.join(baseDir, 'evidence.policy.json');
  const presetKey: PolicyPreset = options.preset || 'recommended';
  const policy = POLICY_PRESETS[presetKey] || POLICY_PRESETS.recommended;

  let created = false;
  if (!fs.existsSync(policyFile) || options.force) {
    await fs.promises.mkdir(baseDir, { recursive: true });
    await fs.promises.writeFile(policyFile, JSON.stringify(policy, null, 2) + '\n', 'utf8');
    created = true;
  }

  let gitignoreUpdated = false;
  if (options.updateGitignore !== false) {
    const gitignorePath = path.join(baseDir, '.gitignore');
    let content = '';
    if (fs.existsSync(gitignorePath)) {
      content = await fs.promises.readFile(gitignorePath, 'utf8');
    }
    const lines = content.split(/\r?\n/);
    const hasEvidenceDir = lines.some(
      (l) => l.trim() === '.evidence-mcp' || l.trim() === '.evidence-mcp/'
    );
    if (!hasEvidenceDir) {
      const addition =
        (content.length > 0 && !content.endsWith('\n') ? '\n' : '') +
        '# Evidence MCP data store\n.evidence-mcp/\n';
      await fs.promises.appendFile(gitignorePath, addition, 'utf8');
      gitignoreUpdated = true;
    }
  }

  return {
    policyPath: policyFile,
    created,
    gitignoreUpdated,
    preset: presetKey,
    policy,
  };
}
