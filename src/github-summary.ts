import fs from 'node:fs';
import {
  EvidenceBundle,
  VerificationResult,
  VerificationProof,
  QuorumResult,
} from './types.js';

export interface GenerateSummaryOptions {
  bundle: EvidenceBundle;
  verification?: VerificationResult;
  proof?: VerificationProof;
  quorum?: QuorumResult;
}

/**
 * Generates high-impact GitHub Actions Step Summary Markdown.
 */
export function generateGitHubStepSummary(options: GenerateSummaryOptions): string {
  const { bundle, verification, proof, quorum } = options;
  const lines: string[] = [];

  // 1. Header Banner
  const statusEmoji =
    bundle.status === 'verified'
      ? '✅'
      : bundle.status === 'stale'
      ? '⚠️'
      : bundle.status === 'failed'
      ? '❌'
      : 'ℹ️';

  const statusLabel =
    bundle.status === 'verified'
      ? 'VERIFIED'
      : bundle.status === 'stale'
      ? 'STALE'
      : bundle.status === 'failed'
      ? 'FAILED'
      : 'UNVERIFIED';

  lines.push(`## ${statusEmoji} Evidence MCP — Audit Summary: \`${bundle.id}\``);
  lines.push('');
  lines.push(`> **Task:** ${bundle.task}`);
  lines.push('');

  // 2. Metric Grid
  const gitCount = bundle.evidence.git?.length || 0;
  const fileCount = bundle.evidence.fileSnapshots?.length || 0;
  const cmdCount = bundle.evidence.commands?.length || 0;
  const astCount = bundle.evidence.ast?.length || 0;
  const assertCount = bundle.assertions?.length || 0;
  const endorseCount = bundle.endorsements?.length || 0;

  lines.push('| Verdict | Workspace | Assertions | Files | Git Commits | Commands | AST Files | Endorsements |');
  lines.push('|---|---|---|---|---|---|---|---|');
  lines.push(
    `| **\`${statusLabel}\`** | \`${bundle.workspacePath}\` | ${assertCount} | ${fileCount} | ${gitCount} | ${cmdCount} | ${astCount} | ${endorseCount} |`
  );
  lines.push('');

  // 3. Cryptographic Proof & Quorum Status Callout
  if (proof || quorum) {
    lines.push('### 🛡️ Cryptographic Integrity & Quorum');
    lines.push('');
    if (proof) {
      lines.push(
        `- **Ed25519 Proof:** \`${proof.id}\` &bull; **Verdict:** \`${proof.verdict.toUpperCase()}\` &bull; **Key:** \`${proof.signer.keyFingerprint.slice(0, 16)}...\``
      );
    }
    if (quorum) {
      const qStatus = quorum.satisfied ? '🟢 SATISFIED' : '🔴 NOT MET';
      lines.push(
        `- **Consensus Quorum:** ${qStatus} (${quorum.approvedCount}/${quorum.policy.minEndorsements || 1} required approvals)`
      );
      if (quorum.reasons.length > 0) {
        for (const r of quorum.reasons) {
          lines.push(`  - ⚠️ ${r}`);
        }
      }
    }
    lines.push('');
  }

  // 4. Assertions & Verification Results
  if (verification) {
    lines.push('### 📋 Itemized Verification Verdicts');
    lines.push('');
    lines.push(`**Overall Verification:** ${verification.status.toUpperCase()} &mdash; _${verification.summary}_`);
    lines.push('');

    if (verification.items && verification.items.length > 0) {
      lines.push('| ID | Type | Verdict | Details |');
      lines.push('|---|---|---|---|');
      for (const item of verification.items) {
        const itemPill =
          item.status === 'verified'
            ? '🟢 Verified'
            : item.status === 'stale'
            ? '🟡 Stale'
            : item.status === 'unverifiable'
            ? '⚪ Unverifiable'
            : '🔴 Failed';
        lines.push(`| \`${item.id}\` | \`${item.type}\` | ${itemPill} | ${item.details} |`);
      }
      lines.push('');
    }
  }

  // 5. AST Semantic Diffs & Breaking Change Warnings
  if (bundle.evidence.ast && bundle.evidence.ast.length > 0) {
    const hasBreaking = bundle.evidence.ast.some((a) => a.diff?.isBreakingChange);
    const breakingNotice = hasBreaking ? ' 🚨 **BREAKING CHANGES DETECTED**' : '';
    lines.push(`### 🧬 AST Semantic Analysis${breakingNotice}`);
    lines.push('');
    lines.push('| File Path | Language | Symbols | Semantic Diff | Breaking Change? |');
    lines.push('|---|---|---|---|---|');
    for (const a of bundle.evidence.ast) {
      const diffBadge = !a.diff?.hasChanges
        ? '🟢 Clean'
        : `🟡 ${a.diff.addedSymbols.length + a.diff.removedSymbols.length + a.diff.modifiedSymbols.length} diff(s)`;
      const breakBadge = a.diff?.isBreakingChange ? '🔴 **YES**' : '✅ No';
      lines.push(`| \`${a.filePath}\` | \`${a.language}\` | ${a.symbolsCount} | ${diffBadge} | ${breakBadge} |`);
    }
    lines.push('');
  }

  // 6. Multi-Agent Peer Endorsements
  if (bundle.endorsements && bundle.endorsements.length > 0) {
    lines.push('### 👥 Multi-Agent Peer Endorsements');
    lines.push('');
    lines.push('| Agent ID | Role | Verdict | Key Fingerprint | Review Commentary |');
    lines.push('|---|---|---|---|---|');
    for (const end of bundle.endorsements) {
      const vBadge =
        end.verdict === 'approved'
          ? '🟢 Approved'
          : end.verdict === 'rejected'
          ? '🔴 Rejected'
          : '🟡 Changes Requested';
      lines.push(
        `| **${end.agentId}** | \`${end.role}\` | ${vBadge} | \`${end.signer.keyFingerprint.slice(0, 12)}...\` | ${end.comment} |`
      );
    }
    lines.push('');
  }

  // 7. Collapsible Command Logs
  if (bundle.evidence.commands && bundle.evidence.commands.length > 0) {
    lines.push('<details><summary><b>View Command Execution Logs (' + bundle.evidence.commands.length + ')</b></summary>');
    lines.push('');
    for (const c of bundle.evidence.commands) {
      const exitBadge = c.exitCode === 0 ? '✅ Exit 0' : `❌ Exit ${c.exitCode}`;
      const prov = c.provenance === 'server_executed' ? 'server_executed (verified)' : 'agent_reported';
      lines.push(`#### \`${c.command} ${(c.args || []).join(' ')}\` &mdash; ${exitBadge}`);
      lines.push(`- **Provenance:** \`${prov}\` &bull; **Recorded:** \`${c.executedAt || c.recordedAt}\``);
      if (c.stdout) {
        lines.push('```text');
        lines.push(c.stdout.trim());
        lines.push('```');
      }
      lines.push('');
    }
    lines.push('</details>');
    lines.push('');
  }

  lines.push('---');
  lines.push('_Summary generated by [Evidence MCP](https://github.com/mokashreef/Evidence-MCP) for GitHub Actions CI/CD._');

  return lines.join('\n');
}

/**
 * Appends or writes the generated summary to GitHub Step Summary file if running in GitHub Actions.
 */
export async function writeToGitHubStepSummary(markdown: string): Promise<boolean> {
  const stepSummaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!stepSummaryPath) {
    return false;
  }

  await fs.promises.appendFile(stepSummaryPath, `${markdown}\n\n`, 'utf8');
  return true;
}

