import { EvidenceBundle, VerificationResult } from './types.js';

/**
 * Formats an evidence bundle and optional verification results into Markdown or JSON.
 */
export function exportEvidenceReport(
  bundle: EvidenceBundle,
  format: 'markdown' | 'json',
  verification?: VerificationResult
): string {
  if (format === 'json') {
    return JSON.stringify(
      {
        bundle,
        verification: verification || null,
      },
      null,
      2
    );
  }

  // Markdown format
  const lines: string[] = [];

  const statusBadge =
    bundle.status === 'verified'
      ? '🟢 VERIFIED'
      : bundle.status === 'stale'
      ? '🟡 STALE'
      : bundle.status === 'failed'
      ? '🔴 FAILED'
      : `⚪ ${bundle.status.toUpperCase()}`;

  lines.push(`# Evidence Bundle Report: \`${bundle.id}\``);
  lines.push('');
  lines.push(`**Task:** ${bundle.task}`);
  lines.push(`**Status:** ${statusBadge}`);
  lines.push(`**Created At:** \`${bundle.createdAt}\``);
  lines.push(`**Updated At:** \`${bundle.updatedAt}\``);
  lines.push(`**Workspace:** \`${bundle.workspacePath}\``);
  lines.push('');

  // Assertions
  lines.push('## Assertions');
  lines.push('');
  if (!bundle.assertions || bundle.assertions.length === 0) {
    lines.push('_No assertions recorded._');
  } else {
    lines.push('| ID | Claim | Supporting Evidence IDs |');
    lines.push('|---|---|---|');
    for (const assertion of bundle.assertions) {
      const linked = assertion.evidenceIds.map((id) => `\`${id}\``).join(', ');
      lines.push(`| \`${assertion.id}\` | ${assertion.claim} | ${linked} |`);
    }
  }
  lines.push('');

  // Git Evidence
  if (bundle.evidence.git && bundle.evidence.git.length > 0) {
    lines.push('## Git Evidence');
    lines.push('');
    for (const git of bundle.evidence.git) {
      lines.push(`### Evidence ID: \`${git.id}\``);
      lines.push(`- **Captured At:** \`${git.capturedAt}\``);
      lines.push(`- **Branch:** \`${git.branch}\``);
      lines.push(`- **HEAD Commit:** \`${git.headCommit}\``);
      lines.push(`- **Clean Working Tree:** ${git.isClean ? '✅ Yes' : '⚠️ No'}`);
      if (git.statusShort) {
        lines.push('');
        lines.push('```git');
        lines.push(git.statusShort);
        lines.push('```');
      }
      lines.push('');
    }
  }

  // File Snapshots
  if (bundle.evidence.fileSnapshots && bundle.evidence.fileSnapshots.length > 0) {
    lines.push('## File Snapshots');
    lines.push('');
    lines.push('| Evidence ID | File Path | SHA-256 | Size (Bytes) | Captured At |');
    lines.push('|---|---|---|---|---|');
    for (const file of bundle.evidence.fileSnapshots) {
      lines.push(
        `| \`${file.id}\` | \`${file.path}\` | \`${file.sha256.slice(0, 16)}...\` | ${file.sizeBytes} | \`${file.capturedAt}\` |`
      );
    }
    lines.push('');
  }

  // Command Records
  if (bundle.evidence.commands && bundle.evidence.commands.length > 0) {
    lines.push('## Recorded Commands');
    lines.push('');
    for (const cmd of bundle.evidence.commands) {
      const exitBadge = cmd.exitCode === 0 ? '✅ 0' : `❌ ${cmd.exitCode}`;
      lines.push(`### \`${cmd.command}\` (ID: \`${cmd.id}\`)`);
      lines.push(`- **Exit Code:** ${exitBadge}`);
      lines.push(`- **Recorded At:** \`${cmd.recordedAt}\``);

      if (cmd.stdout && cmd.stdout.trim().length > 0) {
        lines.push('');
        lines.push('<details><summary>Standard Output (stdout)</summary>');
        lines.push('');
        lines.push('```');
        lines.push(cmd.stdout.trim());
        lines.push('```');
        lines.push('</details>');
      }

      if (cmd.stderr && cmd.stderr.trim().length > 0) {
        lines.push('');
        lines.push('<details><summary>Standard Error (stderr)</summary>');
        lines.push('');
        lines.push('```');
        lines.push(cmd.stderr.trim());
        lines.push('```');
        lines.push('</details>');
      }
      lines.push('');
    }
  }

  // Verification Summary if provided
  if (verification) {
    lines.push('## Verification Details');
    lines.push('');
    lines.push(`- **Overall Verdict:** **${verification.status.toUpperCase()}**`);
    lines.push(`- **Verified At:** \`${verification.verifiedAt}\``);
    lines.push(`- **Summary:** ${verification.summary}`);
    lines.push('');

    if (verification.reasons.length > 0) {
      lines.push('### Issues & Findings');
      for (const reason of verification.reasons) {
        lines.push(`- ⚠️ ${reason}`);
      }
      lines.push('');
    }

    if (verification.items.length > 0) {
      lines.push('### Itemized Verification');
      lines.push('');
      lines.push('| ID | Type | Status | Details |');
      lines.push('|---|---|---|---|');
      for (const item of verification.items) {
        const itemStatus =
          item.status === 'verified' ? '🟢 Verified' : item.status === 'stale' ? '🟡 Stale' : '🔴 Failed';
        lines.push(`| \`${item.id}\` | ${item.type} | ${itemStatus} | ${item.details} |`);
      }
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('_Generated by [Evidence MCP](https://github.com/mokashreef/Evidence-MCP) — Verifiable Coding Agent Handoff._');

  return lines.join('\n');
}
