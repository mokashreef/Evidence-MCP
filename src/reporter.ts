import {
  EvidenceBundle,
  PolicyEvaluationResult,
  SarifLevel,
  SarifReport,
  SarifResult,
  SarifRuleDescriptor,
  VerificationProof,
  VerificationResult,
} from './types.js';

/**
 * Escapes characters for safe inclusion in HTML.
 */
export function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Formats an evidence bundle and optional verification/policy results into Markdown, JSON, HTML, or SARIF v2.1.0.
 */
export function exportEvidenceReport(
  bundle: EvidenceBundle,
  format: 'markdown' | 'json' | 'html' | 'sarif',
  verification?: VerificationResult,
  proof?: VerificationProof,
  policyEvaluation?: PolicyEvaluationResult
): string {
  if (format === 'json') {
    return JSON.stringify(
      {
        bundle,
        verification: verification || null,
        proof: proof || null,
        policyEvaluation: policyEvaluation || null,
      },
      null,
      2
    );
  }

  if (format === 'html') {
    return generateHtmlReport(bundle, verification, proof);
  }

  if (format === 'sarif') {
    return formatSarifReport(bundle, verification, policyEvaluation);
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
      : bundle.status === 'unverifiable'
      ? '⚪ UNVERIFIABLE (AGENT-REPORTED)'
      : `⚪ ${bundle.status.toUpperCase()}`;

  lines.push(`# Evidence Bundle Report: \`${bundle.id}\``);
  lines.push('');
  lines.push(`**Task:** ${bundle.task}`);
  lines.push(`**Status:** ${statusBadge}`);
  lines.push(`**Created At:** \`${bundle.createdAt}\``);
  lines.push(`**Updated At:** \`${bundle.updatedAt}\``);
  lines.push(`**Workspace:** \`${bundle.workspacePath}\``);
  if (bundle.attestation) {
    lines.push(
      `**Cryptographic Attestation:** 🔏 \`${bundle.attestation.algorithm.toUpperCase()}\` (Key: \`${bundle.attestation.keyFingerprint.slice(0, 16)}...\`)`
    );
    lines.push(`**Signed At:** \`${bundle.attestation.signedAt}\``);
  }
  if (proof) {
    lines.push(
      `**Verification Proof:** 🛡️ \`${proof.id}\` (Verdict: \`${proof.verdict.toUpperCase()}\`, Signer: \`${proof.signer.keyFingerprint.slice(0, 16)}...\`)`
    );
  }
  if (bundle.notaryReceipts && bundle.notaryReceipts.length > 0) {
    for (const nr of bundle.notaryReceipts) {
      lines.push(
        `**Remote Notary Receipt:** 🌐 \`${nr.id}\` (Log #${nr.logIndex}, Notary: \`${nr.notaryKeyFingerprint.slice(0, 16)}...\`, At: \`${nr.notarizedAt}\`)`
      );
    }
  }
  lines.push('');

  // Registered Workspaces (if multi-workspace)
  if (bundle.workspaces && Object.keys(bundle.workspaces).length > 1) {
    lines.push('## Registered Workspaces');
    lines.push('');
    lines.push('| Workspace Name | Absolute Path |');
    lines.push('|---|---|');
    for (const [name, wsPath] of Object.entries(bundle.workspaces)) {
      lines.push(`| \`${name}\` | \`${wsPath}\` |`);
    }
    lines.push('');
  }

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
    lines.push('## Git Evidence (Independently Verified)');
    lines.push('');
    for (const git of bundle.evidence.git) {
      lines.push(`### Evidence ID: \`${git.id}\``);
      if (git.workspaceName) {
        lines.push(`- **Workspace:** \`${git.workspaceName}\``);
      }
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
    lines.push('## File Snapshots (Independently Verified)');
    lines.push('');
    const hasMultipleWs = bundle.evidence.fileSnapshots.some((f) => f.workspaceName);
    if (hasMultipleWs) {
      lines.push('| Evidence ID | Workspace | File Path | SHA-256 | Size (Bytes) | Captured At |');
      lines.push('|---|---|---|---|---|---|');
      for (const file of bundle.evidence.fileSnapshots) {
        lines.push(
          `| \`${file.id}\` | \`${file.workspaceName || 'root'}\` | \`${file.path}\` | \`${file.sha256.slice(0, 16)}...\` | ${file.sizeBytes} | \`${file.capturedAt}\` |`
        );
      }
    } else {
      lines.push('| Evidence ID | File Path | SHA-256 | Size (Bytes) | Captured At |');
      lines.push('|---|---|---|---|---|');
      for (const file of bundle.evidence.fileSnapshots) {
        lines.push(
          `| \`${file.id}\` | \`${file.path}\` | \`${file.sha256.slice(0, 16)}...\` | ${file.sizeBytes} | \`${file.capturedAt}\` |`
        );
      }
    }
    lines.push('');
  }

  // Command Records
  if (bundle.evidence.commands && bundle.evidence.commands.length > 0) {
    lines.push('## Command Executions & Records');
    lines.push('');
    lines.push('> [!NOTE]');
    lines.push(
      '> Commands with `server_executed` provenance were directly executed by Evidence MCP in a sandboxed runner. Commands with `agent_reported` provenance are self-reported agent logs.'
    );
    lines.push('');
    for (const cmd of bundle.evidence.commands) {
      const exitBadge = cmd.exitCode === 0 ? '✅ 0' : `❌ ${cmd.exitCode}`;
      const isServerExecuted = cmd.provenance === 'server_executed';
      const cmdDisplay = cmd.args && cmd.args.length > 0 ? `${cmd.command} ${cmd.args.join(' ')}` : cmd.command;
      lines.push(`### \`${cmdDisplay}\` (ID: \`${cmd.id}\`)`);
      if (cmd.workspaceName) {
        lines.push(`- **Workspace:** \`${cmd.workspaceName}\``);
      }
      lines.push(`- **Provenance:** \`${cmd.provenance || 'agent_reported'}\`${isServerExecuted ? ' (Server-Executed)' : ' (Agent-Reported)'}`);
      lines.push(`- **Exit Code:** ${exitBadge}`);
      if (cmd.durationMs !== undefined) {
        lines.push(`- **Duration:** \`${cmd.durationMs}ms\``);
      }
      lines.push(`- **Executed At:** \`${cmd.executedAt || cmd.recordedAt}\``);

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

  // AST Semantic Evidence
  if (bundle.evidence.ast && bundle.evidence.ast.length > 0) {
    lines.push('## AST & Semantic Diff Evidence (Independently Verified)');
    lines.push('');
    for (const ast of bundle.evidence.ast) {
      lines.push(`### \`${ast.filePath}\` (ID: \`${ast.id}\`)`);
      if (ast.workspaceName) {
        lines.push(`- **Workspace:** \`${ast.workspaceName}\``);
      }
      lines.push(`- **Language:** \`${ast.language}\``);
      lines.push(`- **Symbols Analyzed:** ${ast.symbolsCount}`);
      lines.push(`- **Captured At:** \`${ast.capturedAt}\``);

      if (ast.diff) {
        if (!ast.diff.hasChanges) {
          lines.push('- **Semantic Status:** 🟢 Identical to Git HEAD (No semantic changes)');
        } else {
          const breakingBadge = ast.diff.isBreakingChange ? ' 🔴 **BREAKING CHANGE DETECTED**' : '';
          lines.push(`- **Semantic Status:** 🟡 Semantic Diff Detected${breakingBadge}`);
          if (ast.diff.addedSymbols.length > 0) {
            lines.push(
              `  - **Added Symbols (${ast.diff.addedSymbols.length}):** ${ast.diff.addedSymbols
                .map((s) => `\`${s.kind} ${s.name}\``)
                .join(', ')}`
            );
          }
          if (ast.diff.removedSymbols.length > 0) {
            lines.push(
              `  - **Removed Symbols (${ast.diff.removedSymbols.length}):** ${ast.diff.removedSymbols
                .map((s) => `\`${s.kind} ${s.name}\``)
                .join(', ')}`
            );
          }
          if (ast.diff.modifiedSymbols.length > 0) {
            lines.push(`  - **Modified Symbols (${ast.diff.modifiedSymbols.length}):**`);
            for (const mod of ast.diff.modifiedSymbols) {
              lines.push(
                `    - \`${mod.symbol.kind} ${mod.symbol.name}\`: ${mod.changes.join('; ')}`
              );
            }
          }
        }
      }

      if (ast.symbols.length > 0) {
        lines.push('');
        lines.push('<details><summary>Exported & Local Symbols Catalog</summary>');
        lines.push('');
        lines.push('| Kind | Name | Exported | Signature |');
        lines.push('|---|---|---|---|');
        for (const s of ast.symbols) {
          lines.push(
            `| \`${s.kind}\` | \`${s.name}\` | ${s.isExported ? '✅ Yes' : 'No'} | \`${(s.signature || '').replace(/\|/g, '\\|')}\` |`
          );
        }
        lines.push('</details>');
      }
      lines.push('');
    }
  }

  // SBOM Evidence (CycloneDX)
  if (bundle.evidence.sbom && bundle.evidence.sbom.length > 0) {
    lines.push('## SBOM & Supply Chain Evidence');
    lines.push('');
    for (const sbom of bundle.evidence.sbom) {
      const wsLabel = sbom.workspaceName ? ` [${sbom.workspaceName}]` : '';
      lines.push(`### \`${sbom.id}\` (${sbom.format})${wsLabel}`);
      lines.push(`- **Manifest:** \`${sbom.manifestPath}\` (SHA-256: \`${sbom.manifestSha256.slice(0, 16)}...\`)`);
      if (sbom.lockfilePath) {
        lines.push(`- **Lockfile:** \`${sbom.lockfilePath}\` (SHA-256: \`${(sbom.lockfileSha256 || '').slice(0, 16)}...\`)`);
      }
      lines.push(`- **Components:** ${sbom.componentCount} total`);
      lines.push(`- **BOM Digest:** \`${sbom.bomDigest}\``);
      const licPairs = Object.entries(sbom.licenseSummary)
        .map(([k, v]) => `${k}: ${v}`)
        .join(', ');
      if (licPairs) {
        lines.push(`- **Licenses:** ${licPairs}`);
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
          item.status === 'verified'
            ? '🟢 Verified'
            : item.status === 'stale'
            ? '🟡 Stale'
            : item.status === 'unverifiable'
            ? '⚪ Unverifiable (Agent-Reported)'
            : '🔴 Failed';
        lines.push(`| \`${item.id}\` | ${item.type} | ${itemStatus} | ${item.details} |`);
      }
      lines.push('');
    }
  }

  // Peer Endorsements
  if (bundle.endorsements && bundle.endorsements.length > 0) {
    lines.push('## Multi-Agent Peer Endorsements');
    lines.push('');
    lines.push('| Agent ID | Role | Verdict | Signer Key | Review Commentary |');
    lines.push('|---|---|---|---|---|');
    for (const end of bundle.endorsements) {
      const vEmoji =
        end.verdict === 'approved'
          ? '🟢 Approved'
          : end.verdict === 'rejected'
          ? '🔴 Rejected'
          : '🟡 Changes Requested';
      lines.push(
        `| **${end.agentId}** | \`${end.role}\` | ${vEmoji} | \`${end.signer.keyFingerprint.slice(0, 12)}...\` | ${end.comment} |`
      );
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('_Generated by [Evidence MCP](https://github.com/mokashreef/Evidence-MCP) — Verifiable Coding Agent Handoff._');

  return lines.join('\n');
}

/**
 * Generates a self-contained, clean, responsive HTML report.
 */
function generateHtmlReport(
  bundle: EvidenceBundle,
  verification?: VerificationResult,
  proof?: VerificationProof
): string {
  const statusColor =
    bundle.status === 'verified'
      ? '#2da44e'
      : bundle.status === 'stale'
      ? '#bf8700'
      : bundle.status === 'failed'
      ? '#cf222e'
      : '#0969da';

  const statusLabel =
    bundle.status === 'verified'
      ? 'VERIFIED'
      : bundle.status === 'stale'
      ? 'STALE'
      : bundle.status === 'failed'
      ? 'FAILED'
      : 'UNVERIFIABLE (AGENT-REPORTED)';

  const assertionsHtml =
    !bundle.assertions || bundle.assertions.length === 0
      ? '<p class="empty-state">No assertions recorded.</p>'
      : `<table>
          <thead>
            <tr><th>ID</th><th>Claim</th><th>Supporting Evidence</th></tr>
          </thead>
          <tbody>
            ${bundle.assertions
              .map(
                (a) => `<tr>
                  <td><code>${escapeHtml(a.id)}</code></td>
                  <td>${escapeHtml(a.claim)}</td>
                  <td>${a.evidenceIds.map((id) => `<span class="tag">${escapeHtml(id)}</span>`).join(' ')}</td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>`;

  const gitHtml =
    bundle.evidence.git && bundle.evidence.git.length > 0
      ? bundle.evidence.git
          .map(
            (g) => `<div class="card subcard">
              <h4>Evidence ID: <code>${escapeHtml(g.id)}</code></h4>
              <p><strong>Branch:</strong> <code>${escapeHtml(g.branch)}</code> | <strong>HEAD:</strong> <code>${escapeHtml(g.headCommit)}</code> | <strong>Clean Tree:</strong> ${g.isClean ? '✅ Yes' : '⚠️ No'}</p>
              ${g.statusShort ? `<pre><code>${escapeHtml(g.statusShort)}</code></pre>` : ''}
            </div>`
          )
          .join('')
      : '<p class="empty-state">No Git evidence recorded.</p>';

  const filesHtml =
    bundle.evidence.fileSnapshots && bundle.evidence.fileSnapshots.length > 0
      ? `<table>
          <thead>
            <tr><th>ID</th><th>File Path</th><th>SHA-256</th><th>Size</th><th>Captured At</th></tr>
          </thead>
          <tbody>
            ${bundle.evidence.fileSnapshots
              .map(
                (f) => `<tr>
                  <td><code>${escapeHtml(f.id)}</code></td>
                  <td><code>${escapeHtml(f.path)}</code></td>
                  <td title="${escapeHtml(f.sha256)}"><code>${escapeHtml(f.sha256.slice(0, 16))}...</code></td>
                  <td>${f.sizeBytes} B</td>
                  <td>${escapeHtml(f.capturedAt)}</td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>`
      : '<p class="empty-state">No file snapshots recorded.</p>';

  const commandsHtml =
    bundle.evidence.commands && bundle.evidence.commands.length > 0
      ? bundle.evidence.commands
          .map((c) => {
            const isServer = c.provenance === 'server_executed';
            const cmdText = c.args && c.args.length > 0 ? `${c.command} ${c.args.join(' ')}` : c.command;
            const provBadge = isServer
              ? '<span class="badge badge-success">server_executed (verified)</span>'
              : '<span class="badge badge-info">agent_reported (unverified)</span>';
            const durationText = c.durationMs !== undefined ? ` &bull; Duration: ${c.durationMs}ms` : '';
            return `<div class="card subcard">
              <div class="cmd-header">
                <code>${escapeHtml(cmdText)}</code>
                <div>
                  ${provBadge}
                  <span class="badge ${c.exitCode === 0 ? 'badge-success' : 'badge-danger'}">Exit: ${c.exitCode}</span>
                </div>
              </div>
              <p class="meta">Provenance: <code>${escapeHtml(c.provenance || 'agent_reported')}</code>${durationText} &bull; Recorded: ${escapeHtml(c.executedAt || c.recordedAt)}</p>
              ${c.stdout ? `<details><summary>Standard Output (stdout)</summary><pre><code>${escapeHtml(c.stdout)}</code></pre></details>` : ''}
              ${c.stderr ? `<details><summary>Standard Error (stderr)</summary><pre><code>${escapeHtml(c.stderr)}</code></pre></details>` : ''}
            </div>`;
          })
          .join('')
      : '<p class="empty-state">No command executions recorded.</p>';

  const astHtml =
    bundle.evidence.ast && bundle.evidence.ast.length > 0
      ? bundle.evidence.ast
          .map((a) => {
            const breakingBadge = a.diff?.isBreakingChange
              ? '<span class="badge badge-danger">BREAKING CHANGE</span>'
              : '';
            const statusBadge = !a.diff?.hasChanges
              ? '<span class="badge badge-success">Clean (No Diff)</span>'
              : `<span class="badge badge-warning">Modified (${(a.diff.addedSymbols.length + a.diff.removedSymbols.length + a.diff.modifiedSymbols.length)} diffs)</span>`;
            const wsTag = a.workspaceName ? `<span class="tag">${escapeHtml(a.workspaceName)}</span>` : '';

            let diffDetails = '';
            if (a.diff && a.diff.hasChanges) {
              const added =
                a.diff.addedSymbols.length > 0
                  ? `<div style="margin: 4px 0;"><strong style="color:#2da44e;">+ Added:</strong> ${a.diff.addedSymbols
                      .map((s) => `<code>${escapeHtml(s.kind)} ${escapeHtml(s.name)}</code>`)
                      .join(', ')}</div>`
                  : '';
              const removed =
                a.diff.removedSymbols.length > 0
                  ? `<div style="margin: 4px 0;"><strong style="color:#cf222e;">- Removed:</strong> ${a.diff.removedSymbols
                      .map((s) => `<code>${escapeHtml(s.kind)} ${escapeHtml(s.name)}</code>`)
                      .join(', ')}</div>`
                  : '';
              const modified =
                a.diff.modifiedSymbols.length > 0
                  ? `<div style="margin: 4px 0;"><strong style="color:#bf8700;">~ Modified:</strong> ${a.diff.modifiedSymbols
                      .map(
                        (m) =>
                          `<code>${escapeHtml(m.symbol.kind)} ${escapeHtml(m.symbol.name)}</code> (${escapeHtml(m.changes.join('; '))})`
                      )
                      .join(', ')}</div>`
                  : '';
              diffDetails = `<div style="margin-top: 8px; font-size: 13px;">${added}${removed}${modified}</div>`;
            }

            return `<div class="card subcard">
              <div class="cmd-header">
                <div>
                  <code>${escapeHtml(a.filePath)}</code> ${wsTag}
                  <span class="tag">${escapeHtml(a.language)}</span>
                </div>
                <div>
                  ${statusBadge}
                  ${breakingBadge}
                </div>
              </div>
              <p class="meta">Evidence ID: <code>${escapeHtml(a.id)}</code> &bull; Symbols: ${a.symbolsCount} &bull; Captured: ${escapeHtml(a.capturedAt)}</p>
              ${diffDetails}
              ${
                a.symbols.length > 0
                  ? `<details><summary>Exported & Local Symbols (${a.symbols.length})</summary>
                     <table>
                       <thead><tr><th>Kind</th><th>Name</th><th>Exported</th><th>Signature</th></tr></thead>
                       <tbody>
                         ${a.symbols
                           .map(
                             (s) =>
                               `<tr><td><code>${escapeHtml(s.kind)}</code></td><td><strong>${escapeHtml(
                                 s.name
                               )}</strong></td><td>${
                                 s.isExported
                                   ? '<span class="badge badge-success">Yes</span>'
                                   : '<span class="badge">No</span>'
                               }</td><td><code>${escapeHtml(s.signature || '')}</code></td></tr>`
                           )
                           .join('')}
                       </tbody>
                     </table>
                   </details>`
                  : ''
              }
            </div>`;
          })
          .join('')
      : '<p class="empty-state">No AST semantic evidence recorded.</p>';

  const verificationHtml = verification
    ? `<div class="card verification-card">
        <h3>Verification Details</h3>
        <p><strong>Verdict:</strong> <span class="status-pill" style="background:${statusColor}">${escapeHtml(verification.status.toUpperCase())}</span></p>
        <p><strong>Summary:</strong> ${escapeHtml(verification.summary)}</p>
        <p class="meta">Verified At: ${escapeHtml(verification.verifiedAt)}</p>
        ${
          verification.reasons.length > 0
            ? `<div class="findings"><strong>Findings:</strong><ul>${verification.reasons.map((r) => `<li>⚠️ ${escapeHtml(r)}</li>`).join('')}</ul></div>`
            : ''
        }
        ${
          verification.items.length > 0
            ? `<table>
                <thead><tr><th>ID</th><th>Type</th><th>Status</th><th>Details</th></tr></thead>
                <tbody>
                  ${verification.items
                    .map(
                      (item) => `<tr>
                        <td><code>${escapeHtml(item.id)}</code></td>
                        <td>${escapeHtml(item.type)}</td>
                        <td><span class="badge ${item.status === 'verified' ? 'badge-success' : item.status === 'stale' ? 'badge-warning' : item.status === 'unverifiable' ? 'badge-info' : 'badge-danger'}">${escapeHtml(item.status)}</span></td>
                        <td>${escapeHtml(item.details)}</td>
                      </tr>`
                    )
                    .join('')}
                </tbody>
              </table>`
            : ''
        }
      </div>`
    : '';

  const endorsementsHtml =
    bundle.endorsements && bundle.endorsements.length > 0
      ? `<div class="card">
        <table>
          <thead><tr><th>Agent ID</th><th>Role</th><th>Verdict</th><th>Signer Fingerprint</th><th>Review Commentary</th></tr></thead>
          <tbody>
            ${bundle.endorsements
              .map(
                (end) => `<tr>
                  <td><strong>${escapeHtml(end.agentId)}</strong></td>
                  <td><span class="tag">${escapeHtml(end.role)}</span></td>
                  <td><span class="badge ${end.verdict === 'approved' ? 'badge-success' : end.verdict === 'rejected' ? 'badge-danger' : 'badge-warning'}">${escapeHtml(end.verdict)}</span></td>
                  <td><code>${escapeHtml(end.signer.keyFingerprint.slice(0, 12))}...</code></td>
                  <td>${escapeHtml(end.comment)}</td>
                </tr>`
              )
              .join('')}
          </tbody>
        </table>
      </div>`
      : '<p class="empty-state">No peer endorsements recorded.</p>';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Evidence Bundle Report: ${escapeHtml(bundle.id)}</title>
  <style>
    :root {
      --bg: #f6f8fa;
      --card-bg: #ffffff;
      --text: #1f2328;
      --text-muted: #656d76;
      --border: #d0d7de;
      --code-bg: #f6f8fa;
      --primary: #0969da;
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #0d1117;
        --card-bg: #161b22;
        --text: #e6edf3;
        --text-muted: #848d97;
        --border: #30363d;
        --code-bg: #1f242c;
        --primary: #2f81f7;
      }
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      margin: 0;
      padding: 24px;
    }
    .container {
      max-width: 980px;
      margin: 0 auto;
    }
    header {
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
    }
    h1 { margin: 0 0 8px 0; font-size: 24px; }
    h2 { font-size: 18px; margin: 24px 0 12px 0; border-bottom: 1px solid var(--border); padding-bottom: 6px; }
    h3 { font-size: 16px; margin: 0 0 12px 0; }
    h4 { font-size: 14px; margin: 0 0 8px 0; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .subcard { margin-top: 12px; }
    .status-banner {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      color: #ffffff;
      font-weight: 600;
      font-size: 12px;
      margin-left: 8px;
    }
    .meta-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      font-size: 14px;
    }
    .meta-item { display: flex; flex-direction: column; }
    .meta-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
    code {
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 12px;
      background: var(--code-bg);
      padding: 2px 6px;
      border-radius: 4px;
    }
    pre {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px;
      overflow-x: auto;
    }
    pre code { background: none; padding: 0; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      margin-top: 8px;
    }
    th, td {
      text-align: left;
      padding: 8px 12px;
      border: 1px solid var(--border);
    }
    th { background: var(--code-bg); }
    .tag {
      background: var(--code-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2px 8px;
      font-size: 11px;
    }
    .badge {
      display: inline-block;
      padding: 2px 6px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
    }
    .badge-success { background: rgba(46, 160, 67, 0.15); color: #2da44e; }
    .badge-warning { background: rgba(187, 128, 9, 0.15); color: #bf8700; }
    .badge-danger { background: rgba(207, 34, 46, 0.15); color: #cf222e; }
    .badge-info { background: rgba(9, 105, 218, 0.15); color: #0969da; }
    .status-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      color: #fff;
      font-size: 11px;
      font-weight: 600;
    }
    .cmd-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }
    details { margin-top: 8px; font-size: 13px; }
    summary { cursor: pointer; color: var(--primary); font-weight: 500; }
    .meta { font-size: 12px; color: var(--text-muted); margin: 4px 0; }
    .empty-state { color: var(--text-muted); font-style: italic; font-size: 13px; }
    .findings { margin: 12px 0; color: #bf8700; font-size: 13px; }
    .findings ul { margin: 4px 0; padding-left: 20px; }
    footer {
      margin-top: 32px;
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      border-top: 1px solid var(--border);
      padding-top: 16px;
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>
        Evidence Bundle: <code>${escapeHtml(bundle.id)}</code>
        <span class="status-banner" style="background:${statusColor}">${escapeHtml(statusLabel)}</span>
      </h1>
      <p style="margin: 8px 0 0 0; font-size: 15px;">${escapeHtml(bundle.task)}</p>
    </header>

    <div class="card meta-grid">
      <div class="meta-item"><span class="meta-label">Workspace</span><code>${escapeHtml(bundle.workspacePath)}</code></div>
      <div class="meta-item"><span class="meta-label">Created At</span><span>${escapeHtml(bundle.createdAt)}</span></div>
      <div class="meta-item"><span class="meta-label">Updated At</span><span>${escapeHtml(bundle.updatedAt)}</span></div>
      <div class="meta-item"><span class="meta-label">Status</span><span style="font-weight:600;color:${statusColor}">${escapeHtml(bundle.status)}</span></div>
      ${
        bundle.attestation
          ? `<div class="meta-item"><span class="meta-label">Attestation</span><span>🔏 ${escapeHtml(bundle.attestation.algorithm.toUpperCase())} (<code>${escapeHtml(bundle.attestation.keyFingerprint.slice(0, 12))}...</code>)</span></div>`
          : ''
      }
      ${
        proof
          ? `<div class="meta-item"><span class="meta-label">Verification Proof</span><span>🛡️ <code>${escapeHtml(proof.id)}</code> (${escapeHtml(proof.verdict.toUpperCase())})</span></div>`
          : ''
      }
    </div>

    ${verificationHtml}

    ${
      bundle.workspaces && Object.keys(bundle.workspaces).length > 1
        ? `<h2>Registered Workspaces</h2>
    <div class="card">
      <table>
        <thead><tr><th>Workspace Name</th><th>Absolute Path</th></tr></thead>
        <tbody>
          ${Object.entries(bundle.workspaces)
            .map(
              ([name, wsPath]) =>
                `<tr><td><span class="tag">${escapeHtml(name)}</span></td><td><code>${escapeHtml(wsPath)}</code></td></tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>`
        : ''
    }

    <h2>Assertions</h2>
    <div class="card">${assertionsHtml}</div>

    <h2>Git Evidence</h2>
    ${gitHtml}

    <h2>File Snapshots</h2>
    <div class="card">${filesHtml}</div>

    <h2>AST & Semantic Diff Evidence</h2>
    ${astHtml}

    ${
      bundle.evidence.sbom && bundle.evidence.sbom.length > 0
        ? `<h2>SBOM & Supply Chain Evidence</h2>
    <div class="card">
      <table>
        <thead><tr><th>ID</th><th>Format</th><th>Manifest</th><th>Components</th><th>BOM Digest</th></tr></thead>
        <tbody>
          ${bundle.evidence.sbom
            .map(
              (s) =>
                `<tr><td><code>${escapeHtml(s.id)}</code></td><td><span class="tag">${escapeHtml(s.format)}</span></td><td><code>${escapeHtml(s.lockfilePath || s.manifestPath)}</code></td><td>${s.componentCount}</td><td><code>${escapeHtml(s.bomDigest.slice(0, 16))}...</code></td></tr>`
            )
            .join('')}
        </tbody>
      </table>
    </div>`
        : ''
    }

    <h2>Command Executions & Records</h2>
    ${commandsHtml}

    <h2>Multi-Agent Peer Endorsements</h2>
    ${endorsementsHtml}

    <footer>
      Generated by <a href="https://github.com/mokashreef/Evidence-MCP" style="color:var(--primary);text-decoration:none;">Evidence MCP</a> &bull; Verifiable Coding Agent Handoff
    </footer>
  </div>
</body>
</html>`;
}

function normalizeSarifUri(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

/**
 * Formats verification findings, AST breaking changes, and policy violations
 * into OASIS SARIF v2.1.0 JSON for native GitHub Code Scanning ingestion.
 */
export function formatSarifReport(
  bundle: EvidenceBundle,
  verification?: VerificationResult,
  policyEvaluation?: PolicyEvaluationResult
): string {
  const rulesMap = new Map<string, SarifRuleDescriptor>();
  const results: SarifResult[] = [];

  const registerRule = (
    id: string,
    shortDescription: string,
    level: SarifLevel,
    tags: string[]
  ) => {
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: id,
        shortDescription: { text: shortDescription },
        defaultConfiguration: { level },
        properties: { tags },
      });
    }
  };

  const defaultBundleUri = normalizeSarifUri(`.evidence-mcp/bundles/${bundle.id}.json`);

  // Index evidence IDs to file URIs so verification items resolve exact physical paths
  const evidencePathMap = new Map<string, string>();
  for (const snap of bundle.evidence.fileSnapshots || []) {
    evidencePathMap.set(snap.id, normalizeSarifUri(snap.path));
  }
  for (const astEv of bundle.evidence.ast || []) {
    evidencePathMap.set(astEv.id, normalizeSarifUri(astEv.filePath));
  }
  for (const sbomEv of bundle.evidence.sbom || []) {
    evidencePathMap.set(sbomEv.id, normalizeSarifUri(sbomEv.lockfilePath || sbomEv.manifestPath));
  }

  // 1. Verification findings (failed / stale / unverifiable)
  if (verification) {
    for (const item of verification.items) {
      if (item.status === 'verified' || item.status === 'recorded') {
        continue;
      }

      const level: SarifLevel =
        item.status === 'failed'
          ? 'error'
          : item.status === 'stale'
          ? 'warning'
          : 'note';

      const ruleId = `EVIDENCE-${item.status.toUpperCase()}-${item.type.toUpperCase()}`;
      registerRule(
        ruleId,
        `Evidence ${item.type} verification ${item.status}`,
        level,
        ['evidence-mcp', 'verification', item.type]
      );

      const resolvedUri =
        evidencePathMap.get(item.id) ||
        (item.target ? normalizeSarifUri(item.target) : defaultBundleUri);

      results.push({
        ruleId,
        level,
        message: { text: item.details },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: resolvedUri, uriBaseId: '%SRCROOT%' },
              region: { startLine: 1 },
            },
          },
        ],
        properties: {
          bundleId: bundle.id,
          evidenceId: item.id,
          status: item.status,
        },
      });
    }
  }

  // 2. AST Breaking Changes with exact source symbol line regions
  for (const astEv of bundle.evidence.ast || []) {
    if (!astEv.diff?.isBreakingChange) {
      continue;
    }

    const fileUri = normalizeSarifUri(astEv.filePath);
    registerRule(
      'AST-BREAKING-CHANGE',
      'Breaking semantic change detected in exported AST symbol',
      'error',
      ['evidence-mcp', 'ast', 'breaking-change']
    );

    for (const removed of astEv.diff.removedSymbols) {
      if (!removed.isExported) continue;
      results.push({
        ruleId: 'AST-BREAKING-CHANGE',
        level: 'error',
        message: {
          text: `Breaking change in ${astEv.filePath}: exported ${removed.kind} "${removed.name}" was removed.`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: fileUri, uriBaseId: '%SRCROOT%' },
              region: {
                startLine: Math.max(1, removed.startLine || 1),
                endLine: Math.max(1, removed.endLine || removed.startLine || 1),
              },
            },
          },
        ],
        properties: {
          language: astEv.language,
          symbolName: removed.name,
          changeType: 'removed_exported_symbol',
        },
      });
    }

    for (const mod of astEv.diff.modifiedSymbols) {
      results.push({
        ruleId: 'AST-BREAKING-CHANGE',
        level: 'error',
        message: {
          text: `Breaking change in ${astEv.filePath} (${mod.symbol.name}): ${mod.changes.join(' ')}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: fileUri, uriBaseId: '%SRCROOT%' },
              region: {
                startLine: Math.max(1, mod.symbol.startLine || 1),
                endLine: Math.max(1, mod.symbol.endLine || mod.symbol.startLine || 1),
              },
            },
          },
        ],
        properties: {
          language: astEv.language,
          symbolName: mod.symbol.name,
          changeType: 'modified_exported_symbol',
        },
      });
    }
  }

  // 3. Policy Compliance Violations
  if (policyEvaluation) {
    for (const evalItem of policyEvaluation.evaluations) {
      if (evalItem.passed) {
        continue;
      }

      const level: SarifLevel = evalItem.severity === 'error' ? 'error' : 'warning';
      const ruleId = `POLICY-${evalItem.rule.toUpperCase().replace(/[^A-Z0-9]+/g, '-')}`;

      registerRule(
        ruleId,
        `Evidence policy violation: ${evalItem.rule}`,
        level,
        ['evidence-mcp', 'policy', evalItem.category]
      );

      const fallbackPolicyUri =
        evalItem.category === 'license'
          ? 'package.json'
          : evalItem.category === 'sbom'
          ? 'package-lock.json'
          : 'evidence.policy.json';

      results.push({
        ruleId,
        level,
        message: { text: evalItem.message },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: fallbackPolicyUri, uriBaseId: '%SRCROOT%' },
              region: { startLine: 1 },
            },
          },
        ],
        properties: {
          bundleId: bundle.id,
          category: evalItem.category,
          rule: evalItem.rule,
          details: evalItem.details,
        },
      });
    }
  }

  const executionSuccessful =
    (!verification || verification.status === 'verified') &&
    (!policyEvaluation || policyEvaluation.passed);

  const report: SarifReport = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Evidence MCP',
            version: '1.2.0',
            informationUri: 'https://github.com/mokashreef/Evidence-MCP',
            rules: Array.from(rulesMap.values()),
          },
        },
        invocations: [
          {
            executionSuccessful,
            properties: {
              bundleId: bundle.id,
              bundleStatus: verification?.status || bundle.status,
              policyPassed: policyEvaluation?.passed,
            },
          },
        ],
        results,
      },
    ],
  };

  return JSON.stringify(report, null, 2);
}
