import { EvidenceBundle, VerificationResult } from './types.js';

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
 * Formats an evidence bundle and optional verification results into Markdown, JSON, or standalone HTML.
 */
export function exportEvidenceReport(
  bundle: EvidenceBundle,
  format: 'markdown' | 'json' | 'html',
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

  if (format === 'html') {
    return generateHtmlReport(bundle, verification);
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
    lines.push('## Git Evidence (Independently Verified)');
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
    lines.push('## File Snapshots (Independently Verified)');
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
    lines.push('## Recorded Commands (Agent-Reported)');
    lines.push('');
    lines.push('> [!NOTE]');
    lines.push(
      '> Command results are self-reported by the agent and are not independently executed or verified by Evidence MCP.'
    );
    lines.push('');
    for (const cmd of bundle.evidence.commands) {
      const exitBadge = cmd.exitCode === 0 ? '✅ 0' : `❌ ${cmd.exitCode}`;
      lines.push(`### \`${cmd.command}\` (ID: \`${cmd.id}\`)`);
      lines.push(`- **Provenance:** \`${cmd.provenance || 'agent_reported'}\``);
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

  lines.push('---');
  lines.push('_Generated by [Evidence MCP](https://github.com/mokashreef/Evidence-MCP) — Verifiable Coding Agent Handoff._');

  return lines.join('\n');
}

/**
 * Generates a self-contained, clean, responsive HTML report.
 */
function generateHtmlReport(bundle: EvidenceBundle, verification?: VerificationResult): string {
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
          .map(
            (c) => `<div class="card subcard">
              <div class="cmd-header">
                <code>${escapeHtml(c.command)}</code>
                <span class="badge ${c.exitCode === 0 ? 'badge-success' : 'badge-danger'}">Exit: ${c.exitCode}</span>
              </div>
              <p class="meta">Provenance: <code>${escapeHtml(c.provenance || 'agent_reported')}</code> (Unverified) &bull; Recorded: ${escapeHtml(c.recordedAt)}</p>
              ${c.stdout ? `<details><summary>Standard Output (stdout)</summary><pre><code>${escapeHtml(c.stdout)}</code></pre></details>` : ''}
              ${c.stderr ? `<details><summary>Standard Error (stderr)</summary><pre><code>${escapeHtml(c.stderr)}</code></pre></details>` : ''}
            </div>`
          )
          .join('')
      : '<p class="empty-state">No command executions recorded.</p>';

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
    </div>

    ${verificationHtml}

    <h2>Assertions</h2>
    <div class="card">${assertionsHtml}</div>

    <h2>Git Evidence</h2>
    ${gitHtml}

    <h2>File Snapshots</h2>
    <div class="card">${filesHtml}</div>

    <h2>Recorded Commands (Agent-Reported)</h2>
    ${commandsHtml}

    <footer>
      Generated by <a href="https://github.com/mokashreef/Evidence-MCP" style="color:var(--primary);text-decoration:none;">Evidence MCP</a> &bull; Verifiable Coding Agent Handoff
    </footer>
  </div>
</body>
</html>`;
}
