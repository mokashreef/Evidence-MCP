import path from 'node:path';
import fs from 'node:fs';
import {
  WorkspaceDashboardData,
  WorkspaceDashboardSummary,
  WorkspaceDashboardSecurity,
  WorkspaceDashboardBreakdowns,
  WorkspaceDashboardRecentBundle,
  GetWorkspaceDashboardInput,
} from './types.js';
import { validateWorkspacePath } from './security.js';
import { listBundles } from './storage.js';
import { loadAgentRegistry } from './registry.js';

export interface ComputeDashboardOptions {
  workspacePath?: string;
}

/**
 * Aggregates all bundles, cryptographic attestations, agent registries,
 * and compliance policies across a workspace to produce structured audit metrics.
 */
export async function computeWorkspaceDashboard(
  options?: ComputeDashboardOptions
): Promise<WorkspaceDashboardData> {
  const ws = validateWorkspacePath(options?.workspacePath || process.cwd());
  const bundles = await listBundles(ws);

  // 1. Summary
  const summary: WorkspaceDashboardSummary = {
    totalBundles: bundles.length,
    verified: bundles.filter((b) => b.status === 'verified').length,
    stale: bundles.filter((b) => b.status === 'stale').length,
    failed: bundles.filter((b) => b.status === 'failed').length,
    inProgress: bundles.filter((b) => b.status === 'in_progress').length,
    unverifiable: bundles.filter((b) => b.status === 'unverifiable').length,
  };

  // 2. Security & Identity
  let activeTrustedAgents = 0;
  let revokedAgents = 0;
  const agentRoleByFingerprint = new Map<string, string>();

  try {
    const registry = await loadAgentRegistry(ws);
    for (const agent of Object.values(registry.agents || {})) {
      if (agent.status === 'active') {
        activeTrustedAgents++;
      } else if (agent.status === 'revoked') {
        revokedAgents++;
      }
      if (agent.keyFingerprint && agent.role) {
        agentRoleByFingerprint.set(agent.keyFingerprint, agent.role);
      }
    }
  } catch {
    // Registry not initialized or empty; default to zero
  }

  const activePolicies = fs.existsSync(path.join(ws, 'evidence.policy.json'));

  const security: WorkspaceDashboardSecurity = {
    signedAttestations: bundles.filter((b) => Boolean(b.attestation)).length,
    notaryReceipts: bundles.reduce((sum, b) => sum + (b.notaryReceipts?.length || 0), 0),
    rekorEntries: bundles.reduce((sum, b) => sum + (b.rekorEntries?.length || 0), 0),
    activeTrustedAgents,
    revokedAgents,
    activePolicies,
  };

  // 3. Breakdowns
  const breakdowns: WorkspaceDashboardBreakdowns = {
    totalAssertions: bundles.reduce((sum, b) => sum + (b.assertions?.length || 0), 0),
    totalSnapshots: bundles.reduce((sum, b) => sum + (b.evidence?.fileSnapshots?.length || 0), 0),
    totalAstEvidence: bundles.reduce((sum, b) => sum + (b.evidence?.ast?.length || 0), 0),
    totalBreakingChanges: bundles.reduce(
      (sum, b) => sum + (b.evidence?.ast?.filter((a) => Boolean(a.diff?.isBreakingChange)).length || 0),
      0
    ),
    totalCommandsExecuted: bundles.reduce((sum, b) => sum + (b.evidence?.commands?.length || 0), 0),
    totalSbomComponents: bundles.reduce(
      (sum, b) =>
        sum +
        (b.evidence?.sbom?.reduce(
          (s, sb) => s + (sb.componentCount || sb.components?.length || 0),
          0
        ) || 0),
      0
    ),
  };

  // 4. Recent Bundles (sorted newest first, max 10)
  const sorted = [...bundles].sort((a, b) => {
    const timeA = new Date(a.createdAt).getTime() || 0;
    const timeB = new Date(b.createdAt).getTime() || 0;
    return timeB - timeA;
  });

  const recentBundles: WorkspaceDashboardRecentBundle[] = sorted.slice(0, 10).map((b) => {
    const breakingChanges = b.evidence?.ast?.filter((a) => Boolean(a.diff?.isBreakingChange)).length || 0;
    let signerRole: string | undefined;

    if (b.attestation?.keyFingerprint) {
      signerRole = agentRoleByFingerprint.get(b.attestation.keyFingerprint);
    }
    if (!signerRole && b.endorsements && b.endorsements.length > 0) {
      signerRole = b.endorsements[0].role;
    }

    return {
      id: b.id,
      task: b.task,
      status: b.status,
      createdAt: b.createdAt,
      signed: Boolean(b.attestation),
      signerRole,
      notarized: Boolean(b.notaryReceipts && b.notaryReceipts.length > 0),
      rekorAudit: Boolean(b.rekorEntries && b.rekorEntries.length > 0),
      breakingChanges,
      assertionCount: b.assertions?.length || 0,
    };
  });

  return {
    workspacePath: ws,
    generatedAt: new Date().toISOString(),
    summary,
    security,
    breakdowns,
    recentBundles,
  };
}

/**
 * Helper to wrap text with ANSI escape sequence when colors are enabled.
 */
function color(code: string, text: string, noColor: boolean): string {
  if (noColor) return text;
  return `\x1b[${code}m${text}\x1b[0m`;
}

function calcPct(count: number, total: number): string {
  if (total <= 0) return '0.0%';
  return `${((count / total) * 100).toFixed(1)}%`;
}

/**
 * Formats WorkspaceDashboardData into a rich, terminal-ready visual dashboard.
 */
export function renderTerminalDashboard(
  data: WorkspaceDashboardData,
  options?: { noColor?: boolean }
): string {
  const noColor = Boolean(options?.noColor);
  const width = 80;
  const line = '='.repeat(width);
  const sep = '-'.repeat(width);

  const out: string[] = [];

  // Header Banner
  out.push(line);
  out.push(color('1;36', '  EVIDENCE MCP — WORKSPACE SECURITY & AUDIT DASHBOARD', noColor));
  out.push(line);
  out.push(`  Workspace:   ${color('1', data.workspacePath, noColor)}`);
  out.push(`  Generated:   ${data.generatedAt}`);
  const policyLabel = data.security.activePolicies
    ? color('1;32', 'YES (evidence.policy.json active)', noColor)
    : color('90', 'NO (no policy file detected)', noColor);
  out.push(`  Policy File: ${policyLabel}`);
  out.push('');

  // 1. Bundle Status Summary
  out.push(sep);
  out.push(color('1;34', '  [1] BUNDLE STATUS SUMMARY', noColor));
  out.push(sep);
  const tot = data.summary.totalBundles;
  out.push(`    Total Bundles:   ${color('1', String(tot), noColor)}`);
  out.push(
    `    ${color('1;32', '[V] Verified:', noColor)}     ${data.summary.verified.toString().padEnd(4)} (${calcPct(
      data.summary.verified,
      tot
    )})`
  );
  out.push(
    `    ${color('1;33', '[S] Stale:', noColor)}        ${data.summary.stale.toString().padEnd(4)} (${calcPct(
      data.summary.stale,
      tot
    )})`
  );
  out.push(
    `    ${color('1;31', '[F] Failed:', noColor)}       ${data.summary.failed.toString().padEnd(4)} (${calcPct(
      data.summary.failed,
      tot
    )})`
  );
  out.push(
    `    ${color('1;35', '[P] In Progress:', noColor)}  ${data.summary.inProgress.toString().padEnd(4)} (${calcPct(
      data.summary.inProgress,
      tot
    )})`
  );
  out.push(
    `    ${color('90', '[?] Unverifiable:', noColor)} ${data.summary.unverifiable.toString().padEnd(4)} (${calcPct(
      data.summary.unverifiable,
      tot
    )})`
  );
  out.push('');

  // 2. Cryptographic & Supply-Chain Security
  out.push(sep);
  out.push(color('1;34', '  [2] CRYPTOGRAPHIC & SUPPLY-CHAIN SECURITY', noColor));
  out.push(sep);
  out.push(`    Signed Attestations:        ${color('1', String(data.security.signedAttestations), noColor)}`);
  out.push(`    Transparency Notarizations: ${color('1', String(data.security.notaryReceipts), noColor)}`);
  out.push(`    Sigstore Rekor Proofs:      ${color('1', String(data.security.rekorEntries), noColor)}`);
  out.push(
    `    Trusted Agent Registry:     ${color('1;32', `${data.security.activeTrustedAgents} active`, noColor)}, ${color(
      data.security.revokedAgents > 0 ? '1;31' : '90',
      `${data.security.revokedAgents} revoked`,
      noColor
    )}`
  );
  out.push('');

  // 3. Evidence Inventory Breakdowns
  out.push(sep);
  out.push(color('1;34', '  [3] EVIDENCE INVENTORY BREAKDOWNS', noColor));
  out.push(sep);
  const b = data.breakdowns;
  const col1A = `Assertions:        ${color('1', String(b.totalAssertions).padEnd(6), noColor)}`;
  const col1B = `|  File Snapshots:      ${color('1', String(b.totalSnapshots), noColor)}`;
  out.push(`    ${col1A} ${col1B}`);

  const col2A = `AST Symbols:       ${color('1', String(b.totalAstEvidence).padEnd(6), noColor)}`;
  const col2B = `|  Breaking Changes:    ${color(
    b.totalBreakingChanges > 0 ? '1;31' : '1',
    String(b.totalBreakingChanges),
    noColor
  )}`;
  out.push(`    ${col2A} ${col2B}`);

  const col3A = `Commands Executed: ${color('1', String(b.totalCommandsExecuted).padEnd(6), noColor)}`;
  const col3B = `|  SBOM Components:     ${color('1', String(b.totalSbomComponents), noColor)}`;
  out.push(`    ${col3A} ${col3B}`);
  out.push('');

  // 4. Recent Bundles
  out.push(sep);
  out.push(color('1;34', '  [4] RECENT EVIDENCE BUNDLES', noColor));
  out.push(sep);

  if (data.recentBundles.length === 0) {
    out.push('    (No evidence bundles recorded yet in this workspace)');
    out.push('    Tip: Use MCP tool "create_evidence_bundle" or CLI "evidence-mcp exec" to record evidence.');
  } else {
    // Table Header
    const hdr = `    ${'ID'.padEnd(17)} ${'STATUS'.padEnd(12)} ${'SIGNED'.padEnd(8)} ${'NOTARY'.padEnd(8)} ${'REKOR'.padEnd(7)} ${'BRK'.padEnd(5)} TASK`;
    out.push(color('90', hdr, noColor));

    for (const item of data.recentBundles) {
      let statusFormatted = item.status.toUpperCase();
      if (item.status === 'verified') statusFormatted = color('1;32', statusFormatted.padEnd(12), noColor);
      else if (item.status === 'stale') statusFormatted = color('1;33', statusFormatted.padEnd(12), noColor);
      else if (item.status === 'failed') statusFormatted = color('1;31', statusFormatted.padEnd(12), noColor);
      else if (item.status === 'in_progress') statusFormatted = color('1;35', statusFormatted.padEnd(12), noColor);
      else statusFormatted = color('90', statusFormatted.padEnd(12), noColor);

      const signedText = item.signed ? color('1;32', 'YES'.padEnd(8), noColor) : color('90', 'NO'.padEnd(8), noColor);
      const notaryText = item.notarized ? color('1;32', 'YES'.padEnd(8), noColor) : color('90', 'NO'.padEnd(8), noColor);
      const rekorText = item.rekorAudit ? color('1;32', 'YES'.padEnd(7), noColor) : color('90', 'NO'.padEnd(7), noColor);
      const brkText =
        item.breakingChanges > 0
          ? color('1;31', String(item.breakingChanges).padEnd(5), noColor)
          : color('90', '0'.padEnd(5), noColor);

      const maxTaskLen = 22;
      const truncatedTask =
        item.task.length > maxTaskLen ? `${item.task.slice(0, maxTaskLen - 3)}...` : item.task;

      out.push(
        `    ${item.id.padEnd(17)} ${statusFormatted} ${signedText} ${notaryText} ${rekorText} ${brkText} ${truncatedTask}`
      );
    }
  }

  out.push(line);
  return out.join('\n');
}

/**
 * Coordinator to produce either JSON or text representation of workspace dashboard.
 */
export async function getWorkspaceDashboard(
  input?: GetWorkspaceDashboardInput
): Promise<{ data: WorkspaceDashboardData; formatted: string }> {
  const data = await computeWorkspaceDashboard({ workspacePath: input?.workspacePath });
  const format = input?.format || 'json';
  const noColor = Boolean(input?.noColor);
  const formatted =
    format === 'text' ? renderTerminalDashboard(data, { noColor }) : JSON.stringify(data, null, 2);

  return { data, formatted };
}
