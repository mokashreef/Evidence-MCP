#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createEvidenceServer } from './server.js';
import { listBundles, loadBundle, saveBundle, generateId, resolveWorkspaceForBundle, loadProof } from './storage.js';
import { verifyEvidenceBundle } from './verifier.js';
import { exportEvidenceReport } from './reporter.js';
import { signEvidenceBundle } from './attestation.js';
import { executeSandboxedCommand } from './runner.js';
import { captureFileAstEvidence } from './ast.js';
import { createVerificationProof, verifyProofSignature, replayEvidenceBundle } from './proof.js';
import { createPeerEndorsement, checkBundleQuorum } from './consensus.js';
import { generateGitHubStepSummary, writeToGitHubStepSummary } from './github-summary.js';
import { evaluateEvidencePolicy, loadPolicyFile } from './policy.js';
import { dispatchAuditWebhook } from './webhook.js';
import {
  CommandEvidence,
  VerificationProof,
  EvidenceBundle,
  EvidencePolicy,
  PeerEndorsementRole,
  PeerEndorsementVerdict,
} from './types.js';
import path from 'node:path';
import fs from 'node:fs';

const VERSION = '0.9.0';

export function printHelp(): void {
  console.log(`
Evidence MCP (v${VERSION})
Verifiable evidence collection and validation MCP server for AI coding agents.

Usage:
  evidence-mcp                                      Start the MCP server on stdio (default)
  evidence-mcp list [workspacePath]                 List all evidence bundles in workspace
  evidence-mcp verify <bundleId> [options]          Verify an evidence bundle against disk & Git
  evidence-mcp report <bundleId> [options]          Export an evidence report (markdown|json|html)
  evidence-mcp sign <bundleId> [options]            Sign a bundle using an Ed25519 keypair
  evidence-mcp exec <bundleId> <cmd> [args...]      Execute an approved command in sandboxed runner
  evidence-mcp workspace add <bundleId> <name> <p>  Register a package or sub-workspace in bundle
  evidence-mcp workspace list <bundleId>            List all workspaces registered in bundle
  evidence-mcp ast <bundleId> <files...> [options]  Capture AST symbols and semantic diff for files
  evidence-mcp proof create <bundleId> [options]    Export a signed Ed25519 verification proof
  evidence-mcp proof verify <file|id> [options]     Verify cryptographic proof authenticity & digest
  evidence-mcp replay <bundleId> [options]          Replay evidence sequentially with reproducibility check
  evidence-mcp endorse <bundleId> [options]         Append a signed peer review endorsement to a bundle
  evidence-mcp quorum <bundleId> [options]          Check multi-agent consensus quorum compliance
  evidence-mcp summary <bundleId> [options]         Generate GitHub Actions step summary markdown
  evidence-mcp policy <bundleId> [options]          Evaluate bundle compliance against evidence.policy.json
  evidence-mcp webhook <bundleId> <url> [options]   Dispatch signed audit payload to a webhook URL
  evidence-mcp --help, -h                           Show this help message
  evidence-mcp --version, -v                        Show version number

Options:
  --workspace, -w <path>   Workspace directory path (defaults to current working directory)
  --format, -f <format>    Report format: markdown, json, or html (default: markdown)
  --output, -o <file>      Write exported report, proof, or summary directly to file
  --key, -k <file>         Private key file for Ed25519 signing (auto-generates if omitted)
  --timeout <ms>           Execution timeout in milliseconds (default: 30000)
  --cwd <path>             Working directory relative to workspace root
  --no-diff                Do not compute semantic diff against Git HEAD
  --re-execute             Re-execute server commands during replay to verify reproducibility
  --agent <id>             Agent identifier for endorsement (e.g. "agent:tester-v1")
  --role <role>            Reviewer role: tester, security_auditor, architect, peer_reviewer
  --verdict <verdict>      Endorsement verdict: approved, rejected, changes_requested
  --comment <text>         Review commentary text
  --min <count>            Minimum approved endorsements required for quorum (default: 1)
  --roles <roles...>       Comma-separated list of required endorsement roles
  --policy, -p <file>      Path to evidence.policy.json file
  --strict                 Enforce strict policy compliance (fail on warnings)
  --secret, -s <token>     Secret key for HMAC-SHA256 webhook signature
  --proof                  Include signed verification proof in webhook audit payload
  --github                 Automatically append markdown to GITHUB_STEP_SUMMARY
`);
}

/**
 * Handles the CLI execution. Returns an exit code:
 * 0 = success / verified
 * 1 = error / verification failed / stale / unverifiable
 */
export async function runCli(args: string[]): Promise<number> {
  if (args.length === 0 || args[0] === '--stdio') {
    const server = createEvidenceServer();
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error('[Evidence-MCP] Server running on stdio');
    return 0;
  }

  const firstArg = args[0];

  if (firstArg === '--help' || firstArg === '-h' || firstArg === 'help') {
    printHelp();
    return 0;
  }

  if (firstArg === '--version' || firstArg === '-v' || firstArg === 'version') {
    console.log(`evidence-mcp v${VERSION}`);
    return 0;
  }

  // 1. Command: list [workspacePath]
  if (firstArg === 'list') {
    let workspace = process.cwd();
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--workspace' || args[i] === '-w') {
        workspace = args[++i] || workspace;
      } else if (!args[i].startsWith('-')) {
        workspace = args[i];
      }
    }

    const resolvedWorkspace = path.resolve(workspace);
    const bundles = await listBundles(resolvedWorkspace);

    console.log(`\nEvidence Bundles in ${resolvedWorkspace}:`);
    if (bundles.length === 0) {
      console.log('No evidence bundles found under .evidence-mcp/bundles/\n');
      return 0;
    }

    console.log('--------------------------------------------------------------------------------');
    console.log(`${'ID'.padEnd(20)} ${'STATUS'.padEnd(14)} ${'CREATED'.padEnd(20)} TASK`);
    console.log('--------------------------------------------------------------------------------');
    for (const b of bundles) {
      const created = b.createdAt ? b.createdAt.slice(0, 19).replace('T', ' ') : 'unknown';
      console.log(`${b.id.padEnd(20)} ${b.status.padEnd(14)} ${created.padEnd(20)} ${b.task}`);
    }
    console.log('--------------------------------------------------------------------------------');
    console.log(`Total: ${bundles.length} bundle(s)\n`);
    return 0;
  }

  // 2. Command: verify <bundleId>
  if (firstArg === 'verify') {
    const bundleId = args[1];
    if (!bundleId || bundleId.startsWith('-')) {
      console.error('Error: bundleId is required for verify command.\nUsage: evidence-mcp verify <bundleId>');
      return 1;
    }

    let workspace: string | undefined;
    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const result = await verifyEvidenceBundle(bundle);

      console.log(`\nEvidence Verification: ${result.bundleId}`);
      console.log('================================================================================');
      console.log(`Task:      ${bundle.task}`);
      console.log(`Workspace: ${bundle.workspacePath}`);
      console.log(`Verdict:   ${result.status.toUpperCase()}`);
      console.log(`Summary:   ${result.summary}`);
      console.log('--------------------------------------------------------------------------------');

      if (result.items.length > 0) {
        console.log('Itemized Verification:');
        for (const item of result.items) {
          const badge =
            item.status === 'verified'
              ? '[PASS]'
              : item.status === 'stale'
              ? '[STALE]'
              : item.status === 'unverifiable'
              ? '[UNVERIFIED]'
              : '[FAIL]';
          console.log(`  ${badge.padEnd(14)} (${item.type}) ${item.details}`);
        }
      }

      if (result.reasons.length > 0) {
        console.log('--------------------------------------------------------------------------------');
        console.log('Findings & Issues:');
        for (const reason of result.reasons) {
          console.log(`  ⚠️  ${reason}`);
        }
      }
      console.log('================================================================================\n');

      return result.status === 'verified' ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Verification error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 3. Command: report <bundleId>
  if (firstArg === 'report') {
    const bundleId = args[1];
    if (!bundleId || bundleId.startsWith('-')) {
      console.error('Error: bundleId is required for report command.\nUsage: evidence-mcp report <bundleId> [--format markdown|json|html]');
      return 1;
    }

    let format: 'markdown' | 'json' | 'html' = 'markdown';
    let outputPath: string | undefined;
    let workspace: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--format' || args[i] === '-f') && args[i + 1]) {
        const fmt = args[++i].toLowerCase();
        if (fmt === 'markdown' || fmt === 'json' || fmt === 'html') {
          format = fmt;
        } else {
          console.error(`Invalid format "${fmt}". Allowed formats: markdown, json, html.`);
          return 1;
        }
      } else if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
        outputPath = args[++i];
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const verification = await verifyEvidenceBundle(bundle);
      const report = exportEvidenceReport(bundle, format, verification);

      if (outputPath) {
        const resolvedOutput = path.resolve(outputPath);
        await fs.promises.mkdir(path.dirname(resolvedOutput), { recursive: true });
        await fs.promises.writeFile(resolvedOutput, report, 'utf8');
        console.log(`Report successfully exported to: ${resolvedOutput}`);
      } else {
        console.log(report);
      }
      return 0;
    } catch (err: unknown) {
      console.error(`Report generation error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 4. Command: sign <bundleId>
  if (firstArg === 'sign') {
    const bundleId = args[1];
    if (!bundleId || bundleId.startsWith('-')) {
      console.error('Error: bundleId is required for sign command.\nUsage: evidence-mcp sign <bundleId> [--key <pemFile>]');
      return 1;
    }

    let keyFilePath: string | undefined;
    let workspace: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--key' || args[i] === '-k') && args[i + 1]) {
        keyFilePath = args[++i];
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      let privateKeyPem: string | undefined;
      if (keyFilePath) {
        privateKeyPem = await fs.promises.readFile(path.resolve(keyFilePath), 'utf8');
      }

      const attestation = await signEvidenceBundle(bundle, privateKeyPem);
      await saveBundle(bundle);

      console.log(`\nEvidence Bundle Cryptographically Signed: ${bundle.id}`);
      console.log('================================================================================');
      console.log(`Algorithm:       ${attestation.algorithm.toUpperCase()}`);
      console.log(`Key Fingerprint: ${attestation.keyFingerprint}`);
      console.log(`Signed At:       ${attestation.signedAt}`);
      console.log('================================================================================\n');
      return 0;
    } catch (err: unknown) {
      console.error(`Signing error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 5. Command: exec <bundleId> <cmd> [args...]
  if (firstArg === 'exec') {
    const bundleId = args[1];
    const command = args[2];
    if (!bundleId || bundleId.startsWith('-') || !command || command.startsWith('-')) {
      console.error(
        'Error: bundleId and command are required for exec command.\nUsage: evidence-mcp exec <bundleId> <command> [args...] [--timeout <ms>] [--cwd <path>]'
      );
      return 1;
    }

    const commandArgs: string[] = [];
    let workspace: string | undefined;
    let cwd: string | undefined;
    let timeoutMs: number | undefined;

    for (let i = 3; i < args.length; i++) {
      if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      } else if (args[i] === '--cwd' && args[i + 1]) {
        cwd = args[++i];
      } else if (args[i] === '--timeout' && args[i + 1]) {
        timeoutMs = parseInt(args[++i], 10);
      } else {
        commandArgs.push(args[i]);
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const effectiveWorkspace = workspace || bundle.workspacePath;

      const result = await executeSandboxedCommand({
        command,
        args: commandArgs,
        cwd,
        timeoutMs,
        workspacePath: effectiveWorkspace,
      });

      const commandEvidence: CommandEvidence = {
        id: generateId('cmd'),
        type: 'command',
        recordedAt: result.executedAt,
        command: result.command,
        args: result.args,
        exitCode: result.exitCode,
        stdout: result.stdout,
        stderr: result.stderr,
        durationMs: result.durationMs,
        executedAt: result.executedAt,
        timedOut: result.timedOut,
        provenance: 'server_executed',
      };

      if (!bundle.evidence.commands) {
        bundle.evidence.commands = [];
      }
      bundle.evidence.commands.push(commandEvidence);
      bundle.updatedAt = new Date().toISOString();
      await saveBundle(bundle);

      if (result.stdout) {
        process.stdout.write(result.stdout);
        if (!result.stdout.endsWith('\n')) process.stdout.write('\n');
      }
      if (result.stderr) {
        process.stderr.write(result.stderr);
        if (!result.stderr.endsWith('\n')) process.stderr.write('\n');
      }

      console.error(`\n[Evidence MCP] Command executed and recorded: ${commandEvidence.id} (Exit ${result.exitCode}, ${result.durationMs}ms)`);
      return result.exitCode === 0 ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Execution error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 6. Command: workspace add|list
  if (firstArg === 'workspace') {
    const subAction = args[1];
    if (subAction === 'add') {
      const bundleId = args[2];
      const wsName = args[3];
      const wsPath = args[4];
      if (!bundleId || !wsName || !wsPath) {
        console.error(
          'Error: bundleId, workspace name, and path are required.\nUsage: evidence-mcp workspace add <bundleId> <name> <path>'
        );
        return 1;
      }
      try {
        const bundle = await loadBundle(bundleId);
        const resolvedPath = path.resolve(bundle.workspacePath, wsPath);
        if (!bundle.workspaces) {
          bundle.workspaces = { root: bundle.workspacePath };
        }
        bundle.workspaces[wsName] = resolvedPath;
        bundle.updatedAt = new Date().toISOString();
        await saveBundle(bundle);
        console.log(`Workspace "${wsName}" registered successfully: ${resolvedPath}`);
        return 0;
      } catch (err: unknown) {
        console.error(`Workspace error: ${(err as Error).message}`);
        return 1;
      }
    } else if (subAction === 'list') {
      const bundleId = args[2];
      if (!bundleId) {
        console.error('Error: bundleId is required.\nUsage: evidence-mcp workspace list <bundleId>');
        return 1;
      }
      try {
        const bundle = await loadBundle(bundleId);
        console.log(`\nRegistered Workspaces for Bundle: ${bundle.id}`);
        console.log('================================================================================');
        console.log(`root (default):  ${bundle.workspacePath}`);
        if (bundle.workspaces) {
          for (const [name, p] of Object.entries(bundle.workspaces)) {
            if (name !== 'root') {
              console.log(`${name.padEnd(16)} ${p}`);
            }
          }
        }
        console.log('================================================================================\n');
        return 0;
      } catch (err: unknown) {
        console.error(`Workspace error: ${(err as Error).message}`);
        return 1;
      }
    }
  }

  // 7. Command: ast <bundleId> <files...> [options]
  if (firstArg === 'ast') {
    const bundleId = args[1];
    if (!bundleId) {
      console.error('Error: bundleId is required.\nUsage: evidence-mcp ast <bundleId> <files...> [options]');
      return 1;
    }

    const rawFiles: string[] = [];
    let workspacePath: string | undefined;
    let workspaceName: string | undefined;
    let compareWithGitHead = true;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspacePath = args[++i];
      } else if ((args[i] === '--package' || args[i] === '--pkg') && args[i + 1]) {
        workspaceName = args[++i];
      } else if (args[i] === '--no-diff') {
        compareWithGitHead = false;
      } else if (!args[i].startsWith('-')) {
        rawFiles.push(args[i]);
      }
    }

    if (rawFiles.length === 0) {
      console.error('Error: At least one file path must be provided.');
      return 1;
    }

    try {
      const bundle = await loadBundle(bundleId, workspacePath);
      const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);

      if (!bundle.evidence.ast) {
        bundle.evidence.ast = [];
      }

      console.log(`Analyzing AST & semantic diff for ${rawFiles.length} file(s)...`);

      for (const f of rawFiles) {
        const astEv = await captureFileAstEvidence({
          filePath: f,
          workspacePath: targetWs,
          workspaceName,
          compareWithGitHead,
        });

        bundle.evidence.ast.push(astEv);

        const wsLabel = astEv.workspaceName ? ` [${astEv.workspaceName}]` : '';
        console.log(`\n  File: ${astEv.filePath}${wsLabel} (${astEv.language}, ${astEv.symbolsCount} symbols)`);
        if (astEv.diff) {
          if (astEv.diff.hasChanges) {
            const changeBadge = astEv.diff.isBreakingChange ? ' [BREAKING CHANGE]' : '';
            console.log(`  Semantic Changes Detected${changeBadge}:`);
            if (astEv.diff.addedSymbols.length > 0) {
              console.log(
                `    + Added: ${astEv.diff.addedSymbols.map((s) => `${s.kind} ${s.name}`).join(', ')}`
              );
            }
            if (astEv.diff.removedSymbols.length > 0) {
              console.log(
                `    - Removed: ${astEv.diff.removedSymbols.map((s) => `${s.kind} ${s.name}`).join(', ')}`
              );
            }
            if (astEv.diff.modifiedSymbols.length > 0) {
              console.log(
                `    ~ Modified: ${astEv.diff.modifiedSymbols
                  .map((m) => `${m.symbol.kind} ${m.symbol.name} (${m.changes.join('; ')})`)
                  .join(', ')}`
              );
            }
          } else {
            console.log('  No semantic changes compared to Git HEAD.');
          }
        }
      }

      bundle.updatedAt = new Date().toISOString();
      await saveBundle(bundle);
      console.log(`\nAST evidence successfully captured and saved to bundle: ${bundle.id}`);
      return 0;
    } catch (err: unknown) {
      console.error(`AST analysis error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 8. Command: proof create|verify
  if (firstArg === 'proof') {
    const subAction = args[1];
    if (subAction === 'create') {
      const bundleId = args[2];
      if (!bundleId) {
        console.error('Error: bundleId is required.\nUsage: evidence-mcp proof create <bundleId> [options]');
        return 1;
      }

      let workspace: string | undefined;
      let keyFile: string | undefined;
      let outputFile: string | undefined;

      for (let i = 3; i < args.length; i++) {
        if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
          workspace = args[++i];
        } else if ((args[i] === '--key' || args[i] === '-k') && args[i + 1]) {
          keyFile = args[++i];
        } else if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
          outputFile = args[++i];
        }
      }

      try {
        const bundle = await loadBundle(bundleId, workspace);
        let privateKeyPem: string | undefined;
        if (keyFile) {
          privateKeyPem = await fs.promises.readFile(path.resolve(keyFile), 'utf8');
        }

        const verification = await verifyEvidenceBundle(bundle);
        const proof = await createVerificationProof({
          bundle,
          verification,
          workspacePath: bundle.workspacePath,
          privateKeyPem,
        });

        console.log(`\nVerification Proof Created: ${proof.id}`);
        console.log('================================================================================');
        console.log(`Bundle ID:     ${proof.bundleId}`);
        console.log(`Verdict:       ${proof.verdict.toUpperCase()}`);
        console.log(`Bundle Digest: ${proof.bundleDigest}`);
        console.log(`Signer:        ${proof.signer.keyFingerprint}`);
        console.log(`Verified At:   ${proof.verifiedAt}`);
        console.log(`Items Checked: ${proof.itemCount}`);
        console.log('================================================================================\n');

        if (outputFile) {
          const outPath = path.resolve(outputFile);
          await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
          await fs.promises.writeFile(outPath, JSON.stringify(proof, null, 2), 'utf8');
          console.log(`Proof written to: ${outPath}`);
        }

        return proof.verdict === 'verified' ? 0 : 1;
      } catch (err: unknown) {
        console.error(`Proof error: ${(err as Error).message}`);
        return 1;
      }
    } else if (subAction === 'verify') {
      const proofTarget = args[2];
      if (!proofTarget) {
        console.error('Error: proof target is required.\nUsage: evidence-mcp proof verify <proofFile|proofId> [options]');
        return 1;
      }

      let workspace: string | undefined;
      let bundleId: string | undefined;

      for (let i = 3; i < args.length; i++) {
        if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
          workspace = args[++i];
        } else if (args[i] === '--bundle' && args[i + 1]) {
          bundleId = args[++i];
        }
      }

      try {
        let proof: VerificationProof;
        if (fs.existsSync(proofTarget)) {
          const content = await fs.promises.readFile(path.resolve(proofTarget), 'utf8');
          proof = JSON.parse(content) as VerificationProof;
        } else {
          proof = await loadProof(proofTarget, workspace);
        }

        const targetBundleId = bundleId || proof.bundleId;
        let bundle: EvidenceBundle | undefined;
        try {
          bundle = await loadBundle(targetBundleId, workspace);
        } catch {
          // Offline verification without live bundle
        }

        const check = verifyProofSignature(proof, bundle);

        console.log(`\nVerification Proof Inspection: ${proof.id}`);
        console.log('================================================================================');
        console.log(`Valid Signature: ${check.valid ? 'YES' : 'NO'}`);
        console.log(`Verdict:         ${proof.verdict.toUpperCase()}`);
        console.log(`Signer:          ${proof.signer.keyFingerprint}`);
        console.log(`Verified At:     ${proof.verifiedAt}`);
        if (check.bundleDigestMatches !== undefined) {
          console.log(`Bundle Matches:  ${check.bundleDigestMatches ? 'YES (Untampered)' : 'NO (Tampered)'}`);
        }
        if (check.reason) {
          console.log(`Reason:          ${check.reason}`);
        }
        console.log('================================================================================\n');

        return check.valid && check.bundleDigestMatches !== false ? 0 : 1;
      } catch (err: unknown) {
        console.error(`Proof verification error: ${(err as Error).message}`);
        return 1;
      }
    }
  }

  // 9. Command: replay <bundleId> [--re-execute] [--workspace <path>]
  if (firstArg === 'replay') {
    const bundleId = args[1];
    if (!bundleId) {
      console.error('Error: bundleId is required.\nUsage: evidence-mcp replay <bundleId> [options]');
      return 1;
    }

    let workspace: string | undefined;
    let reExecuteCommands = false;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      } else if (args[i] === '--re-execute') {
        reExecuteCommands = true;
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      console.log(`\nReplaying Evidence for Bundle: ${bundle.id}`);
      console.log(`Task: ${bundle.task}`);
      console.log('================================================================================');

      const replayResult = await replayEvidenceBundle(bundle, {
        reExecuteCommands,
        workspacePath: workspace,
      });

      for (const step of replayResult.steps) {
        const badge = step.status === 'passed' ? '[PASS]' : step.status === 'diverged' ? '[DIVERGED]' : '[FAIL]';
        console.log(`${step.index.toString().padStart(2)}. ${badge.padEnd(11)} ${step.description}`);
        console.log(`    ${step.details}`);
        if (step.reproducedExecution) {
          console.log(`    Reproduced in ${step.reproducedExecution.durationMs}ms (Exit: ${step.reproducedExecution.exitCode})`);
        }
      }

      console.log('--------------------------------------------------------------------------------');
      console.log(
        `Replay Summary: ${replayResult.passedSteps}/${replayResult.totalSteps} passed (${replayResult.divergedSteps} diverged).`
      );
      console.log(`Reproducibility: ${replayResult.isReproducible ? 'REPRODUCIBLE' : 'DIVERGED'}`);
      console.log('================================================================================\n');

      return replayResult.isReproducible ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Replay error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 10. Command: endorse <bundleId> [options]
  if (firstArg === 'endorse') {
    const bundleId = args[1];
    if (!bundleId) {
      console.error('Error: bundleId is required.\nUsage: evidence-mcp endorse <bundleId> [options]');
      return 1;
    }

    let agentId: string | undefined;
    let role: PeerEndorsementRole = 'peer_reviewer';
    let verdict: PeerEndorsementVerdict = 'approved';
    let comment = 'LGTM: Verified independently.';
    let keyFile: string | undefined;
    let workspace: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if (args[i] === '--agent' && args[i + 1]) {
        agentId = args[++i];
      } else if (args[i] === '--role' && args[i + 1]) {
        role = args[++i] as PeerEndorsementRole;
      } else if (args[i] === '--verdict' && args[i + 1]) {
        verdict = args[++i] as PeerEndorsementVerdict;
      } else if (args[i] === '--comment' && args[i + 1]) {
        comment = args[++i];
      } else if ((args[i] === '--key' || args[i] === '-k') && args[i + 1]) {
        keyFile = args[++i];
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    if (!agentId) {
      console.error('Error: --agent <id> is required for endorse command.');
      return 1;
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      let privateKeyPem: string | undefined;
      if (keyFile) {
        privateKeyPem = await fs.promises.readFile(path.resolve(keyFile), 'utf8');
      }

      const endorsement = await createPeerEndorsement({
        bundle,
        agentId,
        role,
        verdict,
        comment,
        privateKeyPem,
        workspacePath: bundle.workspacePath,
      });

      console.log(`\nPeer Endorsement Recorded: ${endorsement.id}`);
      console.log('================================================================================');
      console.log(`Bundle ID:     ${bundle.id}`);
      console.log(`Reviewer:      ${endorsement.agentId} (${endorsement.role})`);
      console.log(`Verdict:       ${endorsement.verdict.toUpperCase()}`);
      console.log(`Signer Key:    ${endorsement.signer.keyFingerprint}`);
      console.log(`Comment:       ${endorsement.comment}`);
      console.log(`Timestamp:     ${endorsement.timestamp}`);
      console.log('================================================================================\n');

      return 0;
    } catch (err: unknown) {
      console.error(`Endorsement error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 11. Command: quorum <bundleId> [options]
  if (firstArg === 'quorum') {
    const bundleId = args[1];
    if (!bundleId) {
      console.error('Error: bundleId is required.\nUsage: evidence-mcp quorum <bundleId> [options]');
      return 1;
    }

    let minEndorsements = 1;
    let requiredRoles: PeerEndorsementRole[] = [];
    let workspace: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if (args[i] === '--min' && args[i + 1]) {
        minEndorsements = parseInt(args[++i], 10);
      } else if (args[i] === '--roles' && args[i + 1]) {
        requiredRoles = args[++i].split(',').map((r) => r.trim() as PeerEndorsementRole);
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const quorumResult = checkBundleQuorum(bundle, {
        minEndorsements,
        requiredRoles: requiredRoles.length > 0 ? requiredRoles : undefined,
      });

      console.log(`\nConsensus Quorum Check: ${bundle.id}`);
      console.log('================================================================================');
      console.log(`Quorum Satisfied: ${quorumResult.satisfied ? 'YES (PASSED)' : 'NO (NOT MET)'}`);
      console.log(
        `Approvals:        ${quorumResult.approvedCount}/${quorumResult.policy.minEndorsements || 1} required`
      );
      console.log(`Rejections:       ${quorumResult.rejectionsCount}`);
      console.log(`Total Reviews:    ${quorumResult.totalEndorsements}`);
      console.log(`Valid Signatures: ${quorumResult.verifiedSignatures}`);
      if (quorumResult.reasons.length > 0) {
        console.log('Findings / Violations:');
        for (const r of quorumResult.reasons) {
          console.log(`  - ${r}`);
        }
      }
      console.log('================================================================================\n');

      return quorumResult.satisfied ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Quorum error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 12. Command: summary <bundleId> [options]
  if (firstArg === 'summary') {
    const bundleId = args[1];
    if (!bundleId) {
      console.error('Error: bundleId is required.\nUsage: evidence-mcp summary <bundleId> [options]');
      return 1;
    }

    let workspace: string | undefined;
    let outputFile: string | undefined;
    let writeGitHub = false;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      } else if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
        outputFile = args[++i];
      } else if (args[i] === '--github') {
        writeGitHub = true;
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const verification = await verifyEvidenceBundle(bundle);
      const quorum = checkBundleQuorum(bundle);

      const summaryMarkdown = generateGitHubStepSummary({
        bundle,
        verification,
        quorum,
      });

      if (outputFile) {
        const outPath = path.resolve(outputFile);
        await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
        await fs.promises.writeFile(outPath, summaryMarkdown, 'utf8');
        console.log(`Step summary written to: ${outPath}`);
      }

      if (writeGitHub) {
        const wrote = await writeToGitHubStepSummary(summaryMarkdown);
        if (wrote) {
          console.log(`Summary successfully appended to $GITHUB_STEP_SUMMARY`);
        } else {
          console.warn(`GITHUB_STEP_SUMMARY environment variable not set; printed to stdout instead.`);
          console.log(summaryMarkdown);
        }
      } else if (!outputFile) {
        console.log(summaryMarkdown);
      }

      return 0;
    } catch (err: unknown) {
      console.error(`Summary error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 13. policy <bundleId> [options]
  if (firstArg === 'policy') {
    const bundleId = args[1];
    if (!bundleId || bundleId.startsWith('-')) {
      console.error('Error: bundleId is required for "policy" command.');
      console.error('Usage: evidence-mcp policy <bundleId> [--policy <file>] [--strict] [--workspace <path>]');
      return 1;
    }

    let policyPath: string | undefined;
    let strict = false;
    let workspace: string | undefined;
    let outputFile: string | undefined;

    for (let i = 2; i < args.length; i++) {
      if ((args[i] === '--policy' || args[i] === '-p') && args[i + 1]) {
        policyPath = args[++i];
      } else if (args[i] === '--strict') {
        strict = true;
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      } else if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
        outputFile = args[++i];
      }
    }

    try {
      const bundle = await loadBundle(bundleId, workspace);
      const loaded = await loadPolicyFile(policyPath, bundle.workspacePath);
      if (!loaded) {
        console.error(`Error: Policy file not found. Create "evidence.policy.json" in workspace root or specify with --policy.`);
        return 1;
      }

      let verificationResult;
      try {
        verificationResult = await verifyEvidenceBundle(bundle);
      } catch {
        // Proceed even if verification fails
      }

      const evaluation = evaluateEvidencePolicy({
        bundle,
        policy: loaded.policy,
        strict,
        verificationResult,
      });

      console.log(`\nPolicy Compliance Evaluation: ${bundle.id}`);
      console.log(`Policy Source: ${loaded.sourcePath}`);
      console.log(`Status:        ${evaluation.passed ? 'PASSED (COMPLIANT)' : 'FAILED (NON-COMPLIANT)'}`);
      console.log('='.repeat(80));

      for (const evalItem of evaluation.evaluations) {
        const statusBadge = evalItem.passed
          ? '[PASS]'
          : evalItem.severity === 'error'
          ? '[FAIL]'
          : '[WARN]';
        console.log(` ${statusBadge.padEnd(8)} ${evalItem.rule.padEnd(35)} ${evalItem.message}`);
      }

      console.log('='.repeat(80));
      console.log(`Summary: ${evaluation.policySummary}\n`);

      if (outputFile) {
        const outPath = path.resolve(outputFile);
        await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
        await fs.promises.writeFile(outPath, JSON.stringify(evaluation, null, 2), 'utf8');
        console.log(`Evaluation results written to: ${outPath}`);
      }

      return evaluation.passed ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Policy evaluation error: ${(err as Error).message}`);
      return 1;
    }
  }

  // 14. webhook <bundleId> <url> [options]
  if (firstArg === 'webhook') {
    const bundleId = args[1];
    const webhookUrl = args[2];
    if (!bundleId || !webhookUrl || bundleId.startsWith('-') || webhookUrl.startsWith('-')) {
      console.error('Error: bundleId and webhookUrl are required for "webhook" command.');
      console.error('Usage: evidence-mcp webhook <bundleId> <url> [--secret <token>] [--proof] [--timeout <ms>]');
      return 1;
    }

    let secretToken: string | undefined;
    let includeProof = false;
    let timeoutMs = 10000;
    let workspace: string | undefined;

    for (let i = 3; i < args.length; i++) {
      if ((args[i] === '--secret' || args[i] === '-s') && args[i + 1]) {
        secretToken = args[++i];
      } else if (args[i] === '--proof') {
        includeProof = true;
      } else if (args[i] === '--timeout' && args[i + 1]) {
        timeoutMs = parseInt(args[++i], 10) || 10000;
      } else if ((args[i] === '--workspace' || args[i] === '-w') && args[i + 1]) {
        workspace = args[++i];
      }
    }

    try {
      const result = await dispatchAuditWebhook({
        bundleId,
        webhookUrl,
        secretToken,
        includeProof,
        timeoutMs,
        workspacePath: workspace,
      });

      console.log(`\nWebhook Audit Dispatch: ${bundleId}`);
      console.log('='.repeat(80));
      console.log(`Target URL:    ${result.webhookUrl}`);
      console.log(`Delivery:      ${result.delivered ? 'DELIVERED (SUCCESS)' : 'FAILED'}`);
      if (result.statusCode) {
        console.log(`HTTP Status:   ${result.statusCode} ${result.statusText || ''}`);
      }
      console.log(`Duration:      ${result.durationMs}ms`);
      if (result.signatureHeader) {
        console.log(`Signature:     ${result.signatureHeader}`);
      }
      if (result.error) {
        console.log(`Error:         ${result.error}`);
      }
      if (result.responseBody) {
        console.log(`Response:      ${result.responseBody.trim()}`);
      }
      console.log('='.repeat(80) + '\n');

      return result.delivered ? 0 : 1;
    } catch (err: unknown) {
      console.error(`Webhook error: ${(err as Error).message}`);
      return 1;
    }
  }

  console.error(`Unknown command: "${firstArg}". Run "evidence-mcp --help" for available commands.`);
  return 1;
}

// Execute CLI when invoked directly
const isDirectExecution =
  process.argv[1] &&
  (process.argv[1].endsWith('cli.js') ||
    process.argv[1].endsWith('cli.ts') ||
    process.argv[1].includes('evidence-mcp'));

if (isDirectExecution) {
  runCli(process.argv.slice(2))
    .then((code) => {
      if (code !== 0) {
        process.exitCode = code;
      }
    })
    .catch((err: unknown) => {
      console.error('[Evidence-MCP] Fatal error:', err);
      process.exit(1);
    });
}
