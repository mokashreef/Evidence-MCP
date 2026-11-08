#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createEvidenceServer } from './server.js';
import { listBundles, loadBundle, saveBundle, generateId } from './storage.js';
import { verifyEvidenceBundle } from './verifier.js';
import { exportEvidenceReport } from './reporter.js';
import { signEvidenceBundle } from './attestation.js';
import { executeSandboxedCommand } from './runner.js';
import { CommandEvidence } from './types.js';
import path from 'node:path';
import fs from 'node:fs';

const VERSION = '0.4.0';

export function printHelp(): void {
  console.log(`
Evidence MCP (v${VERSION})
Verifiable evidence collection and validation MCP server for AI coding agents.

Usage:
  evidence-mcp                                  Start the MCP server on stdio (default)
  evidence-mcp list [workspacePath]             List all evidence bundles in workspace
  evidence-mcp verify <bundleId> [options]      Verify an evidence bundle against disk & Git
  evidence-mcp report <bundleId> [options]      Export an evidence report (markdown|json|html)
  evidence-mcp sign <bundleId> [options]        Sign a bundle using an Ed25519 keypair
  evidence-mcp exec <bundleId> <cmd> [args...]  Execute an approved command in sandboxed runner
  evidence-mcp --help, -h                       Show this help message
  evidence-mcp --version, -v                    Show version number

Options:
  --workspace, -w <path>   Workspace directory path (defaults to current working directory)
  --format, -f <format>    Report format: markdown, json, or html (default: markdown)
  --output, -o <file>      Write exported report directly to file
  --key, -k <file>         Private key file for Ed25519 signing (auto-generates if omitted)
  --timeout <ms>           Execution timeout in milliseconds (default: 30000)
  --cwd <path>             Working directory relative to workspace root
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
