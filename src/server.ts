import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  Assertion,
  CommandEvidence,
  EvidenceBundle,
  FileSnapshotEvidence,
  GitEvidence,
  AstEvidence,
} from './types.js';
import { validateWorkspacePath, assertSafeFilePath, writeWorkspaceOutputFile } from './security.js';
import { computeFileSha256AndSize } from './hasher.js';
import { captureGitState } from './git.js';
import {
  generateId,
  saveBundle,
  loadBundle,
  loadProof,
  registerBundleWorkspace,
  resolveWorkspaceForBundle,
} from './storage.js';
import { verifyEvidenceBundle } from './verifier.js';
import { exportEvidenceReport } from './reporter.js';
import { signEvidenceBundle } from './attestation.js';
import { executeSandboxedCommand } from './runner.js';
import { captureFileAstEvidence } from './ast.js';
import { createVerificationProof, verifyProofSignature } from './proof.js';
import { createPeerEndorsement, checkBundleQuorum } from './consensus.js';
import { evaluateEvidencePolicy, loadPolicyFile } from './policy.js';
import { dispatchAuditWebhook } from './webhook.js';
import { registerTrustedAgent, revokeTrustedAgent, listTrustedAgents } from './registry.js';
import { captureWorkspaceSbom } from './sbom.js';
import { notarizeEvidenceBundle } from './notary.js';
import { generateSlsaProvenance } from './slsa.js';
import { EvidencePolicy } from './types.js';

export function createEvidenceServer(): McpServer {
  const server = new McpServer({
    name: 'evidence-mcp',
    version: '1.4.0',
  });

  // 1. create_evidence_bundle
  server.tool(
    'create_evidence_bundle',
    'Creates a new evidence bundle for a task and primary workspace (with optional additional monorepo packages) with in_progress status.',
    {
      task: z.string().min(1).describe('The task or objective being addressed by the agent.'),
      workspacePath: z.string().min(1).describe('Path to the primary workspace root directory.'),
      metadata: z.record(z.string(), z.unknown()).optional().describe('Optional key-value metadata.'),
      additionalWorkspaces: z
        .record(z.string(), z.string())
        .optional()
        .describe('Optional map of named additional workspaces/packages (e.g. { "frontend": "./packages/frontend" }).'),
    },
    async ({ task, workspacePath, metadata, additionalWorkspaces }) => {
      try {
        const resolvedWorkspace = validateWorkspacePath(workspacePath);
        const bundleId = generateId('bundle');
        const now = new Date().toISOString();

        const workspacesMap: Record<string, string> = {
          root: resolvedWorkspace,
        };

        if (additionalWorkspaces) {
          for (const [name, wsPath] of Object.entries(additionalWorkspaces)) {
            if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
              throw new Error(`Invalid workspace name "${name}": must be alphanumeric, hyphens, or underscores.`);
            }
            const resolvedSubWs = validateWorkspacePath(path.resolve(resolvedWorkspace, wsPath));
            workspacesMap[name] = resolvedSubWs;
          }
        }

        const bundle: EvidenceBundle = {
          id: bundleId,
          task,
          workspacePath: resolvedWorkspace,
          workspaces: workspacesMap,
          status: 'in_progress',
          createdAt: now,
          updatedAt: now,
          metadata: metadata || {},
          evidence: {
            git: [],
            commands: [],
            fileSnapshots: [],
          },
          assertions: [],
        };

        await saveBundle(bundle);
        registerBundleWorkspace(bundleId, resolvedWorkspace);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Evidence bundle created successfully.',
                  bundleId: bundle.id,
                  task: bundle.task,
                  status: bundle.status,
                  workspacePath: bundle.workspacePath,
                  workspaces: bundle.workspaces,
                  createdAt: bundle.createdAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to create evidence bundle: ${message}` }],
        };
      }
    }
  );

  // 2. capture_git_evidence
  server.tool(
    'capture_git_evidence',
    'Safely inspects and captures Git state (status, branch, HEAD commit, diff check) without mutating the repo.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      workspaceName: z.string().optional().describe('Optional registered workspace/package name (defaults to primary root).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint if running outside default cwd.'),
    },
    async ({ bundleId, workspaceName, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);
        const gitState = await captureGitState(targetWs);

        const gitEvidence: GitEvidence = {
          id: generateId('git'),
          type: 'git',
          capturedAt: new Date().toISOString(),
          branch: gitState.branch,
          headCommit: gitState.headCommit,
          statusShort: gitState.statusShort,
          diffCheck: gitState.diffCheck,
          isClean: gitState.isClean,
          ...(workspaceName ? { workspaceName } : {}),
        };

        if (!bundle.evidence.git) {
          bundle.evidence.git = [];
        }
        bundle.evidence.git.push(gitEvidence);
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Git evidence captured successfully.',
                  bundleId: bundle.id,
                  evidenceId: gitEvidence.id,
                  workspaceName: gitEvidence.workspaceName || 'root',
                  branch: gitEvidence.branch,
                  headCommit: gitEvidence.headCommit,
                  isClean: gitEvidence.isClean,
                  statusShort: gitEvidence.statusShort,
                  capturedAt: gitEvidence.capturedAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to capture Git evidence: ${message}` }],
        };
      }
    }
  );

  // 3. record_command_result
  server.tool(
    'record_command_result',
    'Records the self-reported execution result of a command supplied by the agent (provenance: agent_reported). Does not execute shell commands or independently verify command output.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      command: z.string().min(1).describe('The exact command string that was executed.'),
      exitCode: z.number().int().describe('The exit code returned by the command execution.'),
      stdout: z.string().describe('The standard output captured from the command.'),
      stderr: z.string().describe('The standard error captured from the command.'),
      workspaceName: z.string().optional().describe('Optional registered workspace/package name (defaults to primary root).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, command, exitCode, stdout, stderr, workspaceName, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);

        const cmdEvidence: CommandEvidence = {
          id: generateId('cmd'),
          type: 'command',
          recordedAt: new Date().toISOString(),
          command,
          exitCode,
          stdout,
          stderr,
          provenance: 'agent_reported',
          ...(workspaceName ? { workspaceName } : {}),
        };

        if (!bundle.evidence.commands) {
          bundle.evidence.commands = [];
        }
        bundle.evidence.commands.push(cmdEvidence);
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Command result recorded successfully (provenance: agent_reported).',
                  bundleId: bundle.id,
                  evidenceId: cmdEvidence.id,
                  provenance: cmdEvidence.provenance,
                  workspaceName: cmdEvidence.workspaceName || 'root',
                  command: cmdEvidence.command,
                  exitCode: cmdEvidence.exitCode,
                  recordedAt: cmdEvidence.recordedAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to record command result: ${message}` }],
        };
      }
    }
  );

  // 4. snapshot_files
  server.tool(
    'snapshot_files',
    'Computes SHA-256 hashes and file sizes for regular files strictly inside the workspace. Rejects sensitive files and symbolic links.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      paths: z.array(z.string().min(1)).min(1).describe('List of file paths relative to workspace root.'),
      workspaceName: z.string().optional().describe('Optional registered workspace/package name (defaults to primary root).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, paths, workspaceName, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);
        const snapshots: FileSnapshotEvidence[] = [];

        for (const filePath of paths) {
          const safePath = assertSafeFilePath(targetWs, filePath);
          const hashResult = await computeFileSha256AndSize(safePath.absolutePath);

          const snapshot: FileSnapshotEvidence = {
            id: generateId('file'),
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: safePath.relativePath,
            absolutePath: safePath.absolutePath,
            sha256: hashResult.sha256,
            sizeBytes: hashResult.sizeBytes,
            ...(workspaceName ? { workspaceName } : {}),
          };

          snapshots.push(snapshot);
        }

        if (!bundle.evidence.fileSnapshots) {
          bundle.evidence.fileSnapshots = [];
        }
        bundle.evidence.fileSnapshots.push(...snapshots);
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: `Successfully snapshotted ${snapshots.length} file(s).`,
                  bundleId: bundle.id,
                  snapshots: snapshots.map((s) => ({
                    evidenceId: s.id,
                    workspaceName: s.workspaceName || 'root',
                    path: s.path,
                    sha256: s.sha256,
                    sizeBytes: s.sizeBytes,
                  })),
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to snapshot files: ${message}` }],
        };
      }
    }
  );

  // 5. add_assertion
  server.tool(
    'add_assertion',
    'Links a stated claim to one or more supporting evidence IDs. Rejects assertions with zero evidence.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      claim: z.string().min(1).describe('The claim or statement being asserted.'),
      evidenceIds: z
        .array(z.string().min(1))
        .min(1, 'Assertion must reference at least one evidence ID.')
        .describe('Array of evidence IDs (git, cmd, file) that substantiate the claim.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, claim, evidenceIds, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);

        // Collect all available evidence IDs in the bundle
        const existingIds = new Set<string>();
        if (bundle.evidence.git) {
          bundle.evidence.git.forEach((g) => existingIds.add(g.id));
        }
        if (bundle.evidence.commands) {
          bundle.evidence.commands.forEach((c) => existingIds.add(c.id));
        }
        if (bundle.evidence.fileSnapshots) {
          bundle.evidence.fileSnapshots.forEach((f) => existingIds.add(f.id));
        }
        if (bundle.evidence.ast) {
          bundle.evidence.ast.forEach((a) => existingIds.add(a.id));
        }

        // Validate that all referenced evidenceIds exist
        const missingIds = evidenceIds.filter((id) => !existingIds.has(id));
        if (missingIds.length > 0) {
          throw new Error(
            `Cannot add assertion: Referenced evidence IDs do not exist in bundle: [${missingIds.join(', ')}]. Available IDs: [${Array.from(existingIds).join(', ')}]`
          );
        }

        const assertion: Assertion = {
          id: generateId('assert'),
          claim,
          evidenceIds,
          createdAt: new Date().toISOString(),
        };

        if (!bundle.assertions) {
          bundle.assertions = [];
        }
        bundle.assertions.push(assertion);
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Assertion added successfully.',
                  bundleId: bundle.id,
                  assertionId: assertion.id,
                  claim: assertion.claim,
                  evidenceIds: assertion.evidenceIds,
                  createdAt: assertion.createdAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to add assertion: ${message}` }],
        };
      }
    }
  );

  // 6. verify_evidence_bundle
  server.tool(
    'verify_evidence_bundle',
    'Re-checks Git state and file hashes against live workspace. Returns verified, stale, failed, or unverifiable status.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to verify.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const result = await verifyEvidenceBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to verify evidence bundle: ${message}` }],
        };
      }
    }
  );

  // 7. export_evidence_report
  server.tool(
    'export_evidence_report',
    'Produces an evidence report in Markdown, JSON, HTML, or SARIF v2.1.0 format with clear distinction between verified and agent-reported evidence.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to export.'),
      format: z
        .enum(['markdown', 'json', 'html', 'sarif'])
        .default('markdown')
        .describe('Output format: "markdown", "json", "html", or "sarif".'),
      policyPath: z
        .string()
        .optional()
        .describe('Optional path to evidence.policy.json to include policy violations in SARIF exports.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, format, policyPath, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const verification = await verifyEvidenceBundle(bundle);

        let policyEvaluation;
        if (format === 'sarif') {
          const loaded = await loadPolicyFile(policyPath, bundle.workspacePath);
          if (loaded) {
            policyEvaluation = evaluateEvidencePolicy({
              bundle,
              policy: loaded.policy,
              verificationResult: verification,
            });
          }
        }

        const report = exportEvidenceReport(
          bundle,
          format,
          verification,
          undefined,
          policyEvaluation
        );

        return {
          content: [
            {
              type: 'text',
              text: report,
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to export evidence report: ${message}` }],
        };
      }
    }
  );

  // 8. sign_evidence_bundle
  server.tool(
    'sign_evidence_bundle',
    'Cryptographically signs an evidence bundle using an Ed25519 keypair for author attestation and tamper detection.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to sign.'),
      privateKeyPem: z
        .string()
        .optional()
        .describe('Optional Ed25519 private key in PEM format (uses local agent key if omitted).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, privateKeyPem, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const attestation = await signEvidenceBundle(bundle, privateKeyPem);
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Evidence bundle cryptographically signed successfully.',
                  bundleId: bundle.id,
                  algorithm: attestation.algorithm,
                  keyFingerprint: attestation.keyFingerprint,
                  signedAt: attestation.signedAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to sign evidence bundle: ${message}` }],
        };
      }
    }
  );

  // 9. execute_verified_command
  server.tool(
    'execute_verified_command',
    'Executes an approved dev/test command in a sandboxed, isolated environment within the workspace and records independently verified execution evidence (provenance: server_executed).',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      command: z.string().min(1).describe('The executable command to run (e.g. "npm", "git", "node", "vitest").'),
      args: z.array(z.string()).default([]).describe('Arguments array passed directly to the command.'),
      cwd: z.string().optional().describe('Optional working directory relative to workspace root.'),
      timeoutMs: z.number().int().min(500).max(120000).optional().describe('Execution timeout in milliseconds (default 30000).'),
      env: z.record(z.string(), z.string()).optional().describe('Optional custom environment variables (sensitive tokens will be rejected).'),
      workspaceName: z.string().optional().describe('Optional registered workspace/package name (defaults to primary root).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, command, args, cwd, timeoutMs, env, workspaceName, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);
        const resolvedWorkspace = validateWorkspacePath(targetWs);

        const executionResult = await executeSandboxedCommand({
          command,
          args,
          cwd,
          timeoutMs,
          env,
          workspacePath: resolvedWorkspace,
        });

        const commandEvidence: CommandEvidence = {
          id: generateId('cmd'),
          type: 'command',
          recordedAt: executionResult.executedAt,
          command: executionResult.command,
          args: executionResult.args,
          exitCode: executionResult.exitCode,
          stdout: executionResult.stdout,
          stderr: executionResult.stderr,
          durationMs: executionResult.durationMs,
          executedAt: executionResult.executedAt,
          timedOut: executionResult.timedOut,
          provenance: 'server_executed',
          ...(workspaceName ? { workspaceName } : {}),
        };

        if (!bundle.evidence.commands) {
          bundle.evidence.commands = [];
        }
        bundle.evidence.commands.push(commandEvidence);
        bundle.updatedAt = new Date().toISOString();
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Command executed and verified evidence recorded successfully.',
                  bundleId: bundle.id,
                  evidenceId: commandEvidence.id,
                  workspaceName: commandEvidence.workspaceName || 'root',
                  command: commandEvidence.command,
                  args: commandEvidence.args,
                  exitCode: commandEvidence.exitCode,
                  durationMs: commandEvidence.durationMs,
                  timedOut: commandEvidence.timedOut,
                  provenance: commandEvidence.provenance,
                  stdoutPreview: commandEvidence.stdout.slice(0, 500),
                  stderrPreview: commandEvidence.stderr.slice(0, 500),
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to execute verified command: ${message}` }],
        };
      }
    }
  );

  // 10. register_workspace
  server.tool(
    'register_workspace',
    'Registers an additional named workspace or package within a monorepo or multi-repo evidence bundle.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      name: z
        .string()
        .min(1)
        .regex(/^[a-zA-Z0-9_-]+$/, 'Workspace name must only contain alphanumeric characters, hyphens, and underscores.')
        .describe('Unique name for the workspace (e.g. "frontend", "backend", "shared").'),
      path: z.string().min(1).describe('Path to the workspace root directory (absolute or relative to bundle root).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, name, path: rawPath, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const baseDir = bundle.workspacePath;
        const resolvedPath = validateWorkspacePath(path.resolve(baseDir, rawPath));

        if (!bundle.workspaces) {
          bundle.workspaces = { root: bundle.workspacePath };
        }

        bundle.workspaces[name] = resolvedPath;
        bundle.updatedAt = new Date().toISOString();
        await saveBundle(bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: `Workspace "${name}" registered successfully in bundle.`,
                  bundleId: bundle.id,
                  workspaceName: name,
                  workspacePath: resolvedPath,
                  allWorkspaces: bundle.workspaces,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to register workspace: ${message}` }],
        };
      }
    }
  );

  // 11. capture_ast_evidence
  server.tool(
    'capture_ast_evidence',
    'Extracts AST symbols, signatures, and computes semantic diffs (with Git HEAD comparison and breaking change detection) for target source files.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      files: z
        .array(z.string().min(1))
        .min(1)
        .describe('Array of relative or absolute file paths to analyze within workspace.'),
      workspaceName: z
        .string()
        .optional()
        .describe('Optional name of the workspace for monorepo packages (defaults to "root").'),
      workspacePath: z.string().optional().describe('Optional workspace root directory to locate the bundle.'),
      compareWithGitHead: z
        .boolean()
        .default(true)
        .describe('Whether to compare symbols against Git HEAD to detect changes and breaking changes.'),
    },
    async ({ bundleId, files, workspaceName, workspacePath, compareWithGitHead }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);

        if (!bundle.evidence.ast) {
          bundle.evidence.ast = [];
        }

        const capturedItems: AstEvidence[] = [];

        for (const filePath of files) {
          const astEvidence = await captureFileAstEvidence({
            filePath,
            workspacePath: targetWs,
            workspaceName,
            compareWithGitHead,
          });

          bundle.evidence.ast.push(astEvidence);
          capturedItems.push(astEvidence);
        }

        bundle.updatedAt = new Date().toISOString();
        await saveBundle(bundle);

        const summary = capturedItems.map((item) => ({
          id: item.id,
          filePath: item.filePath,
          workspaceName: item.workspaceName || 'root',
          language: item.language,
          symbolsCount: item.symbolsCount,
          hasSemanticChanges: item.diff?.hasChanges ?? false,
          isBreakingChange: item.diff?.isBreakingChange ?? false,
          diffSummary: item.diff
            ? {
                added: item.diff.addedSymbols.length,
                removed: item.diff.removedSymbols.length,
                modified: item.diff.modifiedSymbols.length,
              }
            : undefined,
        }));

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: `Captured AST semantic evidence for ${capturedItems.length} file(s).`,
                  bundleId: bundle.id,
                  astEvidence: summary,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to capture AST evidence: ${message}` }],
        };
      }
    }
  );

  // 12. export_verification_proof
  server.tool(
    'export_verification_proof',
    'Verifies an evidence bundle and issues a cryptographically signed, portable Ed25519 verification proof saved to .evidence-mcp/proofs/.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to verify and certify.'),
      privateKeyPem: z.string().optional().describe('Optional PEM-encoded private key for signing (defaults to local agent key).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, privateKeyPem, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const verification = await verifyEvidenceBundle(bundle);
        const proof = await createVerificationProof({
          bundle,
          verification,
          workspacePath: bundle.workspacePath,
          privateKeyPem,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: `Verification proof exported and cryptographically signed successfully.`,
                  proofId: proof.id,
                  bundleId: proof.bundleId,
                  verdict: proof.verdict,
                  bundleDigest: proof.bundleDigest,
                  signerFingerprint: proof.signer.keyFingerprint,
                  signature: proof.signature,
                  itemCount: proof.itemCount,
                  verifiedAt: proof.verifiedAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to export verification proof: ${message}` }],
        };
      }
    }
  );

  // 13. verify_replay_proof
  server.tool(
    'verify_replay_proof',
    'Verifies the cryptographic signature and bundle consistency of an exported verification proof.',
    {
      proofId: z.string().optional().describe('The ID of the proof stored in .evidence-mcp/proofs/ (e.g. "proof_12345678").'),
      proofJson: z.string().optional().describe('Raw JSON string of a verification proof.'),
      bundleId: z.string().optional().describe('Optional bundle ID to verify consistency with live workspace state.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate bundle and proof.'),
    },
    async ({ proofId, proofJson, bundleId, workspacePath }) => {
      try {
        let proofObj: any;
        if (proofJson) {
          proofObj = JSON.parse(proofJson);
        } else if (proofId) {
          proofObj = await loadProof(proofId, workspacePath);
        } else {
          throw new Error('Either proofId or proofJson must be supplied.');
        }

        const targetBundleId = bundleId || proofObj.bundleId;
        let bundle: EvidenceBundle | undefined;
        if (targetBundleId) {
          try {
            bundle = await loadBundle(targetBundleId, workspacePath);
          } catch {
            // Bundle may not exist if verifying proof offline
          }
        }

        const check = verifyProofSignature(proofObj, bundle);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  proofId: proofObj.id,
                  bundleId: proofObj.bundleId,
                  valid: check.valid,
                  verdict: proofObj.verdict,
                  signerFingerprint: proofObj.signer.keyFingerprint,
                  bundleDigestMatches: check.bundleDigestMatches,
                  reason: check.reason,
                  verifiedAt: proofObj.verifiedAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to verify proof: ${message}` }],
        };
      }
    }
  );

  // 14. endorse_evidence_bundle
  server.tool(
    'endorse_evidence_bundle',
    'Appends an independent, cryptographically signed peer review endorsement to an evidence bundle.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to endorse.'),
      agentId: z.string().min(1).describe('Unique identifier of the reviewing agent (e.g. "agent:tester-v1").'),
      role: z
        .enum(['tester', 'security_auditor', 'architect', 'peer_reviewer'])
        .describe('Reviewing agent professional role.'),
      verdict: z
        .enum(['approved', 'rejected', 'changes_requested'])
        .describe('Review endorsement verdict.'),
      comment: z.string().min(1).describe('Detailed evaluation commentary supporting the verdict.'),
      privateKeyPem: z.string().optional().describe('Optional PEM-encoded private key for signing endorsement.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, agentId, role, verdict, comment, privateKeyPem, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const endorsement = await createPeerEndorsement({
          bundle,
          agentId,
          role,
          verdict,
          comment,
          privateKeyPem,
          workspacePath: bundle.workspacePath,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: `Peer endorsement recorded and cryptographically signed successfully.`,
                  endorsementId: endorsement.id,
                  bundleId: bundle.id,
                  agentId: endorsement.agentId,
                  role: endorsement.role,
                  verdict: endorsement.verdict,
                  bundleDigest: endorsement.bundleDigest,
                  signerFingerprint: endorsement.signer.keyFingerprint,
                  timestamp: endorsement.timestamp,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to endorse bundle: ${message}` }],
        };
      }
    }
  );

  // 15. check_bundle_quorum
  server.tool(
    'check_bundle_quorum',
    'Evaluates consensus quorum rules across all peer endorsements on an evidence bundle.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      minEndorsements: z.number().int().min(1).default(1).describe('Minimum number of approved endorsements required.'),
      requiredRoles: z
        .array(z.enum(['tester', 'security_auditor', 'architect', 'peer_reviewer']))
        .optional()
        .describe('Array of required reviewer roles (e.g. ["tester", "security_auditor"]).'),
      requireUniqueSigners: z.boolean().default(true).describe('Enforce unique signer keys and agent IDs.'),
      disallowRejections: z.boolean().default(true).describe('Fail quorum if any explicit rejection exists.'),
      requireTrustedRegistry: z
        .boolean()
        .default(false)
        .describe('Require all endorser agent keys to be registered and active in the workspace agent registry.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({
      bundleId,
      minEndorsements,
      requiredRoles,
      requireUniqueSigners,
      disallowRejections,
      requireTrustedRegistry,
      workspacePath,
    }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const quorumResult = checkBundleQuorum(bundle, {
          minEndorsements,
          requiredRoles,
          requireUniqueSigners,
          disallowRejections,
          requireTrustedRegistry,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId: quorumResult.bundleId,
                  satisfied: quorumResult.satisfied,
                  totalEndorsements: quorumResult.totalEndorsements,
                  approvedCount: quorumResult.approvedCount,
                  rejectionsCount: quorumResult.rejectionsCount,
                  verifiedSignatures: quorumResult.verifiedSignatures,
                  policy: quorumResult.policy,
                  reasons: quorumResult.reasons,
                  endorsements: quorumResult.endorsements.map((e) => ({
                    id: e.id,
                    agentId: e.agentId,
                    role: e.role,
                    verdict: e.verdict,
                    signerFingerprint: e.signer.keyFingerprint,
                    timestamp: e.timestamp,
                  })),
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to check bundle quorum: ${message}` }],
        };
      }
    }
  );

  // 16. evaluate_evidence_policy
  server.tool(
    'evaluate_evidence_policy',
    'Evaluates an evidence bundle against declarative compliance rules defined in evidence.policy.json or an inline policy.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to evaluate.'),
      policyPath: z.string().optional().describe('Path to evidence.policy.json file (defaults to workspace discovery).'),
      policy: z.record(z.string(), z.unknown()).optional().describe('Inline policy definition overriding file on disk.'),
      strict: z.boolean().default(false).describe('Enforce strict compliance (fail if any warnings exist).'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, policyPath, policy, strict, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);

        let activePolicy: EvidencePolicy;
        let source = 'inline';

        if (policy) {
          activePolicy = policy as unknown as EvidencePolicy;
        } else {
          const loaded = await loadPolicyFile(policyPath, bundle.workspacePath);
          if (!loaded) {
            throw new Error(
              `No policy found. Provide an inline policy or create "evidence.policy.json" in workspace root.`
            );
          }
          activePolicy = loaded.policy;
          source = loaded.sourcePath;
        }

        let verificationResult;
        try {
          verificationResult = await verifyEvidenceBundle(bundle);
        } catch {
          // Proceed even if verification throws
        }

        const evaluation = evaluateEvidencePolicy({
          bundle,
          policy: activePolicy,
          strict,
          verificationResult,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId: evaluation.bundleId,
                  passed: evaluation.passed,
                  policySource: source,
                  summary: evaluation.policySummary,
                  rulesEvaluated: evaluation.rulesEvaluated,
                  passedCount: evaluation.passedCount,
                  failedCount: evaluation.failedCount,
                  warningCount: evaluation.warningCount,
                  evaluations: evaluation.evaluations,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to evaluate evidence policy: ${message}` }],
        };
      }
    }
  );

  // 17. dispatch_webhook_audit
  server.tool(
    'dispatch_webhook_audit',
    'Dispatches a cryptographically signed HMAC-SHA256 audit payload to a remote webhook endpoint.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to dispatch.'),
      webhookUrl: z.string().url().describe('Target HTTP or HTTPS webhook URL.'),
      secretToken: z.string().optional().describe('Optional secret key for HMAC-SHA256 signature (X-Evidence-Signature).'),
      includeProof: z.boolean().default(false).describe('Generate and attach portable Ed25519 verification proof.'),
      headers: z.record(z.string(), z.string()).optional().describe('Optional additional HTTP request headers.'),
      timeoutMs: z.number().int().min(1000).max(60000).default(10000).describe('Network timeout in milliseconds.'),
      allowPrivateNetwork: z.boolean().default(false).describe('Permit local/private/loopback network webhook targets (disabled by default for SSRF protection).'),
      maxRetries: z.number().int().min(0).max(5).default(2).describe('Maximum transient failure retry attempts with exponential backoff.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, webhookUrl, secretToken, includeProof, headers, timeoutMs, allowPrivateNetwork, maxRetries, workspacePath }) => {
      try {
        const result = await dispatchAuditWebhook({
          bundleId,
          webhookUrl,
          secretToken,
          includeProof,
          headers,
          timeoutMs,
          allowPrivateNetwork,
          maxRetries,
          workspacePath,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId: result.bundleId,
                  delivered: result.delivered,
                  webhookUrl: result.webhookUrl,
                  statusCode: result.statusCode,
                  statusText: result.statusText,
                  durationMs: result.durationMs,
                  signatureHeader: result.signatureHeader,
                  responsePreview: result.responseBody,
                  error: result.error,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to dispatch webhook audit: ${message}` }],
        };
      }
    }
  );

  // 18. register_trusted_agent
  server.tool(
    'register_trusted_agent',
    'Registers or updates an authorized agent public key and role in the workspace trusted agent registry.',
    {
      agentId: z.string().min(1).describe('Unique agent identifier (e.g. "agent:security-auditor-1").'),
      name: z.string().min(1).describe('Human-readable display name for the agent.'),
      role: z.string().min(1).describe('Agent functional role (e.g. "security_auditor", "tester", "architect").'),
      publicKeyPem: z.string().min(1).describe('PEM-encoded public key of the agent.'),
      expiresAt: z.string().optional().describe('Optional ISO timestamp after which the agent key expires.'),
      metadata: z.record(z.string(), z.unknown()).optional().describe('Optional metadata dictionary.'),
      workspacePath: z.string().optional().describe('Optional workspace path root.'),
    },
    async ({ agentId, name, role, publicKeyPem, expiresAt, metadata, workspacePath }) => {
      try {
        const targetWs = workspacePath ? validateWorkspacePath(workspacePath) : process.cwd();
        const agent = await registerTrustedAgent({
          workspacePath: targetWs,
          agentId,
          name,
          role,
          publicKeyPem,
          expiresAt,
          metadata,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Agent successfully registered in trusted registry.',
                  agentId: agent.agentId,
                  name: agent.name,
                  role: agent.role,
                  keyFingerprint: agent.keyFingerprint,
                  status: agent.status,
                  registeredAt: agent.registeredAt,
                  expiresAt: agent.expiresAt,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to register trusted agent: ${message}` }],
        };
      }
    }
  );

  // 19. revoke_trusted_agent
  server.tool(
    'revoke_trusted_agent',
    'Revokes a trusted agent key in the workspace registry, invalidating future endorsements or attestations.',
    {
      agentId: z.string().min(1).describe('Unique agent identifier to revoke.'),
      reason: z.string().min(1).describe('Audit reason for key revocation.'),
      workspacePath: z.string().optional().describe('Optional workspace path root.'),
    },
    async ({ agentId, reason, workspacePath }) => {
      try {
        const targetWs = workspacePath ? validateWorkspacePath(workspacePath) : process.cwd();
        const agent = await revokeTrustedAgent({
          workspacePath: targetWs,
          agentId,
          reason,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  message: 'Agent successfully revoked in trusted registry.',
                  agentId: agent.agentId,
                  status: agent.status,
                  revokedAt: agent.revokedAt,
                  revocationReason: agent.revocationReason,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to revoke trusted agent: ${message}` }],
        };
      }
    }
  );

  // 20. capture_sbom_evidence
  server.tool(
    'capture_sbom_evidence',
    'Generates a CycloneDX v1.5 SBOM from workspace package manifests/lockfiles and records verifiable supply-chain evidence on the bundle.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      workspaceName: z.string().optional().describe('Optional registered monorepo package name.'),
      includeDevDependencies: z
        .boolean()
        .default(true)
        .describe('Whether to include development dependencies in the SBOM inventory.'),
      outputPath: z
        .string()
        .optional()
        .describe('Optional relative file path within the workspace to write the CycloneDX v1.5 JSON file.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint to locate the bundle.'),
    },
    async ({ bundleId, workspaceName, includeDevDependencies, outputPath, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const targetWs = resolveWorkspaceForBundle(bundle, workspaceName);

        const { evidence, cycloneDxBom } = await captureWorkspaceSbom({
          workspacePath: targetWs,
          workspaceName,
          includeDevDependencies,
        });

        if (!bundle.evidence.sbom) {
          bundle.evidence.sbom = [];
        }
        bundle.evidence.sbom.push(evidence);
        await saveBundle(bundle);

        let exportedFile: string | undefined;
        if (outputPath) {
          exportedFile = await writeWorkspaceOutputFile(
            targetWs,
            outputPath,
            JSON.stringify(cycloneDxBom, null, 2)
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId: bundle.id,
                  evidenceId: evidence.id,
                  format: evidence.format,
                  manifestPath: evidence.manifestPath,
                  lockfilePath: evidence.lockfilePath || null,
                  componentCount: evidence.componentCount,
                  bomDigest: evidence.bomDigest,
                  licenseSummary: evidence.licenseSummary,
                  exportedFile: exportedFile || null,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to capture SBOM evidence: ${message}` }],
        };
      }
    }
  );

  // 21. notarize_evidence_bundle
  server.tool(
    'notarize_evidence_bundle',
    'Anchors only the anonymized bundle SHA-256 digest to a remote transparency notary service and stores the signed Ed25519 receipt.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      notaryUrl: z.string().url().describe('HTTP or HTTPS URL of the transparency notary service.'),
      authToken: z.string().optional().describe('Optional Bearer authentication token for the notary endpoint.'),
      timeoutMs: z.number().int().min(500).max(60000).optional().describe('Optional HTTP timeout in ms.'),
      allowPrivateNetwork: z.boolean().default(false).describe('Permit local/private/loopback network notary targets (disabled by default for SSRF protection).'),
      maxRetries: z.number().int().min(0).max(5).optional().describe('Maximum transient failure retry attempts with exponential backoff.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, notaryUrl, authToken, timeoutMs, allowPrivateNetwork, maxRetries, workspacePath }) => {
      try {
        const res = await notarizeEvidenceBundle({
          bundleId,
          notaryUrl,
          authToken,
          timeoutMs,
          allowPrivateNetwork,
          maxRetries,
          workspacePath,
        });

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId,
                  receiptId: res.receipt.id,
                  bundleDigest: res.bundleDigest,
                  notaryUrl: res.receipt.notaryUrl,
                  notaryKeyFingerprint: res.receipt.notaryKeyFingerprint,
                  logIndex: res.receipt.logIndex,
                  merkleLeafHash: res.receipt.merkleLeafHash,
                  notarizedAt: res.receipt.notarizedAt,
                  durationMs: res.durationMs,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to notarize evidence bundle: ${message}` }],
        };
      }
    }
  );

  // 22. export_slsa_provenance
  server.tool(
    'export_slsa_provenance',
    'Generates and optionally Ed25519-signs an in-toto v1 / SLSA v1.0 Provenance attestation envelope from an evidence bundle.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle.'),
      builderId: z.string().optional().describe('Optional SLSA builder ID URI override.'),
      sign: z.boolean().default(true).describe('Sign the SLSA statement with Ed25519 keypair (default: true).'),
      outputPath: z
        .string()
        .optional()
        .describe('Optional relative path inside the workspace to write the SLSA provenance JSON.'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, builderId, sign, outputPath, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const envelope = await generateSlsaProvenance({
          bundle,
          builderId,
          includeSignature: sign,
        });

        bundle.slsaProvenance = envelope;
        await saveBundle(bundle);

        let exportedFile: string | undefined;
        if (outputPath) {
          exportedFile = await writeWorkspaceOutputFile(
            bundle.workspacePath,
            outputPath,
            JSON.stringify(envelope, null, 2)
          );
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bundleId,
                  predicateType: envelope.statement.predicateType,
                  statementDigest: envelope.statementDigest,
                  subjectCount: envelope.statement.subject.length,
                  dependencyCount: envelope.statement.predicate.buildDefinition.resolvedDependencies.length,
                  signed: Boolean(envelope.signature),
                  keyFingerprint: envelope.signature?.keyFingerprint || null,
                  exportedFile: exportedFile || null,
                  provenance: envelope,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          isError: true,
          content: [{ type: 'text', text: `Failed to export SLSA provenance: ${message}` }],
        };
      }
    }
  );

  return server;
}
