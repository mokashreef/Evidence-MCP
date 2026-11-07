import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import {
  Assertion,
  CommandEvidence,
  EvidenceBundle,
  FileSnapshotEvidence,
  GitEvidence,
} from './types.js';
import { validateWorkspacePath, assertSafeFilePath } from './security.js';
import { computeFileSha256AndSize } from './hasher.js';
import { captureGitState } from './git.js';
import {
  generateId,
  saveBundle,
  loadBundle,
  registerBundleWorkspace,
} from './storage.js';
import { verifyEvidenceBundle } from './verifier.js';
import { exportEvidenceReport } from './reporter.js';
import { signEvidenceBundle } from './attestation.js';

export function createEvidenceServer(): McpServer {
  const server = new McpServer({
    name: 'evidence-mcp',
    version: '0.3.0',
  });

  // 1. create_evidence_bundle
  server.tool(
    'create_evidence_bundle',
    'Creates a new evidence bundle for a task and workspace with in_progress status.',
    {
      task: z.string().min(1).describe('The task or objective being addressed by the agent.'),
      workspacePath: z.string().min(1).describe('Path to the workspace root directory.'),
      metadata: z.record(z.string(), z.unknown()).optional().describe('Optional key-value metadata.'),
    },
    async ({ task, workspacePath, metadata }) => {
      try {
        const resolvedWorkspace = validateWorkspacePath(workspacePath);
        const bundleId = generateId('bundle');
        const now = new Date().toISOString();

        const bundle: EvidenceBundle = {
          id: bundleId,
          task,
          workspacePath: resolvedWorkspace,
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
      workspacePath: z.string().optional().describe('Optional workspace path hint if running outside default cwd.'),
    },
    async ({ bundleId, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const gitState = await captureGitState(bundle.workspacePath);

        const gitEvidence: GitEvidence = {
          id: generateId('git'),
          type: 'git',
          capturedAt: new Date().toISOString(),
          branch: gitState.branch,
          headCommit: gitState.headCommit,
          statusShort: gitState.statusShort,
          diffCheck: gitState.diffCheck,
          isClean: gitState.isClean,
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
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, command, exitCode, stdout, stderr, workspacePath }) => {
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
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, paths, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const snapshots: FileSnapshotEvidence[] = [];

        for (const filePath of paths) {
          const safePath = assertSafeFilePath(bundle.workspacePath, filePath);
          const hashResult = await computeFileSha256AndSize(safePath.absolutePath);

          const snapshot: FileSnapshotEvidence = {
            id: generateId('file'),
            type: 'file_snapshot',
            capturedAt: new Date().toISOString(),
            path: safePath.relativePath,
            absolutePath: safePath.absolutePath,
            sha256: hashResult.sha256,
            sizeBytes: hashResult.sizeBytes,
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
    'Produces an evidence report in Markdown, JSON, or HTML format with clear distinction between verified and agent-reported evidence.',
    {
      bundleId: z.string().min(1).describe('The unique identifier of the evidence bundle to export.'),
      format: z
        .enum(['markdown', 'json', 'html'])
        .default('markdown')
        .describe('Output format: "markdown", "json", or "html".'),
      workspacePath: z.string().optional().describe('Optional workspace path hint.'),
    },
    async ({ bundleId, format, workspacePath }) => {
      try {
        const bundle = await loadBundle(bundleId, workspacePath);
        const verification = await verifyEvidenceBundle(bundle);
        const report = exportEvidenceReport(bundle, format, verification);

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

  return server;
}
