import { z } from 'zod';

export type BundleStatus = 'in_progress' | 'completed' | 'verified' | 'stale' | 'failed' | 'unverifiable';
export type EvidenceType = 'git' | 'command' | 'file_snapshot';
export type VerificationStatus = 'verified' | 'stale' | 'failed' | 'unverifiable';

export interface GitEvidence {
  id: string;
  type: 'git';
  capturedAt: string;
  branch: string;
  headCommit: string;
  statusShort: string;
  diffCheck: string;
  isClean: boolean;
  workspaceName?: string;
}

export interface CommandEvidence {
  id: string;
  type: 'command';
  recordedAt: string;
  command: string;
  exitCode: number;
  stdout: string;
  stderr: string;
  provenance: 'agent_reported' | 'server_executed';
  args?: string[];
  durationMs?: number;
  executedAt?: string;
  timedOut?: boolean;
  workspaceName?: string;
}

export interface FileSnapshotEvidence {
  id: string;
  type: 'file_snapshot';
  capturedAt: string;
  path: string; // workspace-relative path
  absolutePath: string;
  sha256: string;
  sizeBytes: number;
  workspaceName?: string;
}

export interface Assertion {
  id: string;
  claim: string;
  evidenceIds: string[];
  createdAt: string;
}

export interface BundleAttestation {
  algorithm: 'ed25519';
  publicKeyPem: string;
  keyFingerprint: string;
  signedAt: string;
  signature: string;
}

export interface EvidenceBundle {
  id: string;
  task: string;
  workspacePath: string;
  workspaces?: Record<string, string>;
  status: BundleStatus;
  createdAt: string;
  updatedAt: string;
  metadata?: Record<string, unknown>;
  attestation?: BundleAttestation;
  evidence: {
    git?: GitEvidence[];
    commands?: CommandEvidence[];
    fileSnapshots?: FileSnapshotEvidence[];
  };
  assertions: Assertion[];
}

export interface VerificationItemResult {
  id: string;
  type: 'git' | 'file' | 'command' | 'assertion' | 'attestation';
  status: 'verified' | 'stale' | 'failed' | 'unverifiable' | 'recorded';
  details: string;
  target?: string;
  expected?: string;
  actual?: string;
}

export interface VerificationResult {
  bundleId: string;
  status: VerificationStatus;
  verifiedAt: string;
  summary: string;
  reasons: string[];
  items: VerificationItemResult[];
}

// ==========================================
// Tool Zod Schemas
// ==========================================

export const CreateEvidenceBundleSchema = z.object({
  task: z.string().min(1, 'Task description cannot be empty.'),
  workspacePath: z.string().min(1, 'Workspace path cannot be empty.'),
  metadata: z.record(z.string(), z.unknown()).optional(),
  additionalWorkspaces: z.record(z.string(), z.string()).optional(),
});
export type CreateEvidenceBundleInput = z.infer<typeof CreateEvidenceBundleSchema>;

export const RegisterWorkspaceSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  name: z
    .string()
    .min(1, 'Workspace name cannot be empty.')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Workspace name must only contain alphanumeric characters, hyphens, and underscores.'),
  path: z.string().min(1, 'Workspace path cannot be empty.'),
  workspacePath: z.string().optional(),
});
export type RegisterWorkspaceInput = z.infer<typeof RegisterWorkspaceSchema>;

export const CaptureGitEvidenceSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  workspacePath: z.string().optional(),
  workspaceName: z.string().optional(),
});
export type CaptureGitEvidenceInput = z.infer<typeof CaptureGitEvidenceSchema>;

export const RecordCommandResultSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  command: z.string().min(1, 'Command string cannot be empty.'),
  exitCode: z.number().int(),
  stdout: z.string(),
  stderr: z.string(),
  workspacePath: z.string().optional(),
  workspaceName: z.string().optional(),
});
export type RecordCommandResultInput = z.infer<typeof RecordCommandResultSchema>;

export const SnapshotFilesSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  paths: z.array(z.string().min(1)).min(1, 'At least one file path must be provided.'),
  workspacePath: z.string().optional(),
  workspaceName: z.string().optional(),
});
export type SnapshotFilesInput = z.infer<typeof SnapshotFilesSchema>;

export const AddAssertionSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  claim: z.string().min(1, 'Claim cannot be empty.'),
  evidenceIds: z.array(z.string().min(1)).min(1, 'Assertion must reference at least one evidence ID.'),
  workspacePath: z.string().optional(),
});
export type AddAssertionInput = z.infer<typeof AddAssertionSchema>;

export const VerifyEvidenceBundleSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  workspacePath: z.string().optional(),
});
export type VerifyEvidenceBundleInput = z.infer<typeof VerifyEvidenceBundleSchema>;

export const ExportEvidenceReportSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  format: z.enum(['markdown', 'json', 'html']).default('markdown'),
  workspacePath: z.string().optional(),
});
export type ExportEvidenceReportInput = z.infer<typeof ExportEvidenceReportSchema>;

export const SignEvidenceBundleSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  privateKeyPem: z.string().optional(),
  workspacePath: z.string().optional(),
});
export type SignEvidenceBundleInput = z.infer<typeof SignEvidenceBundleSchema>;

export const ExecuteVerifiedCommandSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  command: z.string().min(1, 'Command cannot be empty.'),
  args: z.array(z.string()).default([]),
  cwd: z.string().optional(),
  timeoutMs: z.number().int().min(500).max(120000).optional(),
  env: z.record(z.string(), z.string()).optional(),
  workspacePath: z.string().optional(),
  workspaceName: z.string().optional(),
});
export type ExecuteVerifiedCommandInput = z.infer<typeof ExecuteVerifiedCommandSchema>;
