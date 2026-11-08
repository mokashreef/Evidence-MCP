import { z } from 'zod';

export type BundleStatus = 'in_progress' | 'completed' | 'verified' | 'stale' | 'failed' | 'unverifiable';
export type EvidenceType = 'git' | 'command' | 'file_snapshot' | 'ast';
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
  cwd?: string;
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

export type AstSymbolKind =
  | 'function'
  | 'class'
  | 'interface'
  | 'type'
  | 'enum'
  | 'variable'
  | 'method';

export interface AstParameter {
  name: string;
  type?: string;
  optional?: boolean;
  defaultValue?: string;
}

export interface AstSymbol {
  name: string;
  kind: AstSymbolKind;
  isExported: boolean;
  isAsync?: boolean;
  signature?: string;
  parameters?: AstParameter[];
  returnType?: string;
  startLine: number;
  endLine: number;
}

export interface AstSemanticDiff {
  filePath: string;
  hasChanges: boolean;
  isBreakingChange: boolean;
  addedSymbols: AstSymbol[];
  removedSymbols: AstSymbol[];
  modifiedSymbols: {
    symbol: AstSymbol;
    previous: AstSymbol;
    changes: string[];
  }[];
}

export interface AstEvidence {
  id: string;
  type: 'ast';
  capturedAt: string;
  filePath: string;
  workspaceName?: string;
  language: string;
  symbolsCount: number;
  symbols: AstSymbol[];
  diff?: AstSemanticDiff;
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
    ast?: AstEvidence[];
  };
  assertions: Assertion[];
}

export interface VerificationItemResult {
  id: string;
  type: 'git' | 'file' | 'command' | 'assertion' | 'attestation' | 'ast';
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

export const CaptureAstEvidenceSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  files: z.array(z.string().min(1)).min(1, 'At least one file path must be provided.'),
  workspaceName: z.string().optional(),
  workspacePath: z.string().optional(),
  compareWithGitHead: z.boolean().default(true),
});
export type CaptureAstEvidenceInput = z.infer<typeof CaptureAstEvidenceSchema>;

export interface VerificationProof {
  id: string;
  bundleId: string;
  bundleDigest: string;
  verdict: VerificationStatus;
  summary: string;
  verifiedAt: string;
  signer: {
    algorithm: 'ed25519';
    publicKeyPem: string;
    keyFingerprint: string;
  };
  signature: string;
  itemCount: number;
  environment: {
    platform: string;
    nodeVersion: string;
    arch: string;
  };
}

export interface ReplayStepResult {
  index: number;
  evidenceId: string;
  type: 'git' | 'file' | 'command' | 'ast';
  description: string;
  originalTimestamp: string;
  status: 'passed' | 'failed' | 'diverged';
  details: string;
  reproducedExecution?: {
    exitCode: number;
    exitCodeMatches: boolean;
    durationMs: number;
  };
}

export interface ReplayResult {
  bundleId: string;
  replayedAt: string;
  totalSteps: number;
  passedSteps: number;
  divergedSteps: number;
  isReproducible: boolean;
  steps: ReplayStepResult[];
}

export const ExportVerificationProofSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  privateKeyPem: z.string().optional(),
  workspacePath: z.string().optional(),
});
export type ExportVerificationProofInput = z.infer<typeof ExportVerificationProofSchema>;

export const VerifyReplayProofSchema = z.object({
  proofId: z.string().optional(),
  proofJson: z.string().optional(),
  bundleId: z.string().optional(),
  workspacePath: z.string().optional(),
});
export type VerifyReplayProofInput = z.infer<typeof VerifyReplayProofSchema>;
