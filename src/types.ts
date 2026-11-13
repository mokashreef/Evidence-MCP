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

export interface SbomComponent {
  name: string;
  version: string;
  purl?: string;
  scope?: 'required' | 'optional' | 'dev' | 'excluded';
  license?: string;
  integrity?: string;
}

export interface SbomEvidence {
  id: string;
  type: 'sbom';
  capturedAt: string;
  format: 'cyclonedx-1.5';
  ecosystem?: 'npm' | 'golang' | 'cargo' | 'pypi' | 'mixed';
  workspaceName?: string;
  manifestPath: string;
  manifestSha256: string;
  lockfilePath?: string;
  lockfileSha256?: string;
  additionalManifests?: Array<{ path: string; sha256: string }>;
  componentCount: number;
  components: SbomComponent[];
  licenseSummary: Record<string, number>;
  bomDigest: string;
}

export interface NotaryReceipt {
  id: string;
  bundleId: string;
  bundleDigest: string;
  notaryUrl: string;
  notaryPublicKeyPem: string;
  notaryKeyFingerprint: string;
  algorithm: 'ed25519';
  logIndex: number;
  merkleLeafHash: string;
  notarizedAt: string;
  signature: string;
  authorKeyFingerprint?: string;
}

// ==========================================
// SLSA v1.0 Provenance Types
// ==========================================

export interface SlsaSubject {
  name: string;
  digest: Record<string, string>;
}

export interface SlsaResourceDescriptor {
  uri?: string;
  name?: string;
  digest?: Record<string, string>;
  mediaType?: string;
  annotations?: Record<string, unknown>;
}

export interface SlsaProvenanceStatement {
  _type: string;
  subject: SlsaSubject[];
  predicateType: string;
  predicate: {
    buildDefinition: {
      buildType: string;
      externalParameters: Record<string, unknown>;
      internalParameters: Record<string, unknown>;
      resolvedDependencies: SlsaResourceDescriptor[];
    };
    runDetails: {
      builder: {
        id: string;
        version?: Record<string, string>;
      };
      metadata: {
        invocationId: string;
        startedOn: string;
        finishedOn?: string;
      };
      byproducts?: SlsaResourceDescriptor[];
    };
  };
}

export interface SlsaProvenanceSignature {
  algorithm: 'ed25519';
  publicKeyPem: string;
  keyFingerprint: string;
  signedAt: string;
  signature: string;
}

export interface SlsaProvenanceEnvelope {
  statement: SlsaProvenanceStatement;
  statementDigest: string;
  signature?: SlsaProvenanceSignature;
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
  endorsements?: PeerEndorsement[];
  notaryReceipts?: NotaryReceipt[];
  slsaProvenance?: SlsaProvenanceEnvelope;
  evidence: {
    git?: GitEvidence[];
    commands?: CommandEvidence[];
    fileSnapshots?: FileSnapshotEvidence[];
    ast?: AstEvidence[];
    sbom?: SbomEvidence[];
  };
  assertions: Assertion[];
}

export interface VerificationItemResult {
  id: string;
  type: 'git' | 'file' | 'command' | 'assertion' | 'attestation' | 'ast' | 'sbom';
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
  format: z.enum(['markdown', 'json', 'html', 'sarif']).default('markdown'),
  policyPath: z.string().optional(),
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

// ==========================================
// Multi-Agent Consensus & Quorum Types
// ==========================================

export type PeerEndorsementRole =
  | 'tester'
  | 'security_auditor'
  | 'architect'
  | 'peer_reviewer';

export type PeerEndorsementVerdict =
  | 'approved'
  | 'rejected'
  | 'changes_requested';

export interface PeerEndorsement {
  id: string;
  agentId: string;
  role: PeerEndorsementRole;
  verdict: PeerEndorsementVerdict;
  comment: string;
  timestamp: string;
  bundleDigest: string;
  signer: {
    algorithm: 'ed25519';
    publicKeyPem: string;
    keyFingerprint: string;
  };
  signature: string;
}

export interface QuorumPolicy {
  minEndorsements?: number;
  requiredRoles?: PeerEndorsementRole[];
  requireUniqueSigners?: boolean;
  disallowRejections?: boolean;
  requireTrustedRegistry?: boolean;
}

export interface QuorumResult {
  bundleId: string;
  satisfied: boolean;
  totalEndorsements: number;
  approvedCount: number;
  rejectionsCount: number;
  changesRequestedCount: number;
  verifiedSignatures: number;
  policy: QuorumPolicy;
  reasons: string[];
  endorsements: PeerEndorsement[];
}

export const EndorseEvidenceBundleSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  agentId: z.string().min(1, 'agentId is required.'),
  role: z.enum(['tester', 'security_auditor', 'architect', 'peer_reviewer']),
  verdict: z.enum(['approved', 'rejected', 'changes_requested']),
  comment: z.string().min(1, 'Review commentary is required.'),
  privateKeyPem: z.string().optional(),
  workspacePath: z.string().optional(),
});
export type EndorseEvidenceBundleInput = z.infer<typeof EndorseEvidenceBundleSchema>;

export const CheckBundleQuorumSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  minEndorsements: z.number().int().min(1).default(1),
  requiredRoles: z.array(z.enum(['tester', 'security_auditor', 'architect', 'peer_reviewer'])).optional(),
  requireUniqueSigners: z.boolean().default(true),
  disallowRejections: z.boolean().default(true),
  requireTrustedRegistry: z.boolean().default(false),
  workspacePath: z.string().optional(),
});
export type CheckBundleQuorumInput = z.infer<typeof CheckBundleQuorumSchema>;

// ==========================================
// Automated Evidence Policy Engine Types
// ==========================================

export interface EvidencePolicyGitRules {
  requireCleanWorkingTree?: boolean;
  allowedBranches?: string[];
  disallowDetachedHead?: boolean;
}

export interface EvidencePolicyFileRules {
  maxSnapshots?: number;
  requiredPatterns?: string[];
  disallowedPatterns?: string[];
}

export interface EvidencePolicyCommandRules {
  requireServerExecutedCommands?: boolean;
  minServerExecutedCommands?: number;
  disallowNonZeroExitCodes?: boolean;
  requiredCommandPatterns?: string[];
}

export interface EvidencePolicyAstRules {
  requireAstEvidence?: boolean;
  disallowBreakingChanges?: boolean;
}

export interface EvidencePolicyAssertionRules {
  minAssertions?: number;
  disallowUnverifiable?: boolean;
}

export interface EvidencePolicyAttestationRules {
  requireSignature?: boolean;
  allowedFingerprints?: string[];
  requireTrustedRegistry?: boolean;
  requireNotary?: boolean;
  allowedNotaryFingerprints?: string[];
  /** Minimum number of distinct valid notary keys required to attest the bundle. */
  minNotaryCount?: number;
}

export const NotarizeEvidenceBundleSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  notaryUrl: z.string().url('notaryUrl must be a valid URL.'),
  authToken: z.string().optional(),
  timeoutMs: z.number().int().min(500).max(60000).optional(),
  allowPrivateNetwork: z.boolean().optional(),
  maxRetries: z.number().int().min(0).max(5).optional(),
  workspacePath: z.string().optional(),
});
export type NotarizeEvidenceBundleInput = z.infer<typeof NotarizeEvidenceBundleSchema>;

export interface EvidencePolicyLicenseRules {
  requireLicenseField?: boolean;
  allowedLicenses?: string[];
  disallowedLicenses?: string[];
}

export interface EvidencePolicySbomRules {
  requireSbom?: boolean;
  disallowComponentLicenses?: string[];
  blockedPackages?: string[];
  maxComponents?: number;
  requirePurls?: boolean;
}

export interface EvidencePolicySlsaRules {
  requireProvenance?: boolean;
  requireSignature?: boolean;
  allowedBuilderIds?: string[];
  minDependencies?: number;
}

export interface EvidencePolicy {
  version?: '1' | '1.0';
  description?: string;
  git?: EvidencePolicyGitRules;
  files?: EvidencePolicyFileRules;
  commands?: EvidencePolicyCommandRules;
  ast?: EvidencePolicyAstRules;
  assertions?: EvidencePolicyAssertionRules;
  attestation?: EvidencePolicyAttestationRules;
  consensus?: QuorumPolicy;
  license?: EvidencePolicyLicenseRules;
  sbom?: EvidencePolicySbomRules;
  slsa?: EvidencePolicySlsaRules;
}

export interface PolicyRuleEvaluation {
  rule: string;
  category:
    | 'git'
    | 'files'
    | 'commands'
    | 'ast'
    | 'assertions'
    | 'attestation'
    | 'consensus'
    | 'license'
    | 'sbom'
    | 'slsa';
  passed: boolean;
  message: string;
  severity: 'error' | 'warning';
  details?: Record<string, unknown>;
}

export const CaptureSbomEvidenceSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  workspaceName: z.string().optional(),
  includeDevDependencies: z.boolean().default(true),
  outputPath: z.string().optional(),
  workspacePath: z.string().optional(),
});
export type CaptureSbomEvidenceInput = z.infer<typeof CaptureSbomEvidenceSchema>;

export interface PolicyEvaluationResult {
  bundleId: string;
  passed: boolean;
  evaluatedAt: string;
  policySummary: string;
  rulesEvaluated: number;
  passedCount: number;
  failedCount: number;
  warningCount: number;
  evaluations: PolicyRuleEvaluation[];
}

export const EvaluateEvidencePolicySchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  policyPath: z.string().optional(),
  policy: z.record(z.string(), z.unknown()).optional(),
  workspacePath: z.string().optional(),
  strict: z.boolean().default(false),
});
export type EvaluateEvidencePolicyInput = z.infer<typeof EvaluateEvidencePolicySchema>;

// ==========================================
// Webhook Audit & Notification Types
// ==========================================

export interface WebhookDispatchOptions {
  bundleId: string;
  webhookUrl: string;
  secretToken?: string;
  includeProof?: boolean;
  includeReport?: boolean;
  headers?: Record<string, string>;
  timeoutMs?: number;
  allowPrivateNetwork?: boolean;
  maxRetries?: number;
  workspacePath?: string;
}

export interface WebhookAuditPayload {
  event: 'evidence_bundle.audit';
  bundleId: string;
  task: string;
  status: string;
  bundleDigest: string;
  createdAt: string;
  timestamp: string;
  bundle: EvidenceBundle;
  proof?: VerificationProof;
  policyResult?: PolicyEvaluationResult;
}

export interface WebhookDispatchResult {
  bundleId: string;
  delivered: boolean;
  webhookUrl: string;
  statusCode?: number;
  statusText?: string;
  responseBody?: string;
  signatureHeader?: string;
  durationMs: number;
  timestamp: string;
  error?: string;
}

export const DispatchWebhookAuditSchema = z.object({
  bundleId: z.string().min(1, 'bundleId is required.'),
  webhookUrl: z.string().url('Must be a valid HTTP or HTTPS URL.'),
  secretToken: z.string().optional(),
  includeProof: z.boolean().default(false),
  headers: z.record(z.string(), z.string()).optional(),
  timeoutMs: z.number().int().min(1000).max(60000).default(10000),
  workspacePath: z.string().optional(),
});
export type DispatchWebhookAuditInput = z.infer<typeof DispatchWebhookAuditSchema>;

// ==========================================
// Agent Key Registry Types (v1.0.0)
// ==========================================

export type AgentRegistryStatus = 'active' | 'revoked' | 'suspended';

export interface RegisteredAgent {
  agentId: string;
  name: string;
  role: PeerEndorsementRole | string;
  publicKeyPem: string;
  keyFingerprint: string;
  registeredAt: string;
  expiresAt?: string;
  status: AgentRegistryStatus;
  revokedAt?: string;
  revocationReason?: string;
  metadata?: Record<string, unknown>;
}

export interface AgentRegistry {
  version: '1' | '1.0';
  workspacePath: string;
  updatedAt: string;
  agents: Record<string, RegisteredAgent>;
}

export const RegisterTrustedAgentSchema = z.object({
  agentId: z.string().min(1, 'agentId is required.'),
  name: z.string().min(1, 'Agent display name is required.'),
  role: z.string().min(1, 'Agent role is required.'),
  publicKeyPem: z.string().min(1, 'PEM-encoded public key is required.'),
  expiresAt: z.string().optional(),
  metadata: z.record(z.string(), z.unknown()).optional(),
  workspacePath: z.string().optional(),
});
export type RegisterTrustedAgentInput = z.infer<typeof RegisterTrustedAgentSchema>;

export const RevokeTrustedAgentSchema = z.object({
  agentId: z.string().min(1, 'agentId is required.'),
  reason: z.string().min(1, 'Revocation reason is required.'),
  workspacePath: z.string().optional(),
});
export type RevokeTrustedAgentInput = z.infer<typeof RevokeTrustedAgentSchema>;

export const ListTrustedAgentsSchema = z.object({
  workspacePath: z.string().optional(),
  status: z.enum(['active', 'revoked', 'suspended', 'all']).default('all'),
});
export type ListTrustedAgentsInput = z.infer<typeof ListTrustedAgentsSchema>;

// ==========================================
// SARIF v2.1.0 Report Types
// ==========================================

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface SarifRuleDescriptor {
  id: string;
  name?: string;
  shortDescription: { text: string };
  defaultConfiguration?: { level: SarifLevel };
  properties?: { tags?: string[] };
}

export interface SarifPhysicalLocation {
  artifactLocation: {
    uri: string;
    uriBaseId?: string;
  };
  region?: {
    startLine: number;
    endLine?: number;
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: Array<{
    physicalLocation: SarifPhysicalLocation;
  }>;
  properties?: Record<string, unknown>;
}

export interface SarifReport {
  $schema: string;
  version: '2.1.0';
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRuleDescriptor[];
      };
    };
    invocations?: Array<{
      executionSuccessful: boolean;
      properties?: Record<string, unknown>;
    }>;
    results: SarifResult[];
  }>;
}
