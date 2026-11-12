import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  generateSlsaProvenance,
  verifySlsaProvenanceSignature,
  IN_TOTO_STATEMENT_V1_TYPE,
  SLSA_PROVENANCE_V1_PREDICATE_TYPE,
  SlsaProvenanceEnvelope,
} from '../src/slsa.js';
import { generateAgentKeyPair } from '../src/attestation.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { captureWorkspaceSbom } from '../src/sbom.js';
import { signNotaryAttestationPayload } from '../src/notary.js';
import { computeBundleDigest } from '../src/proof.js';
import { saveBundle, generateId } from '../src/storage.js';
import { createEvidenceServer } from '../src/server.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle } from '../src/types.js';

describe('SLSA v1.0 Provenance Attestation Export', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-slsa-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  });

  async function createRichBundle(): Promise<EvidenceBundle> {
    await fs.promises.mkdir(path.join(tempWorkspace, 'dist'), { recursive: true });
    const artifactA = path.join(tempWorkspace, 'dist', 'index.js');
    await fs.promises.writeFile(artifactA, 'export const build = 1;\n', 'utf8');
    const artifactHash = await computeFileSha256AndSize(artifactA);

    await fs.promises.writeFile(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify({ name: 'slsa-demo', version: '1.0.0', dependencies: { zod: '^4.0.0' } }),
      'utf8'
    );
    const { evidence: sbomEv } = await captureWorkspaceSbom({ workspacePath: tempWorkspace });

    const now = new Date().toISOString();
    const bundle: EvidenceBundle = {
      id: generateId('bundle'),
      task: 'Build & attest release artifacts',
      workspacePath: tempWorkspace,
      status: 'verified',
      createdAt: now,
      updatedAt: now,
      evidence: {
        git: [
          {
            id: generateId('git'),
            branch: 'main',
            headCommit: 'abcdef1234567890abcdef1234567890abcdef12',
            statusShort: '',
            diffCheck: '',
            isClean: true,
            capturedAt: now,
          },
        ],
        fileSnapshots: [
          {
            id: generateId('file'),
            path: 'dist/index.js',
            sha256: artifactHash.sha256,
            sizeBytes: artifactHash.sizeBytes,
            capturedAt: now,
          },
        ],
        commands: [
          {
            id: generateId('cmd'),
            command: 'npm run build',
            exitCode: 0,
            stdout: 'ok',
            stderr: '',
            durationMs: 120,
            executedAt: now,
            provenance: 'server_executed',
          },
        ],
        sbom: [sbomEv],
      },
      assertions: [],
    };

    const notaryKeys = generateAgentKeyPair();
    bundle.notaryReceipts = [
      signNotaryAttestationPayload({
        bundleId: bundle.id,
        bundleDigest: computeBundleDigest(bundle),
        notaryUrl: 'https://notary.example.com/v1/log',
        logIndex: 42,
        privateKeyPem: notaryKeys.privateKeyPem,
      }),
    ];

    await saveBundle(bundle);
    return bundle;
  }

  it('generates a compliant signed SLSA v1.0 in-toto statement and detects tampering', async () => {
    const bundle = await createRichBundle();
    const signer = generateAgentKeyPair();

    const envelope = await generateSlsaProvenance({
      bundle,
      builderId: 'https://ci.example.com/runners/github-hosted',
      privateKeyPem: signer.privateKeyPem,
    });

    expect(envelope.statement._type).toBe(IN_TOTO_STATEMENT_V1_TYPE);
    expect(envelope.statement.predicateType).toBe(SLSA_PROVENANCE_V1_PREDICATE_TYPE);
    expect(envelope.statement.subject).toHaveLength(1);
    expect(envelope.statement.subject[0].name).toBe('dist/index.js');
    expect(envelope.statement.subject[0].digest.sha256).toMatch(/^[a-f0-9]{64}$/);

    // Resolved dependencies include Git source + npm PURL dependency
    const deps = envelope.statement.predicate.buildDefinition.resolvedDependencies;
    expect(deps.some((d) => d.digest?.gitCommit === 'abcdef1234567890abcdef1234567890abcdef12')).toBe(
      true
    );
    expect(deps.some((d) => d.uri === 'pkg:npm/zod@4.0.0')).toBe(true);

    // Byproducts include command + notary receipt
    const byproducts = envelope.statement.predicate.runDetails.byproducts || [];
    expect(byproducts.some((b) => b.name === 'npm run build')).toBe(true);
    expect(byproducts.some((b) => b.name?.startsWith('notary-receipt:'))).toBe(true);

    // Verify signature
    const verified = verifySlsaProvenanceSignature(envelope);
    expect(verified.valid).toBe(true);
    expect(verified.keyFingerprint).toBe(signer.fingerprint);

    // Tamper subject -> rejected by both digest and signature check
    const tampered: SlsaProvenanceEnvelope = JSON.parse(JSON.stringify(envelope));
    tampered.statement.subject[0].digest.sha256 = '0'.repeat(64);
    expect(verifySlsaProvenanceSignature(tampered).valid).toBe(false);

    // Tamper digest field -> also rejected
    tampered.statementDigest = 'f'.repeat(64);
    expect(verifySlsaProvenanceSignature(tampered).valid).toBe(false);
  });

  it('uses deterministic bundle fallback subject when bundle has no file snapshots', async () => {
    const now = new Date().toISOString();
    const emptyBundle: EvidenceBundle = {
      id: 'bundle_empty_slsa',
      task: 'Minimal provenance',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {},
      assertions: [],
    };
    await saveBundle(emptyBundle);

    const unsigned = await generateSlsaProvenance({
      bundle: emptyBundle,
      includeSignature: false,
    });
    expect(unsigned.statement.subject).toEqual([
      {
        name: 'evidence-bundle://bundle_empty_slsa',
        digest: { sha256: computeBundleDigest(emptyBundle) },
      },
    ]);
    expect(unsigned.signature).toBeUndefined();
    expect(verifySlsaProvenanceSignature(unsigned).valid).toBe(false);
  });

  it('supports MCP export_slsa_provenance tool, rejects path traversal, and supports CLI slsa command', async () => {
    const bundle = await createRichBundle();
    const server = createEvidenceServer();

    // Reject path traversal
    const badRes = await (server as any)._registeredTools['export_slsa_provenance'].handler({
      bundleId: bundle.id,
      outputPath: '../escape-slsa.json',
      sign: true,
      workspacePath: tempWorkspace,
    });
    expect(badRes.isError).toBe(true);
    expect(badRes.content[0].text).toContain('Path traversal rejected');

    // Valid MCP export
    const goodRes = await (server as any)._registeredTools['export_slsa_provenance'].handler({
      bundleId: bundle.id,
      outputPath: 'artifacts/release.slsa.json',
      sign: true,
      workspacePath: tempWorkspace,
    });
    expect(goodRes.isError).toBeUndefined();
    const mcpParsed = JSON.parse(goodRes.content[0].text);
    expect(mcpParsed.signed).toBe(true);
    expect(mcpParsed.subjectCount).toBe(1);
    const writtenJson = JSON.parse(
      await fs.promises.readFile(path.join(tempWorkspace, 'artifacts', 'release.slsa.json'), 'utf8')
    ) as SlsaProvenanceEnvelope;
    expect(verifySlsaProvenanceSignature(writtenJson).valid).toBe(true);

    // CLI export
    const cliOut = path.join(tempWorkspace, 'cli-provenance.intoto.json');
    const exitCode = await runCli([
      'slsa',
      bundle.id,
      '--output',
      cliOut,
      '--workspace',
      tempWorkspace,
    ]);
    expect(exitCode).toBe(0);
    const cliEnvelope = JSON.parse(await fs.promises.readFile(cliOut, 'utf8')) as SlsaProvenanceEnvelope;
    expect(verifySlsaProvenanceSignature(cliEnvelope).valid).toBe(true);
  });
});
