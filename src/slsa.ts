import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import {
  EvidenceBundle,
  SlsaSubject,
  SlsaResourceDescriptor,
  SlsaProvenanceStatement,
  SlsaProvenanceSignature,
  SlsaProvenanceEnvelope,
} from './types.js';
import {
  canonicalStringify,
  computeKeyFingerprint,
  getOrCreateLocalKeyPair,
} from './attestation.js';
import { computeBundleDigest } from './proof.js';
import { buildNpmPurl } from './sbom.js';

export const IN_TOTO_STATEMENT_V1_TYPE = 'https://in-toto.io/Statement/v1';
export const SLSA_PROVENANCE_V1_PREDICATE_TYPE = 'https://slsa.dev/provenance/v1';

function normalizeHashDigest(integrity?: string): Record<string, string> | undefined {
  if (!integrity) return undefined;
  if (/^[a-f0-9]{64}$/i.test(integrity)) {
    return { sha256: integrity.toLowerCase() };
  }
  if (integrity.startsWith('sha512-')) {
    return { sha512: integrity.slice('sha512-'.length) };
  }
  if (integrity.startsWith('sha256-')) {
    return { sha256: integrity.slice('sha256-'.length) };
  }
  return undefined;
}

/**
 * Generates an in-toto v1 / SLSA v1.0 Provenance attestation statement (and optional Ed25519 signature)
 * directly from an EvidenceBundle's captured file snapshots, Git commits, runner commands, SBOMs, and notary receipts.
 */
export async function generateSlsaProvenance(options: {
  bundle: EvidenceBundle;
  builderId?: string;
  buildType?: string;
  privateKeyPem?: string;
  includeSignature?: boolean;
}): Promise<SlsaProvenanceEnvelope> {
  const {
    bundle,
    builderId = 'https://github.com/mokashreef/Evidence-MCP/builder/v1',
    buildType = 'https://evidence-mcp.dev/attestation/v1',
    privateKeyPem,
    includeSignature = true,
  } = options;

  const bundleDigest = computeBundleDigest(bundle);

  // 1. Assemble artifact subjects (file snapshots sorted deterministically, or bundle subject fallback)
  const snapshotSubjects: SlsaSubject[] = (bundle.evidence.fileSnapshots || [])
    .map((f) => ({
      name: f.path.replace(/\\/g, '/'),
      digest: { sha256: f.sha256 },
    }))
    .sort((a, b) => a.name.localeCompare(b.name));

  const subject: SlsaSubject[] =
    snapshotSubjects.length > 0
      ? snapshotSubjects
      : [
          {
            name: `evidence-bundle://${bundle.id}`,
            digest: { sha256: bundleDigest },
          },
        ];

  // 2. Resolved dependencies (Git sources + SBOM components)
  const resolvedDependencies: SlsaResourceDescriptor[] = [];

  for (const gitEv of bundle.evidence.git || []) {
    const repoBase = path.resolve(bundle.workspacePath).replace(/\\/g, '/');
    resolvedDependencies.push({
      uri: `git+file://${repoBase}`,
      name: gitEv.workspaceName || 'root',
      digest: { gitCommit: gitEv.headCommit },
      annotations: {
        branch: gitEv.branch,
        isClean: gitEv.isClean,
      },
    });
  }

  for (const sbomEv of bundle.evidence.sbom || []) {
    for (const comp of sbomEv.components) {
      const digest = normalizeHashDigest(comp.integrity);
      resolvedDependencies.push({
        uri: comp.purl || buildNpmPurl(comp.name, comp.version),
        name: comp.name,
        ...(digest ? { digest } : {}),
        annotations: {
          version: comp.version,
          scope: comp.scope || 'required',
          ...(comp.license ? { license: comp.license } : {}),
        },
      });
    }
  }

  // 3. Byproducts (server-executed commands + anchored remote notary receipts)
  const byproducts: SlsaResourceDescriptor[] = [];

  for (const cmd of bundle.evidence.commands || []) {
    const cmdHash = crypto
      .createHash('sha256')
      .update(canonicalStringify({ id: cmd.id, command: cmd.command, exitCode: cmd.exitCode, provenance: cmd.provenance }))
      .digest('hex');

    byproducts.push({
      name: cmd.command,
      mediaType: 'application/json',
      digest: { sha256: cmdHash },
      annotations: {
        id: cmd.id,
        exitCode: cmd.exitCode,
        provenance: cmd.provenance,
      },
    });
  }

  for (const receipt of bundle.notaryReceipts || []) {
    byproducts.push({
      name: `notary-receipt:${receipt.id}`,
      uri: receipt.notaryUrl,
      digest: { sha256: receipt.merkleLeafHash },
      annotations: {
        logIndex: receipt.logIndex,
        notaryKeyFingerprint: receipt.notaryKeyFingerprint,
        notarizedAt: receipt.notarizedAt,
      },
    });
  }

  const latestGit = bundle.evidence.git?.[bundle.evidence.git.length - 1];

  const statement: SlsaProvenanceStatement = {
    _type: IN_TOTO_STATEMENT_V1_TYPE,
    subject,
    predicateType: SLSA_PROVENANCE_V1_PREDICATE_TYPE,
    predicate: {
      buildDefinition: {
        buildType,
        externalParameters: {
          bundleId: bundle.id,
          task: bundle.task,
          bundleStatus: bundle.status,
          ...(latestGit ? { gitBranch: latestGit.branch, gitCommit: latestGit.headCommit } : {}),
        },
        internalParameters: {
          bundleDigest,
          platform: os.platform(),
          arch: os.arch(),
          nodeVersion: process.version,
        },
        resolvedDependencies,
      },
      runDetails: {
        builder: {
          id: builderId,
          version: {
            'evidence-mcp': '1.4.0',
          },
        },
        metadata: {
          invocationId: bundle.id,
          startedOn: bundle.createdAt,
          finishedOn: bundle.updatedAt,
        },
        ...(byproducts.length > 0 ? { byproducts } : {}),
      },
    },
  };

  const canonicalBytes = Buffer.from(canonicalStringify(statement), 'utf8');
  const statementDigest = crypto.createHash('sha256').update(canonicalBytes).digest('hex');

  if (!includeSignature) {
    return {
      statement,
      statementDigest,
    };
  }

  let privPem: string;
  let pubPem: string;
  if (privateKeyPem) {
    privPem = privateKeyPem;
    const privObj = crypto.createPrivateKey(privPem);
    const pubObj = crypto.createPublicKey(privObj);
    pubPem = pubObj.export({ type: 'spki', format: 'pem' }) as string;
  } else {
    const keys = await getOrCreateLocalKeyPair(bundle.workspacePath);
    privPem = keys.privateKeyPem;
    pubPem = keys.publicKeyPem;
  }

  const sigBuffer = crypto.sign(null, canonicalBytes, privPem);

  return {
    statement,
    statementDigest,
    signature: {
      algorithm: 'ed25519',
      publicKeyPem: pubPem.trim(),
      keyFingerprint: computeKeyFingerprint(pubPem),
      signedAt: new Date().toISOString(),
      signature: sigBuffer.toString('base64'),
    },
  };
}

/**
 * Cryptographically verifies a signed SLSA Provenance Envelope against its canonical in-toto Statement.
 */
export function verifySlsaProvenanceSignature(envelope: SlsaProvenanceEnvelope): {
  valid: boolean;
  reason?: string;
  keyFingerprint?: string;
} {
  if (!envelope?.statement) {
    return { valid: false, reason: 'SLSA provenance envelope missing statement.' };
  }

  if (envelope.statement._type !== IN_TOTO_STATEMENT_V1_TYPE) {
    return { valid: false, reason: `Unsupported statement _type: ${envelope.statement._type}` };
  }

  if (envelope.statement.predicateType !== SLSA_PROVENANCE_V1_PREDICATE_TYPE) {
    return {
      valid: false,
      reason: `Unsupported predicateType: ${envelope.statement.predicateType}`,
    };
  }

  const canonicalBytes = Buffer.from(canonicalStringify(envelope.statement), 'utf8');
  const expectedDigest = crypto.createHash('sha256').update(canonicalBytes).digest('hex');

  if (envelope.statementDigest && envelope.statementDigest !== expectedDigest) {
    return {
      valid: false,
      reason: 'Statement digest mismatch: provenance statement was modified after export.',
    };
  }

  if (!envelope.signature) {
    return { valid: false, reason: 'SLSA provenance envelope is unsigned.' };
  }

  if (envelope.signature.algorithm !== 'ed25519') {
    return {
      valid: false,
      reason: `Unsupported SLSA signature algorithm: ${envelope.signature.algorithm}`,
    };
  }

  try {
    const computedFp = computeKeyFingerprint(envelope.signature.publicKeyPem);
    if (computedFp !== envelope.signature.keyFingerprint) {
      return {
        valid: false,
        reason: 'SLSA signer public key fingerprint mismatch.',
      };
    }

    const sigBuf = Buffer.from(envelope.signature.signature, 'base64');
    const verified = crypto.verify(null, canonicalBytes, envelope.signature.publicKeyPem, sigBuf);
    if (!verified) {
      return {
        valid: false,
        reason: 'SLSA provenance Ed25519 signature verification failed.',
      };
    }

    return {
      valid: true,
      keyFingerprint: computedFp,
    };
  } catch (err: unknown) {
    return {
      valid: false,
      reason: `SLSA signature verification error: ${(err as Error).message}`,
    };
  }
}
