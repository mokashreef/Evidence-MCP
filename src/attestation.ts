import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { BundleAttestation, EvidenceBundle } from './types.js';
import { getEvidenceDir } from './storage.js';

export interface KeyPairResult {
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprint: string;
}

/**
 * Computes a SHA-256 fingerprint for a PEM-encoded public key.
 */
export function computeKeyFingerprint(publicKeyPem: string): string {
  const cleanKey = publicKeyPem
    .replace(/-----BEGIN [A-Z ]+-----/g, '')
    .replace(/-----END [A-Z ]+-----/g, '')
    .replace(/\s+/g, '');
  return crypto.createHash('sha256').update(cleanKey).digest('hex');
}

/**
 * Generates an Ed25519 keypair for bundle signing.
 */
export function generateAgentKeyPair(): KeyPairResult {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const fingerprint = computeKeyFingerprint(publicKey);

  return {
    publicKeyPem: publicKey,
    privateKeyPem: privateKey,
    fingerprint,
  };
}

/**
 * Retrieves or generates an agent keypair stored locally under .evidence-mcp/keys/.
 */
export async function getOrCreateLocalKeyPair(workspacePath: string): Promise<KeyPairResult> {
  const keysDir = path.join(getEvidenceDir(workspacePath), 'keys');
  const privPath = path.join(keysDir, 'agent.key');
  const pubPath = path.join(keysDir, 'agent.pub');

  if (fs.existsSync(privPath) && fs.existsSync(pubPath)) {
    const privateKeyPem = await fs.promises.readFile(privPath, 'utf8');
    const publicKeyPem = await fs.promises.readFile(pubPath, 'utf8');
    const fingerprint = computeKeyFingerprint(publicKeyPem);
    return { privateKeyPem, publicKeyPem, fingerprint };
  }

  await fs.promises.mkdir(keysDir, { recursive: true });
  const keyPair = generateAgentKeyPair();

  await fs.promises.writeFile(privPath, keyPair.privateKeyPem, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.writeFile(pubPath, keyPair.publicKeyPem, { encoding: 'utf8', mode: 0o644 });

  return keyPair;
}

/**
 * Deterministically serializes a bundle into a canonical JSON representation for signing.
 * Recursively sorts all object keys and excludes dynamic metadata (attestation, updatedAt).
 */
export function getCanonicalPayload(bundle: EvidenceBundle): Buffer {
  const canonicalObject: Record<string, unknown> = {
    id: bundle.id,
    task: bundle.task,
    workspacePath: path.resolve(bundle.workspacePath).replace(/\\/g, '/'),
    workspaces: bundle.workspaces || { root: path.resolve(bundle.workspacePath).replace(/\\/g, '/') },
    createdAt: bundle.createdAt,
    evidence: {
      git: (bundle.evidence.git || []).map((g) => ({
        id: g.id,
        branch: g.branch,
        headCommit: g.headCommit,
        statusShort: g.statusShort,
        diffCheck: g.diffCheck,
        isClean: g.isClean,
      })),
      commands: (bundle.evidence.commands || []).map((c) => ({
        id: c.id,
        command: c.command,
        exitCode: c.exitCode,
        stdout: c.stdout,
        stderr: c.stderr,
        provenance: c.provenance,
      })),
      fileSnapshots: (bundle.evidence.fileSnapshots || []).map((f) => ({
        id: f.id,
        path: f.path.replace(/\\/g, '/'),
        sha256: f.sha256,
        sizeBytes: f.sizeBytes,
      })),
      ast: (bundle.evidence.ast || []).map((a) => ({
        id: a.id,
        filePath: a.filePath.replace(/\\/g, '/'),
        language: a.language,
        symbolsCount: a.symbolsCount,
      })),
    },
    assertions: (bundle.assertions || []).map((a) => ({
      id: a.id,
      claim: a.claim,
      evidenceIds: [...a.evidenceIds].sort(),
    })),
  };

  if (bundle.evidence.sbom && bundle.evidence.sbom.length > 0) {
    (canonicalObject.evidence as Record<string, unknown>).sbom = bundle.evidence.sbom.map((s) => ({
      id: s.id,
      format: s.format,
      manifestPath: s.manifestPath.replace(/\\/g, '/'),
      manifestSha256: s.manifestSha256,
      lockfilePath: s.lockfilePath ? s.lockfilePath.replace(/\\/g, '/') : null,
      lockfileSha256: s.lockfileSha256 || null,
      componentCount: s.componentCount,
      bomDigest: s.bomDigest,
    }));
  }

  const jsonString = canonicalStringify(canonicalObject);
  return Buffer.from(jsonString, 'utf8');
}

/**
 * Canonical JSON stringifier that sorts all keys alphabetically.
 */
export function canonicalStringify(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return `[${obj.map((item) => canonicalStringify(item)).join(',')}]`;
  }

  const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
  const pairs = sortedKeys.map((key) => {
    const val = (obj as Record<string, unknown>)[key];
    return `${JSON.stringify(key)}:${canonicalStringify(val)}`;
  });

  return `{${pairs.join(',')}}`;
}

/**
 * Signs an evidence bundle using Ed25519 and returns the attestation metadata.
 */
export async function signEvidenceBundle(
  bundle: EvidenceBundle,
  privateKeyPem?: string
): Promise<BundleAttestation> {
  let privPem: string;
  let pubPem: string;

  if (privateKeyPem) {
    privPem = privateKeyPem;
    const privKeyObj = crypto.createPrivateKey(privateKeyPem);
    const pubKeyObj = crypto.createPublicKey(privKeyObj);
    pubPem = pubKeyObj.export({ type: 'spki', format: 'pem' }) as string;
  } else {
    const localKeys = await getOrCreateLocalKeyPair(bundle.workspacePath);
    privPem = localKeys.privateKeyPem;
    pubPem = localKeys.publicKeyPem;
  }

  const payload = getCanonicalPayload(bundle);
  const signatureBuffer = crypto.sign(null, payload, privPem);
  const signatureBase64 = signatureBuffer.toString('base64');
  const keyFingerprint = computeKeyFingerprint(pubPem);

  const attestation: BundleAttestation = {
    algorithm: 'ed25519',
    publicKeyPem: pubPem,
    keyFingerprint,
    signedAt: new Date().toISOString(),
    signature: signatureBase64,
  };

  bundle.attestation = attestation;
  return attestation;
}

/**
 * Verifies whether the bundle attestation signature matches its canonical content.
 */
export function verifyBundleAttestation(bundle: EvidenceBundle): { valid: boolean; reason?: string } {
  if (!bundle.attestation) {
    return { valid: false, reason: 'Bundle has no cryptographic attestation.' };
  }

  const { algorithm, publicKeyPem, signature } = bundle.attestation;

  if (algorithm !== 'ed25519') {
    return { valid: false, reason: `Unsupported attestation algorithm: ${algorithm}` };
  }

  try {
    const payload = getCanonicalPayload(bundle);
    const signatureBuffer = Buffer.from(signature, 'base64');
    const isValid = crypto.verify(null, payload, publicKeyPem, signatureBuffer);

    if (!isValid) {
      return {
        valid: false,
        reason: 'Cryptographic signature mismatch: bundle content has been modified after signing.',
      };
    }

    return { valid: true };
  } catch (err: unknown) {
    return {
      valid: false,
      reason: `Signature verification error: ${(err as Error).message}`,
    };
  }
}
