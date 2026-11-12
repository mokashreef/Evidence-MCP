import crypto from 'node:crypto';
import { EvidenceBundle, NotaryReceipt } from './types.js';
import { canonicalStringify, computeKeyFingerprint } from './attestation.js';
import { computeBundleDigest } from './proof.js';
import { generateId, loadBundle, saveBundle } from './storage.js';
import { validateHttpUrl, postJsonWithTimeout } from './network.js';

export type UnsignedNotaryPayload = {
  id: string;
  bundleId: string;
  bundleDigest: string;
  notaryUrl: string;
  logIndex: number;
  merkleLeafHash: string;
  notarizedAt: string;
  authorKeyFingerprint?: string;
};

/**
 * Produces a deterministic canonical JSON buffer over notary receipt claims
 * for Ed25519 signing and verification.
 */
export function getCanonicalNotaryPayload(payload: UnsignedNotaryPayload): Buffer {
  const canonicalObject: Record<string, unknown> = {
    id: payload.id,
    bundleId: payload.bundleId,
    bundleDigest: payload.bundleDigest,
    notaryUrl: payload.notaryUrl,
    logIndex: payload.logIndex,
    merkleLeafHash: payload.merkleLeafHash,
    notarizedAt: payload.notarizedAt,
    authorKeyFingerprint: payload.authorKeyFingerprint || null,
  };
  return Buffer.from(canonicalStringify(canonicalObject), 'utf8');
}

/**
 * Signs a transparency notary receipt payload using an Ed25519 private key.
 * Useful for compliant remote notary endpoints and verification harnesses.
 */
export function signNotaryAttestationPayload(options: {
  id?: string;
  bundleId: string;
  bundleDigest: string;
  notaryUrl: string;
  logIndex: number;
  notarizedAt?: string;
  authorKeyFingerprint?: string;
  privateKeyPem: string;
}): NotaryReceipt {
  const id = options.id || generateId('notary');
  const notarizedAt = options.notarizedAt || new Date().toISOString();
  const merkleLeafHash = crypto
    .createHash('sha256')
    .update(`${options.bundleDigest}:${options.logIndex}:${notarizedAt}`, 'utf8')
    .digest('hex');

  const privKeyObj = crypto.createPrivateKey(options.privateKeyPem);
  const pubKeyObj = crypto.createPublicKey(privKeyObj);
  const notaryPublicKeyPem = (pubKeyObj.export({ type: 'spki', format: 'pem' }) as string).trim();
  const notaryKeyFingerprint = computeKeyFingerprint(notaryPublicKeyPem);

  const unsignedPayload: UnsignedNotaryPayload = {
    id,
    bundleId: options.bundleId,
    bundleDigest: options.bundleDigest,
    notaryUrl: options.notaryUrl,
    logIndex: options.logIndex,
    merkleLeafHash,
    notarizedAt,
    authorKeyFingerprint: options.authorKeyFingerprint,
  };

  const payloadBuf = getCanonicalNotaryPayload(unsignedPayload);
  const signature = crypto.sign(null, payloadBuf, options.privateKeyPem).toString('base64');

  return {
    ...unsignedPayload,
    notaryPublicKeyPem,
    notaryKeyFingerprint,
    algorithm: 'ed25519',
    signature,
  };
}

/**
 * Verifies the cryptographic signature, notary key fingerprint, and optional
 * live bundle digest consistency of a transparency notary receipt.
 */
export function verifyNotaryReceipt(
  receipt: NotaryReceipt,
  expectedBundle?: EvidenceBundle
): {
  valid: boolean;
  bundleDigestMatches?: boolean;
  reason?: string;
} {
  try {
    if (receipt.algorithm !== 'ed25519') {
      return {
        valid: false,
        reason: `Unsupported notary signature algorithm "${receipt.algorithm}".`,
      };
    }

    const computedFingerprint = computeKeyFingerprint(receipt.notaryPublicKeyPem);
    if (computedFingerprint !== receipt.notaryKeyFingerprint) {
      return {
        valid: false,
        reason: `Notary key fingerprint mismatch: declared ${receipt.notaryKeyFingerprint} != computed ${computedFingerprint}.`,
      };
    }

    const payloadBuf = getCanonicalNotaryPayload({
      id: receipt.id,
      bundleId: receipt.bundleId,
      bundleDigest: receipt.bundleDigest,
      notaryUrl: receipt.notaryUrl,
      logIndex: receipt.logIndex,
      merkleLeafHash: receipt.merkleLeafHash,
      notarizedAt: receipt.notarizedAt,
      authorKeyFingerprint: receipt.authorKeyFingerprint,
    });

    const isSigValid = crypto.verify(
      null,
      payloadBuf,
      receipt.notaryPublicKeyPem,
      Buffer.from(receipt.signature, 'base64')
    );

    if (!isSigValid) {
      return {
        valid: false,
        reason: `Cryptographic signature invalid on notary receipt "${receipt.id}".`,
      };
    }

    let bundleDigestMatches: boolean | undefined;
    if (expectedBundle) {
      if (expectedBundle.id !== receipt.bundleId) {
        return {
          valid: false,
          bundleDigestMatches: false,
          reason: `Notary receipt belongs to bundle "${receipt.bundleId}", not "${expectedBundle.id}".`,
        };
      }
      const currentDigest = computeBundleDigest(expectedBundle);
      bundleDigestMatches = currentDigest === receipt.bundleDigest;
      if (!bundleDigestMatches) {
        return {
          valid: false,
          bundleDigestMatches: false,
          reason: `Notary receipt "${receipt.id}" is stale: bundle digest changed since notarization.`,
        };
      }
    }

    return {
      valid: true,
      bundleDigestMatches,
    };
  } catch (err: unknown) {
    return {
      valid: false,
      reason: `Notary receipt verification error: ${(err as Error).message}`,
    };
  }
}

/**
 * Anchors an evidence bundle's SHA-256 digest to a remote transparency notary service
 * (sending zero workspace files or secrets) and persists the verified signed receipt.
 */
export async function notarizeEvidenceBundle(options: {
  bundleId: string;
  notaryUrl: string;
  authToken?: string;
  timeoutMs?: number;
  allowPrivateNetwork?: boolean;
  maxRetries?: number;
  workspacePath?: string;
}): Promise<{
  receipt: NotaryReceipt;
  bundleDigest: string;
  durationMs: number;
}> {
  const {
    bundleId,
    notaryUrl,
    authToken,
    timeoutMs = 10000,
    allowPrivateNetwork = false,
    maxRetries,
    workspacePath,
  } = options;

  validateHttpUrl(notaryUrl, { allowPrivateNetwork });
  const bundle = await loadBundle(bundleId, workspacePath);
  const bundleDigest = computeBundleDigest(bundle);

  const submissionPayload = {
    bundleId: bundle.id,
    bundleDigest,
    authorKeyFingerprint: bundle.attestation?.keyFingerprint,
    submittedAt: new Date().toISOString(),
  };

  const headers: Record<string, string> = {
    'X-Evidence-Bundle-Id': bundle.id,
    'X-Evidence-Digest': bundleDigest,
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const res = await postJsonWithTimeout({
    url: notaryUrl,
    body: JSON.stringify(submissionPayload),
    headers,
    timeoutMs,
    allowPrivateNetwork,
    maxRetries,
  });

  if (!res.ok) {
    throw new Error(`Notary request failed: ${res.error || `HTTP ${res.statusCode}`}`);
  }

  let rawReceipt: Partial<NotaryReceipt>;
  try {
    rawReceipt = JSON.parse(res.responseBody || '{}') as Partial<NotaryReceipt>;
  } catch (err: unknown) {
    throw new Error(`Invalid JSON receipt from notary endpoint: ${(err as Error).message}`);
  }

  if (
    !rawReceipt.signature ||
    !rawReceipt.notaryPublicKeyPem ||
    !rawReceipt.notarizedAt ||
    typeof rawReceipt.logIndex !== 'number' ||
    !rawReceipt.merkleLeafHash
  ) {
    throw new Error(
      'Notary server response missing required signed receipt fields (signature, notaryPublicKeyPem, notarizedAt, logIndex, merkleLeafHash).'
    );
  }

  const receipt: NotaryReceipt = {
    id: rawReceipt.id || generateId('notary'),
    bundleId: rawReceipt.bundleId || bundle.id,
    bundleDigest: rawReceipt.bundleDigest || bundleDigest,
    notaryUrl: rawReceipt.notaryUrl || notaryUrl,
    notaryPublicKeyPem: rawReceipt.notaryPublicKeyPem.trim(),
    notaryKeyFingerprint:
      rawReceipt.notaryKeyFingerprint || computeKeyFingerprint(rawReceipt.notaryPublicKeyPem),
    algorithm: 'ed25519',
    logIndex: rawReceipt.logIndex,
    merkleLeafHash: rawReceipt.merkleLeafHash,
    notarizedAt: rawReceipt.notarizedAt,
    signature: rawReceipt.signature,
    authorKeyFingerprint: rawReceipt.authorKeyFingerprint ?? bundle.attestation?.keyFingerprint,
  };

  const verification = verifyNotaryReceipt(receipt, bundle);
  if (!verification.valid) {
    throw new Error(
      `Notary returned an invalid or mismatched receipt: ${verification.reason}`
    );
  }

  if (!bundle.notaryReceipts) {
    bundle.notaryReceipts = [];
  }
  bundle.notaryReceipts.push(receipt);
  await saveBundle(bundle);

  return {
    receipt,
    bundleDigest,
    durationMs: res.durationMs,
  };
}
