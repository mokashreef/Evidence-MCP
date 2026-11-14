import crypto from 'node:crypto';
import {
  EvidenceBundle,
  RekorEntryReceipt,
  RekorInclusionProof,
} from './types.js';
import { computeBundleDigest } from './proof.js';
import { loadBundle, saveBundle } from './storage.js';
import { postJsonWithTimeout } from './network.js';
import { signEvidenceBundle } from './attestation.js';

export const DEFAULT_REKOR_URL = 'https://rekor.sigstore.dev';

export interface SubmitRekorOptions {
  bundleId: string;
  bundle?: EvidenceBundle;
  rekorUrl?: string;
  timeoutMs?: number;
  allowPrivateNetwork?: boolean;
  maxRetries?: number;
  workspacePath?: string;
}

export interface VerifyRekorOptions {
  receipt: RekorEntryReceipt;
  bundle: EvidenceBundle;
}

export interface VerifyRekorResult {
  valid: boolean;
  reason?: string;
  inclusionVerified?: boolean;
  leafHash?: string;
  rootHash?: string;
}

/**
 * Cryptographically verifies an RFC 6962 Merkle tree inclusion proof.
 * Used for offline verification of transparency log entries (Certificate Transparency / Rekor).
 *
 * @param leafHashHex 32-byte leaf hash in hexadecimal
 * @param leafIndex 0-based leaf index in tree
 * @param treeSize Total number of leaves in tree
 * @param proofHashesHex Audit path hashes from leaf to root
 * @param expectedRootHex Expected tree root hash from checkpoint / signed tree head
 */
export function verifyRfc6962InclusionProof(
  leafHashHex: string,
  leafIndex: number,
  treeSize: number,
  proofHashesHex: string[],
  expectedRootHex: string
): boolean {
  if (!leafHashHex || !expectedRootHex) {
    return false;
  }
  if (leafIndex >= treeSize || leafIndex < 0 || treeSize < 1) {
    return false;
  }

  try {
    let fn = leafIndex;
    let sn = treeSize - 1;
    let r = Buffer.from(leafHashHex, 'hex');

    for (const p of proofHashesHex) {
      if (sn === 0) {
        return false;
      }
      const pBuf = Buffer.from(p, 'hex');
      if (fn % 2 === 1 || fn === sn) {
        // r is right child
        r = crypto
          .createHash('sha256')
          .update(Buffer.concat([Buffer.from([0x01]), pBuf, r]))
          .digest();
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      } else {
        // r is left child
        r = crypto
          .createHash('sha256')
          .update(Buffer.concat([Buffer.from([0x01]), r, pBuf]))
          .digest();
      }
      fn = Math.floor(fn / 2);
      sn = Math.floor(sn / 2);
    }

    if (sn !== 0) {
      return false;
    }

    return r.toString('hex').toLowerCase() === expectedRootHex.toLowerCase();
  } catch {
    return false;
  }
}

/**
 * Builds standard Rekor v0.0.1 hashedrekord proposal entry payload.
 */
export function buildHashedRekordPayload(options: {
  bundleDigest: string;
  signatureBase64: string;
  publicKeyBase64: string;
}): Record<string, unknown> {
  return {
    apiVersion: '0.0.1',
    kind: 'hashedrekord',
    spec: {
      data: {
        hash: {
          algorithm: 'sha256',
          value: options.bundleDigest,
        },
      },
      signature: {
        content: options.signatureBase64,
        publicKey: {
          content: options.publicKeyBase64,
        },
      },
    },
  };
}

/**
 * Submits an evidence bundle's cryptographic digest and attestation signature to a Sigstore Rekor transparency log.
 */
export async function submitRekorLogEntry(
  options: SubmitRekorOptions
): Promise<{ receipt: RekorEntryReceipt; alreadyExists: boolean }> {
  const {
    bundleId,
    rekorUrl = DEFAULT_REKOR_URL,
    timeoutMs = 15000,
    allowPrivateNetwork = false,
    maxRetries = 2,
    workspacePath,
  } = options;

  const bundle = options.bundle || (await loadBundle(bundleId, workspacePath));

  // Ensure bundle is cryptographically signed
  if (!bundle.attestation) {
    bundle.attestation = await signEvidenceBundle(bundle);
    await saveBundle(bundle);
  }

  if (!bundle.attestation) {
    throw new Error('Bundle must be cryptographically signed before submitting to Rekor transparency log.');
  }

  const bundleDigest = computeBundleDigest(bundle);
  const sigBase64 = Buffer.from(bundle.attestation.signature, 'hex').toString('base64');
  const pubKeyBase64 = Buffer.from(bundle.attestation.publicKeyPem, 'utf8').toString('base64');

  const proposedEntry = buildHashedRekordPayload({
    bundleDigest,
    signatureBase64: sigBase64,
    publicKeyBase64: pubKeyBase64,
  });

  const normalizedUrl = rekorUrl.replace(/\/+$/, '');
  const targetUrl = `${normalizedUrl}/api/v1/log/entries`;

  const httpRes = await postJsonWithTimeout({
    url: targetUrl,
    body: JSON.stringify(proposedEntry),
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    timeoutMs,
    allowPrivateNetwork,
    maxRetries,
  });

  if (!httpRes.ok || !httpRes.responseBody) {
    const errText = httpRes.responseBody || httpRes.error || `HTTP ${httpRes.statusCode}`;
    throw new Error(`Rekor log entry submission failed: ${errText}`);
  }

  let parsedResponse: Record<string, unknown>;
  try {
    parsedResponse = JSON.parse(httpRes.responseBody);
  } catch (err: unknown) {
    throw new Error(`Invalid JSON response from Rekor log: ${(err as Error).message}`);
  }

  const receipt = parseRekorResponse(parsedResponse, bundle.id, bundleDigest, normalizedUrl);
  const alreadyExists = httpRes.statusCode === 200 || httpRes.statusCode === 409;

  // Append to bundle rekorEntries avoiding duplicates
  if (!bundle.rekorEntries) {
    bundle.rekorEntries = [];
  }
  const existingIdx = bundle.rekorEntries.findIndex((r) => r.uuid === receipt.uuid);
  if (existingIdx >= 0) {
    bundle.rekorEntries[existingIdx] = receipt;
  } else {
    bundle.rekorEntries.push(receipt);
  }
  await saveBundle(bundle);

  return { receipt, alreadyExists };
}

/**
 * Parses a Rekor entry response map into a structured RekorEntryReceipt.
 */
export function parseRekorResponse(
  responseMap: Record<string, unknown>,
  bundleId: string,
  bundleDigest: string,
  rekorUrl: string
): RekorEntryReceipt {
  const keys = Object.keys(responseMap);
  if (keys.length === 0) {
    throw new Error('Empty response map returned by Rekor server.');
  }

  const uuid = keys[0];
  const entry = responseMap[uuid] as Record<string, unknown>;
  if (!entry) {
    throw new Error(`Malformed Rekor entry data for UUID: ${uuid}`);
  }

  const logIndex = typeof entry.logIndex === 'number' ? entry.logIndex : 0;
  const logID = typeof entry.logID === 'string' ? entry.logID : '';
  const integratedTime = typeof entry.integratedTime === 'number' ? entry.integratedTime : Math.floor(Date.now() / 1000);

  const verification = (entry.verification as Record<string, unknown>) || {};
  const signedEntryTimestamp = typeof verification.signedEntryTimestamp === 'string'
    ? verification.signedEntryTimestamp
    : '';

  let inclusionProof: RekorInclusionProof | undefined;
  if (verification.inclusionProof && typeof verification.inclusionProof === 'object') {
    const inc = verification.inclusionProof as Record<string, unknown>;
    inclusionProof = {
      logIndex: typeof inc.logIndex === 'number' ? inc.logIndex : logIndex,
      rootHash: typeof inc.rootHash === 'string' ? inc.rootHash : '',
      treeSize: typeof inc.treeSize === 'number' ? inc.treeSize : 0,
      hashes: Array.isArray(inc.hashes) ? (inc.hashes as string[]) : [],
      checkpoint: typeof inc.checkpoint === 'string' ? inc.checkpoint : undefined,
    };
  }

  return {
    uuid,
    bundleId,
    bundleDigest,
    rekorUrl,
    logIndex,
    logID,
    integratedTime,
    signedEntryTimestamp,
    inclusionProof,
    recordedAt: new Date().toISOString(),
  };
}

/**
 * Cryptographically verifies a Rekor entry receipt against live bundle contents and Merkle proof.
 */
export function verifyRekorEntryReceipt(options: VerifyRekorOptions): VerifyRekorResult {
  const { receipt, bundle } = options;

  if (!receipt) {
    return { valid: false, reason: 'Rekor entry receipt is missing or undefined.' };
  }

  if (receipt.bundleId !== bundle.id) {
    return {
      valid: false,
      reason: `Rekor receipt bundleId mismatch: expected "${bundle.id}", found "${receipt.bundleId}".`,
    };
  }

  const currentDigest = computeBundleDigest(bundle);
  if (receipt.bundleDigest !== currentDigest) {
    return {
      valid: false,
      reason: `Rekor receipt bundle digest mismatch: bundle was modified after Rekor logging. (receipt=${receipt.bundleDigest.slice(0, 16)}..., current=${currentDigest.slice(0, 16)}...)`,
    };
  }

  if (!receipt.uuid || receipt.uuid.trim() === '') {
    return { valid: false, reason: 'Rekor receipt missing entry UUID.' };
  }

  if (receipt.inclusionProof) {
    const proof = receipt.inclusionProof;
    if (!proof.rootHash || proof.treeSize < 1) {
      return { valid: false, reason: 'Rekor inclusion proof is incomplete (missing rootHash or treeSize < 1).' };
    }

    // Leaf hash in Rekor is typically the 64-character entry hash (first 64 chars of uuid)
    const leafHash = receipt.uuid.slice(0, 64);
    const proofValid = verifyRfc6962InclusionProof(
      leafHash,
      proof.logIndex,
      proof.treeSize,
      proof.hashes,
      proof.rootHash
    );

    if (!proofValid) {
      return {
        valid: false,
        reason: `Rekor Merkle tree inclusion proof verification failed against root hash "${proof.rootHash}".`,
        inclusionVerified: false,
        leafHash,
        rootHash: proof.rootHash,
      };
    }

    return {
      valid: true,
      inclusionVerified: true,
      leafHash,
      rootHash: proof.rootHash,
    };
  }

  return {
    valid: true,
    inclusionVerified: false,
  };
}
