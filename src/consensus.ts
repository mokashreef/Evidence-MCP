import crypto from 'node:crypto';
import {
  EvidenceBundle,
  PeerEndorsement,
  PeerEndorsementRole,
  PeerEndorsementVerdict,
  QuorumPolicy,
  QuorumResult,
} from './types.js';
import {
  canonicalStringify,
  computeKeyFingerprint,
  getOrCreateLocalKeyPair,
} from './attestation.js';
import { computeBundleDigest } from './proof.js';
import { generateId, saveBundle } from './storage.js';

/**
 * Deterministically serializes an endorsement payload for cryptographic signing.
 */
export function getCanonicalEndorsementPayload(
  endorsement: Omit<PeerEndorsement, 'signature'>
): Buffer {
  const canonicalObject: Record<string, unknown> = {
    id: endorsement.id,
    agentId: endorsement.agentId,
    role: endorsement.role,
    verdict: endorsement.verdict,
    comment: endorsement.comment,
    timestamp: endorsement.timestamp,
    bundleDigest: endorsement.bundleDigest,
    signer: {
      algorithm: endorsement.signer.algorithm,
      publicKeyPem: endorsement.signer.publicKeyPem.trim(),
      keyFingerprint: endorsement.signer.keyFingerprint,
    },
  };

  const jsonString = canonicalStringify(canonicalObject);
  return Buffer.from(jsonString, 'utf8');
}

/**
 * Creates and cryptographically signs a peer endorsement on an evidence bundle.
 */
export async function createPeerEndorsement(options: {
  bundle: EvidenceBundle;
  agentId: string;
  role: PeerEndorsementRole;
  verdict: PeerEndorsementVerdict;
  comment: string;
  privateKeyPem?: string;
  workspacePath: string;
}): Promise<PeerEndorsement> {
  const { bundle, agentId, role, verdict, comment, privateKeyPem, workspacePath } = options;

  let privKey: string;
  let pubKey: string;
  let fingerprint: string;

  if (privateKeyPem) {
    privKey = privateKeyPem;
    const pubObj = crypto.createPublicKey(privKey);
    pubKey = pubObj.export({ type: 'spki', format: 'pem' }) as string;
    fingerprint = computeKeyFingerprint(pubKey);
  } else {
    const keyPair = await getOrCreateLocalKeyPair(workspacePath);
    privKey = keyPair.privateKeyPem;
    pubKey = keyPair.publicKeyPem;
    fingerprint = keyPair.fingerprint;
  }

  const bundleDigest = computeBundleDigest(bundle);
  const endorsementId = generateId('endorse');
  const timestamp = new Date().toISOString();

  const unsignedEndorsement: Omit<PeerEndorsement, 'signature'> = {
    id: endorsementId,
    agentId,
    role,
    verdict,
    comment,
    timestamp,
    bundleDigest,
    signer: {
      algorithm: 'ed25519',
      publicKeyPem: pubKey,
      keyFingerprint: fingerprint,
    },
  };

  const canonicalPayload = getCanonicalEndorsementPayload(unsignedEndorsement);
  const signatureBuffer = crypto.sign(null, canonicalPayload, privKey);
  const signature = signatureBuffer.toString('base64');

  const completeEndorsement: PeerEndorsement = {
    ...unsignedEndorsement,
    signature,
  };

  if (!bundle.endorsements) {
    bundle.endorsements = [];
  }

  bundle.endorsements.push(completeEndorsement);
  bundle.updatedAt = new Date().toISOString();
  await saveBundle(bundle);

  return completeEndorsement;
}

/**
 * Verifies the cryptographic signature and bundle consistency of a peer endorsement.
 */
export function verifyPeerEndorsement(
  endorsement: PeerEndorsement,
  expectedBundle?: EvidenceBundle
): {
  valid: boolean;
  reason?: string;
  bundleDigestMatches?: boolean;
} {
  try {
    const { signature, ...unsignedEndorsement } = endorsement;
    const canonicalPayload = getCanonicalEndorsementPayload(unsignedEndorsement);
    const signatureBuffer = Buffer.from(signature, 'base64');

    const isSigValid = crypto.verify(
      null,
      canonicalPayload,
      endorsement.signer.publicKeyPem,
      signatureBuffer
    );

    if (!isSigValid) {
      return {
        valid: false,
        reason: `Cryptographic signature mismatch on endorsement ${endorsement.id}.`,
      };
    }

    const computedFingerprint = computeKeyFingerprint(endorsement.signer.publicKeyPem);
    if (computedFingerprint !== endorsement.signer.keyFingerprint) {
      return {
        valid: false,
        reason: `Signer key fingerprint mismatch on endorsement ${endorsement.id}: embedded ${endorsement.signer.keyFingerprint} != computed ${computedFingerprint}`,
      };
    }

    let bundleDigestMatches: boolean | undefined;
    if (expectedBundle) {
      const currentDigest = computeBundleDigest(expectedBundle);
      bundleDigestMatches = currentDigest === endorsement.bundleDigest;
      if (!bundleDigestMatches) {
        return {
          valid: false,
          bundleDigestMatches: false,
          reason: `Bundle digest mismatch on endorsement ${endorsement.id}: bundle content has changed since endorsement was signed.`,
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
      reason: `Endorsement verification error: ${(err as Error).message}`,
    };
  }
}

/**
 * Validates all peer endorsements on an evidence bundle against a consensus quorum policy.
 */
export function checkBundleQuorum(
  bundle: EvidenceBundle,
  policy: QuorumPolicy = {}
): QuorumResult {
  const {
    minEndorsements = 1,
    requiredRoles = [],
    requireUniqueSigners = true,
    disallowRejections = true,
  } = policy;

  const endorsements = bundle.endorsements || [];
  const reasons: string[] = [];

  let approvedCount = 0;
  let rejectionsCount = 0;
  let changesRequestedCount = 0;
  let verifiedSignatures = 0;

  const seenFingerprints = new Set<string>();
  const seenAgentIds = new Set<string>();
  const approvedRoles = new Set<PeerEndorsementRole>();

  for (const end of endorsements) {
    const check = verifyPeerEndorsement(end, bundle);
    if (!check.valid) {
      reasons.push(`Invalid endorsement ${end.id} from agent "${end.agentId}": ${check.reason}`);
      continue;
    }

    verifiedSignatures++;

    if (requireUniqueSigners) {
      if (seenFingerprints.has(end.signer.keyFingerprint)) {
        reasons.push(
          `Duplicate signer key detected: fingerprint ${end.signer.keyFingerprint} endorsed multiple times.`
        );
        continue;
      }
      if (seenAgentIds.has(end.agentId)) {
        reasons.push(`Duplicate agent ID detected: agent "${end.agentId}" endorsed multiple times.`);
        continue;
      }
      seenFingerprints.add(end.signer.keyFingerprint);
      seenAgentIds.add(end.agentId);
    }

    if (end.verdict === 'approved') {
      approvedCount++;
      approvedRoles.add(end.role);
    } else if (end.verdict === 'rejected') {
      rejectionsCount++;
    } else if (end.verdict === 'changes_requested') {
      changesRequestedCount++;
    }
  }

  // Quorum rule 1: Rejections
  if (disallowRejections && rejectionsCount > 0) {
    reasons.push(
      `Quorum blocked by ${rejectionsCount} explicit rejection(s) from reviewing agent(s).`
    );
  }

  // Quorum rule 2: Minimum approved endorsements
  if (approvedCount < minEndorsements) {
    reasons.push(
      `Insufficient approved endorsements: received ${approvedCount}, required at least ${minEndorsements}.`
    );
  }

  // Quorum rule 3: Required roles
  for (const role of requiredRoles) {
    if (!approvedRoles.has(role)) {
      reasons.push(`Missing required endorsement role: "${role}".`);
    }
  }

  const satisfied = reasons.length === 0 && approvedCount >= minEndorsements;

  return {
    bundleId: bundle.id,
    satisfied,
    totalEndorsements: endorsements.length,
    approvedCount,
    rejectionsCount,
    changesRequestedCount,
    verifiedSignatures,
    policy: {
      minEndorsements,
      requiredRoles,
      requireUniqueSigners,
      disallowRejections,
    },
    reasons,
    endorsements,
  };
}
