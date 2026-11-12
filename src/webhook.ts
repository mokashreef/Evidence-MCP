import crypto from 'node:crypto';
import {
  WebhookAuditPayload,
  WebhookDispatchOptions,
  WebhookDispatchResult,
} from './types.js';
import { loadBundle } from './storage.js';
import { computeBundleDigest, createVerificationProof } from './proof.js';
import { verifyEvidenceBundle } from './verifier.js';
import { validateHttpUrl, postJsonWithTimeout } from './network.js';

/**
 * Computes an HMAC-SHA256 signature for a payload using a secret token.
 */
export function computeHmacSignature(payload: string, secretToken: string): string {
  return crypto.createHmac('sha256', secretToken).update(payload, 'utf8').digest('hex');
}

/**
 * Verifies an incoming HMAC-SHA256 signature string (format: "sha256=<hex>" or raw hex).
 */
export function verifyHmacSignature(
  payload: string,
  secretToken: string,
  signatureHeader: string
): boolean {
  try {
    const expectedHex = computeHmacSignature(payload, secretToken);
    const cleanedHeader = signatureHeader.replace(/^sha256=/, '').trim();

    if (expectedHex.length !== cleanedHeader.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      Buffer.from(expectedHex, 'utf8'),
      Buffer.from(cleanedHeader, 'utf8')
    );
  } catch {
    return false;
  }
}

/**
 * Assembles and dispatches an audit webhook payload for an evidence bundle.
 */
export async function dispatchAuditWebhook(
  options: WebhookDispatchOptions
): Promise<WebhookDispatchResult> {
  const {
    bundleId,
    webhookUrl,
    secretToken,
    includeProof = false,
    headers = {},
    timeoutMs = 10000,
    allowPrivateNetwork = false,
    maxRetries,
    workspacePath,
  } = options;

  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  // Validate URL protocol and SSRF host rules
  try {
    validateHttpUrl(webhookUrl, { allowPrivateNetwork });
  } catch (err: unknown) {
    return {
      bundleId,
      delivered: false,
      webhookUrl,
      durationMs: Date.now() - startTime,
      timestamp,
      error: `Invalid webhook URL: ${(err as Error).message}`,
    };
  }

  // Load bundle
  let bundle;
  try {
    bundle = await loadBundle(bundleId, workspacePath);
  } catch (err: unknown) {
    return {
      bundleId,
      delivered: false,
      webhookUrl,
      durationMs: Date.now() - startTime,
      timestamp,
      error: `Failed to load bundle: ${(err as Error).message}`,
    };
  }

  const bundleDigest = computeBundleDigest(bundle);

  // Optional proof generation
  let proof;
  if (includeProof) {
    try {
      const verification = await verifyEvidenceBundle(bundle);
      proof = await createVerificationProof({
        bundle,
        verification,
        workspacePath: bundle.workspacePath,
      });
    } catch {
      // If proof generation fails, proceed without proof
    }
  }

  const payload: WebhookAuditPayload = {
    event: 'evidence_bundle.audit',
    bundleId: bundle.id,
    task: bundle.task,
    status: bundle.status,
    bundleDigest,
    createdAt: bundle.createdAt,
    timestamp,
    bundle,
    proof,
  };

  const payloadString = JSON.stringify(payload);

  // Prepare HTTP headers
  const requestHeaders: Record<string, string> = {
    'X-Evidence-Bundle-Id': bundle.id,
    'X-Evidence-Timestamp': timestamp,
    'X-Evidence-Event': 'evidence_bundle.audit',
    'X-Evidence-Digest': bundleDigest,
    ...headers,
  };

  let signatureHeader: string | undefined;
  if (secretToken) {
    const hmacHex = computeHmacSignature(payloadString, secretToken);
    signatureHeader = `sha256=${hmacHex}`;
    requestHeaders['X-Evidence-Signature'] = signatureHeader;
  }

  const postRes = await postJsonWithTimeout({
    url: webhookUrl,
    body: payloadString,
    headers: requestHeaders,
    timeoutMs,
    allowPrivateNetwork,
    maxRetries,
  });

  return {
    bundleId: bundle.id,
    delivered: postRes.ok,
    webhookUrl,
    statusCode: postRes.statusCode,
    statusText: postRes.statusText,
    responseBody: postRes.responseBody ? postRes.responseBody.slice(0, 2048) : undefined,
    signatureHeader,
    durationMs: Date.now() - startTime,
    timestamp,
    error: postRes.error,
  };
}
