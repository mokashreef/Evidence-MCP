import crypto from 'node:crypto';
import {
  WebhookAuditPayload,
  WebhookDispatchOptions,
  WebhookDispatchResult,
} from './types.js';
import { loadBundle } from './storage.js';
import { computeBundleDigest, createVerificationProof } from './proof.js';
import { verifyEvidenceBundle } from './verifier.js';

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
    workspacePath,
  } = options;

  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  // Validate URL protocol
  try {
    const parsedUrl = new URL(webhookUrl);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      throw new Error(`Webhook URL must use http: or https: protocol (received "${parsedUrl.protocol}").`);
    }
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
    'Content-Type': 'application/json',
    'User-Agent': 'Evidence-MCP/0.9.0',
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

  // Dispatch HTTP POST request with timeout
  const controller = new AbortController();
  const timeoutTimer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(webhookUrl, {
      method: 'POST',
      headers: requestHeaders,
      body: payloadString,
      signal: controller.signal,
    });

    clearTimeout(timeoutTimer);
    const durationMs = Date.now() - startTime;
    const responseBody = await response.text();

    const delivered = response.ok; // 200..299
    return {
      bundleId: bundle.id,
      delivered,
      webhookUrl,
      statusCode: response.status,
      statusText: response.statusText,
      responseBody: responseBody.slice(0, 2048), // cap preview
      signatureHeader,
      durationMs,
      timestamp,
      error: delivered ? undefined : `HTTP error: ${response.status} ${response.statusText}`,
    };
  } catch (err: unknown) {
    clearTimeout(timeoutTimer);
    const durationMs = Date.now() - startTime;
    const isAbort = (err as Error).name === 'AbortError';
    const errorMessage = isAbort
      ? `Webhook delivery timed out after ${timeoutMs}ms.`
      : `Network error: ${(err as Error).message}`;

    return {
      bundleId: bundle.id,
      delivered: false,
      webhookUrl,
      signatureHeader,
      durationMs,
      timestamp,
      error: errorMessage,
    };
  }
}
