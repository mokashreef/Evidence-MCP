import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import {
  notarizeEvidenceBundle,
  signNotaryAttestationPayload,
  verifyNotaryReceipt,
} from '../src/notary.js';
import { generateAgentKeyPair, signEvidenceBundle } from '../src/attestation.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { evaluateEvidencePolicy } from '../src/policy.js';
import { createEvidenceServer } from '../src/server.js';
import { saveBundle, loadBundle, generateId } from '../src/storage.js';
import { computeFileSha256AndSize } from '../src/hasher.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle, EvidencePolicy } from '../src/types.js';

describe('Remote Transparency Notary Attestation', () => {
  let tempWorkspace: string;
  let mockServer: http.Server;
  let serverPort: number;
  let notaryKeys: ReturnType<typeof generateAgentKeyPair>;
  let logSeq = 0;
  let capturedSubmissions: Array<{
    headers: http.IncomingHttpHeaders;
    body: Record<string, unknown>;
  }> = [];

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-notary-test-'));
    notaryKeys = generateAgentKeyPair();
    logSeq = 0;
    capturedSubmissions = [];

    await new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        let rawBody = '';
        req.on('data', (c) => {
          rawBody += c.toString();
        });
        req.on('end', () => {
          if (req.url === '/slow') {
            setTimeout(() => {
              res.statusCode = 200;
              res.end('{}');
            }, 3000);
            return;
          }

          if (req.url === '/fail') {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: 'Notary unavailable' }));
            return;
          }

          const parsed = JSON.parse(rawBody || '{}') as Record<string, unknown>;
          capturedSubmissions.push({ headers: req.headers, body: parsed });
          logSeq += 1;

          const receipt = signNotaryAttestationPayload({
            bundleId: String(parsed.bundleId),
            bundleDigest: String(parsed.bundleDigest),
            notaryUrl: `http://127.0.0.1:${serverPort}${req.url || '/notarize'}`,
            logIndex: logSeq,
            authorKeyFingerprint:
              typeof parsed.authorKeyFingerprint === 'string'
                ? parsed.authorKeyFingerprint
                : undefined,
            privateKeyPem: notaryKeys.privateKeyPem,
          });

          if (req.url === '/tamper-response') {
            receipt.signature = Buffer.from('corrupted-sig').toString('base64');
          }

          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify(receipt));
        });
      });

      mockServer.listen(0, '127.0.0.1', () => {
        const addr = mockServer.address() as { port: number };
        serverPort = addr.port;
        resolve();
      });
    });
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => mockServer.close(() => resolve()));
    await fs.promises.rm(tempWorkspace, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  });

  async function createVerifiedBundle(): Promise<EvidenceBundle> {
    const filePath = path.join(tempWorkspace, 'service.ts');
    await fs.promises.writeFile(filePath, 'export const secretMarker = "SENSITIVE_LOCAL_CODE";\n', 'utf8');
    const { sha256, sizeBytes } = await computeFileSha256AndSize(filePath);
    const now = new Date().toISOString();
    const fileId = generateId('file');

    const bundle: EvidenceBundle = {
      id: generateId('bundle'),
      task: 'Remote notarization verification task',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        fileSnapshots: [
          {
            id: fileId,
            type: 'file_snapshot',
            capturedAt: now,
            path: 'service.ts',
            absolutePath: filePath,
            sha256,
            sizeBytes,
          },
        ],
      },
      assertions: [
        {
          id: generateId('assert'),
          claim: 'service.ts validated',
          evidenceIds: [fileId],
          createdAt: now,
        },
      ],
    };

    bundle.attestation = await signEvidenceBundle(bundle);
    await saveBundle(bundle);
    return bundle;
  }

  it('submits anonymized bundleDigest only, verifies receipt, and detects tampering or staleness', async () => {
    const bundle = await createVerifiedBundle();
    const notaryUrl = `http://127.0.0.1:${serverPort}/notarize`;

    const res = await notarizeEvidenceBundle({
      bundleId: bundle.id,
      notaryUrl,
      authToken: 'notary-bearer-xyz',
      workspacePath: tempWorkspace,
    });

    expect(res.receipt.id).toMatch(/^notary_/);
    expect(res.receipt.logIndex).toBe(1);
    expect(res.receipt.notaryKeyFingerprint).toBe(notaryKeys.fingerprint);

    // Privacy guarantee: source code/file contents never sent to notary endpoint
    expect(capturedSubmissions.length).toBe(1);
    const sub = capturedSubmissions[0];
    expect(sub.headers['authorization']).toBe('Bearer notary-bearer-xyz');
    expect(Object.keys(sub.body).sort()).toEqual([
      'authorKeyFingerprint',
      'bundleDigest',
      'bundleId',
      'submittedAt',
    ]);
    expect(JSON.stringify(sub.body)).not.toContain('SENSITIVE_LOCAL_CODE');

    // Verify saved receipt & verifier integration
    const reloaded = await loadBundle(bundle.id, tempWorkspace);
    expect(reloaded.notaryReceipts?.length).toBe(1);
    expect(verifyNotaryReceipt(reloaded.notaryReceipts![0], reloaded).valid).toBe(true);

    const verifiedRes = await verifyEvidenceBundle(reloaded);
    expect(verifiedRes.status).toBe('verified');
    expect(verifiedRes.items.find((i) => i.id === res.receipt.id)?.status).toBe('verified');

    // If bundle changes after notarization (even if re-signed locally), remote receipt becomes stale
    const modifiedBundle: EvidenceBundle = JSON.parse(JSON.stringify(reloaded));
    modifiedBundle.task = 'Altered task after notarization';
    modifiedBundle.attestation = await signEvidenceBundle(modifiedBundle);
    const staleVerify = await verifyEvidenceBundle(modifiedBundle);
    expect(staleVerify.status).toBe('stale');
    expect(staleVerify.items.find((i) => i.id === res.receipt.id)?.status).toBe('stale');

    // If receipt signature is tampered, verifyEvidenceBundle marks it failed
    const tamperedSigBundle: EvidenceBundle = JSON.parse(JSON.stringify(reloaded));
    tamperedSigBundle.notaryReceipts![0].signature = Buffer.from('bad-sig').toString('base64');
    const failedVerify = await verifyEvidenceBundle(tamperedSigBundle);
    expect(failedVerify.status).toBe('failed');
  });

  it('rejects invalid notary signatures, HTTP failures, and network timeouts without mutating bundle', async () => {
    const bundle = await createVerifiedBundle();

    await expect(
      notarizeEvidenceBundle({
        bundleId: bundle.id,
        notaryUrl: `http://127.0.0.1:${serverPort}/tamper-response`,
        workspacePath: tempWorkspace,
      })
    ).rejects.toThrow(/invalid or mismatched receipt/i);

    await expect(
      notarizeEvidenceBundle({
        bundleId: bundle.id,
        notaryUrl: `http://127.0.0.1:${serverPort}/fail`,
        workspacePath: tempWorkspace,
      })
    ).rejects.toThrow(/HTTP error: 500/i);

    await expect(
      notarizeEvidenceBundle({
        bundleId: bundle.id,
        notaryUrl: `http://127.0.0.1:${serverPort}/slow`,
        timeoutMs: 500,
        workspacePath: tempWorkspace,
      })
    ).rejects.toThrow(/timed out/i);

    const untouched = await loadBundle(bundle.id, tempWorkspace);
    expect(untouched.notaryReceipts || []).toEqual([]);
  });

  it('enforces requireNotary and allowedNotaryFingerprints in evaluateEvidencePolicy', async () => {
    const bundle = await createVerifiedBundle();

    const policy: EvidencePolicy = {
      attestation: {
        requireNotary: true,
        allowedNotaryFingerprints: [notaryKeys.fingerprint],
      },
    };

    // Unsigned / un-notarized -> fails
    const unnotarized = evaluateEvidencePolicy({ bundle, policy });
    expect(unnotarized.passed).toBe(false);
    expect(unnotarized.evaluations.find((e) => e.rule === 'attestation.requireNotary')?.passed).toBe(
      false
    );

    // Notarize bundle -> passes
    await notarizeEvidenceBundle({
      bundleId: bundle.id,
      notaryUrl: `http://127.0.0.1:${serverPort}/notarize`,
      workspacePath: tempWorkspace,
    });
    const notarizedBundle = await loadBundle(bundle.id, tempWorkspace);

    const passedEval = evaluateEvidencePolicy({ bundle: notarizedBundle, policy });
    expect(passedEval.passed).toBe(true);
    expect(passedEval.evaluations.find((e) => e.rule === 'attestation.requireNotary')?.passed).toBe(
      true
    );
    expect(
      passedEval.evaluations.find((e) => e.rule === 'attestation.allowedNotaryFingerprints')?.passed
    ).toBe(true);

    // Wrong allowed fingerprint -> fails
    const wrongFpEval = evaluateEvidencePolicy({
      bundle: notarizedBundle,
      policy: {
        attestation: {
          requireNotary: true,
          allowedNotaryFingerprints: ['00'.repeat(32)],
        },
      },
    });
    expect(wrongFpEval.passed).toBe(false);
  });

  it('supports MCP notarize_evidence_bundle tool and CLI notarize command', async () => {
    const bundle = await createVerifiedBundle();
    const notaryUrl = `http://127.0.0.1:${serverPort}/notarize`;

    // 1. MCP Tool
    const server = createEvidenceServer();
    const mcpRes = await (server as any)._registeredTools['notarize_evidence_bundle'].handler({
      bundleId: bundle.id,
      notaryUrl,
      workspacePath: tempWorkspace,
    });
    expect(mcpRes.isError).toBeUndefined();
    const parsed = JSON.parse(mcpRes.content[0].text);
    expect(parsed.logIndex).toBe(1);
    expect(parsed.notaryKeyFingerprint).toBe(notaryKeys.fingerprint);

    // 2. CLI command
    const exitCode = await runCli([
      'notarize',
      bundle.id,
      notaryUrl,
      '--token',
      'cli-tok',
      '--workspace',
      tempWorkspace,
    ]);
    expect(exitCode).toBe(0);

    const updated = await loadBundle(bundle.id, tempWorkspace);
    expect(updated.notaryReceipts?.length).toBe(2);
    expect(updated.notaryReceipts?.[1].logIndex).toBe(2);
  });
});
