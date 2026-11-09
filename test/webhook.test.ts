import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import http from 'node:http';
import {
  computeHmacSignature,
  verifyHmacSignature,
  dispatchAuditWebhook,
} from '../src/webhook.js';
import { EvidenceBundle } from '../src/types.js';
import { saveBundle } from '../src/storage.js';
import { runCli } from '../src/cli.js';

describe('Webhook Audit & Notification System', () => {
  let tempWorkspace: string;
  let mockServer: http.Server;
  let serverPort: number;
  let receivedRequests: Array<{
    method: string;
    headers: http.IncomingHttpHeaders;
    body: string;
  }> = [];

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-webhook-test-'));
    receivedRequests = [];

    // Spin up an in-process mock HTTP server
    await new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => {
          body += chunk.toString();
        });
        req.on('end', () => {
          receivedRequests.push({
            method: req.method || 'GET',
            headers: req.headers,
            body,
          });

          if (req.url === '/fail') {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: 'Internal Server Error' }));
          } else if (req.url === '/slow') {
            // Intentionally don't respond immediately
            setTimeout(() => {
              res.statusCode = 200;
              res.end(JSON.stringify({ ok: true }));
            }, 3000);
          } else {
            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ ok: true, received: true }));
          }
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
    await new Promise<void>((resolve) => {
      mockServer.close(() => resolve());
    });
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('HMAC Signature Verification', () => {
    it('computes and verifies HMAC-SHA256 signatures accurately', () => {
      const secret = 'super-secret-token-123';
      const payload = JSON.stringify({ task: 'Verify Audit', bundleId: 'bundle_123' });

      const sig = computeHmacSignature(payload, secret);
      expect(sig).toMatch(/^[a-f0-9]{64}$/);

      // Verify with sha256= prefix and without
      expect(verifyHmacSignature(payload, secret, `sha256=${sig}`)).toBe(true);
      expect(verifyHmacSignature(payload, secret, sig)).toBe(true);

      // Tampered payload fails
      expect(verifyHmacSignature(payload + 'tampered', secret, sig)).toBe(false);

      // Wrong secret fails
      expect(verifyHmacSignature(payload, 'wrong-secret', sig)).toBe(false);
    });
  });

  describe('Webhook Delivery', () => {
    function createMockBundle(): EvidenceBundle {
      const now = new Date().toISOString();
      return {
        id: 'bundle_webtest1',
        task: 'Webhook Dispatch Task',
        workspacePath: tempWorkspace,
        status: 'completed',
        createdAt: now,
        updatedAt: now,
        evidence: {
          git: [],
          commands: [],
          fileSnapshots: [],
        },
        assertions: [],
      };
    }

    it('successfully delivers audit payload with HMAC signature to target endpoint', async () => {
      const bundle = createMockBundle();
      await saveBundle(bundle);

      const secret = 'ci-webhook-secret';
      const targetUrl = `http://127.0.0.1:${serverPort}/webhook`;

      const result = await dispatchAuditWebhook({
        bundleId: bundle.id,
        webhookUrl: targetUrl,
        secretToken: secret,
        workspacePath: tempWorkspace,
      });

      expect(result.delivered).toBe(true);
      expect(result.statusCode).toBe(200);
      expect(result.signatureHeader).toMatch(/^sha256=[a-f0-9]{64}$/);

      expect(receivedRequests.length).toBe(1);
      const req = receivedRequests[0];
      expect(req.headers['x-evidence-bundle-id']).toBe(bundle.id);
      expect(req.headers['x-evidence-signature']).toBe(result.signatureHeader);

      const parsedPayload = JSON.parse(req.body);
      expect(parsedPayload.event).toBe('evidence_bundle.audit');
      expect(parsedPayload.bundleId).toBe(bundle.id);
      expect(parsedPayload.bundle.task).toBe('Webhook Dispatch Task');

      // Verify HMAC on received body
      expect(verifyHmacSignature(req.body, secret, req.headers['x-evidence-signature'] as string)).toBe(true);
    });

    it('handles HTTP error responses from webhook server gracefully', async () => {
      const bundle = createMockBundle();
      await saveBundle(bundle);

      const targetUrl = `http://127.0.0.1:${serverPort}/fail`;

      const result = await dispatchAuditWebhook({
        bundleId: bundle.id,
        webhookUrl: targetUrl,
        workspacePath: tempWorkspace,
      });

      expect(result.delivered).toBe(false);
      expect(result.statusCode).toBe(500);
      expect(result.error).toContain('HTTP error: 500');
    });

    it('handles connection timeout safely using AbortController', async () => {
      const bundle = createMockBundle();
      await saveBundle(bundle);

      const targetUrl = `http://127.0.0.1:${serverPort}/slow`;

      const result = await dispatchAuditWebhook({
        bundleId: bundle.id,
        webhookUrl: targetUrl,
        timeoutMs: 500, // fast timeout
        workspacePath: tempWorkspace,
      });

      expect(result.delivered).toBe(false);
      expect(result.error).toMatch(/timed out/i);
    });
  });

  describe('CLI Integration', () => {
    it('executes evidence-mcp webhook CLI command against endpoint', async () => {
      const now = new Date().toISOString();
      const bundle: EvidenceBundle = {
        id: 'bundle_cliwh1',
        task: 'CLI Webhook Task',
        workspacePath: tempWorkspace,
        status: 'in_progress',
        createdAt: now,
        updatedAt: now,
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      const targetUrl = `http://127.0.0.1:${serverPort}/webhook`;
      const exitCode = await runCli([
        'webhook',
        bundle.id,
        targetUrl,
        '--secret',
        'cli-secret',
        '--workspace',
        tempWorkspace,
      ]);

      expect(exitCode).toBe(0);
      expect(receivedRequests.length).toBe(1);
    });
  });
});
