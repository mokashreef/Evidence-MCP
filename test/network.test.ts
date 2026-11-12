import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import http from 'node:http';
import {
  isPrivateIpAddress,
  isRestrictedHostname,
  validateHttpUrl,
  postJsonWithTimeout,
} from '../src/network.js';

describe('Network Hardening (SSRF Protection & Exponential Backoff)', () => {
  let mockServer: http.Server;
  let serverPort: number;
  let requestCounter = 0;

  beforeEach(async () => {
    requestCounter = 0;
    await new Promise<void>((resolve) => {
      mockServer = http.createServer((req, res) => {
        requestCounter += 1;

        if (req.url === '/flaky-503') {
          if (requestCounter < 3) {
            res.statusCode = 503;
            res.end(JSON.stringify({ error: 'Temporarily unavailable' }));
            return;
          }
          res.statusCode = 200;
          res.setHeader('Content-Type', 'application/json');
          res.end(JSON.stringify({ ok: true, attempt: requestCounter }));
          return;
        }

        if (req.url === '/rate-limit-429') {
          if (requestCounter === 1) {
            res.statusCode = 429;
            res.end(JSON.stringify({ error: 'Too many requests' }));
            return;
          }
          res.statusCode = 200;
          res.end(JSON.stringify({ recovered: true }));
          return;
        }

        if (req.url === '/bad-request-400') {
          res.statusCode = 400;
          res.end(JSON.stringify({ error: 'Malformed payload' }));
          return;
        }

        res.statusCode = 500;
        res.end(JSON.stringify({ error: 'Persistent failure' }));
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
  });

  it('detects private, loopback, link-local, metadata, and IPv4-mapped IPv6 addresses', () => {
    expect(isPrivateIpAddress('127.0.0.1')).toBe(true);
    expect(isPrivateIpAddress('10.0.0.42')).toBe(true);
    expect(isPrivateIpAddress('172.16.5.1')).toBe(true);
    expect(isPrivateIpAddress('172.31.255.254')).toBe(true);
    expect(isPrivateIpAddress('192.168.1.10')).toBe(true);
    expect(isPrivateIpAddress('169.254.169.254')).toBe(true);
    expect(isPrivateIpAddress('100.64.0.1')).toBe(true);
    expect(isPrivateIpAddress('0.0.0.0')).toBe(true);
    expect(isPrivateIpAddress('::1')).toBe(true);
    expect(isPrivateIpAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isPrivateIpAddress('::ffff:7f00:1')).toBe(true);
    expect(isPrivateIpAddress('fd12:3456:789a::1')).toBe(true);
    expect(isPrivateIpAddress('fe80::1')).toBe(true);

    // Public IPs remain allowed
    expect(isPrivateIpAddress('8.8.8.8')).toBe(false);
    expect(isPrivateIpAddress('1.1.1.1')).toBe(false);
    expect(isPrivateIpAddress('172.32.0.1')).toBe(false);
    expect(isPrivateIpAddress('2606:4700:4700::1111')).toBe(false);

    expect(isRestrictedHostname('localhost')).toBe(true);
    expect(isRestrictedHostname('sub.localhost')).toBe(true);
    expect(isRestrictedHostname('metadata.google.internal')).toBe(true);
    expect(isRestrictedHostname('printer.local')).toBe(true);
    expect(isRestrictedHostname('notary.example.com')).toBe(false);
  });

  it('blocks SSRF targets, embedded credentials, and non-HTTP schemes by default', async () => {
    expect(() => validateHttpUrl('file:///etc/passwd')).toThrow(/http: or https:/i);
    expect(() => validateHttpUrl('https://user:pass@example.com/hook')).toThrow(/credentials/i);
    expect(() => validateHttpUrl('http://169.254.169.254/latest/meta-data/')).toThrow(/Blocked private/i);
    expect(() => validateHttpUrl('http://127.0.0.1:8080/hook')).toThrow(/Blocked private/i);
    expect(() => validateHttpUrl('http://[::1]:8080/hook')).toThrow(/Blocked private/i);
    expect(() => validateHttpUrl('http://localhost:3000/notarize')).toThrow(/Blocked private/i);

    // Explicit opt-in permits local endpoints
    const parsedLocal = validateHttpUrl('http://127.0.0.1:8080/hook', {
      allowPrivateNetwork: true,
    });
    expect(parsedLocal.hostname).toBe('127.0.0.1');

    // Public HTTPS URL validates cleanly without opt-in
    const parsedPublic = validateHttpUrl('https://notary.example.com/v1/log');
    expect(parsedPublic.hostname).toBe('notary.example.com');

    // postJsonWithTimeout blocks loopback/metadata immediately with 0 network attempts
    const blockedRes = await postJsonWithTimeout({
      url: `http://127.0.0.1:${serverPort}/flaky-503`,
      body: '{}',
    });
    expect(blockedRes.ok).toBe(false);
    expect(blockedRes.attempts).toBe(0);
    expect(blockedRes.error).toMatch(/Blocked private/i);
    expect(requestCounter).toBe(0);
  });

  it('retries transient 503 and 429 failures with backoff and recovers', async () => {
    const recovered503 = await postJsonWithTimeout({
      url: `http://127.0.0.1:${serverPort}/flaky-503`,
      body: JSON.stringify({ test: true }),
      allowPrivateNetwork: true,
      maxRetries: 2,
      retryDelayMs: 15,
    });
    expect(recovered503.ok).toBe(true);
    expect(recovered503.statusCode).toBe(200);
    expect(recovered503.attempts).toBe(3);
    expect(requestCounter).toBe(3);

    requestCounter = 0;
    const recovered429 = await postJsonWithTimeout({
      url: `http://127.0.0.1:${serverPort}/rate-limit-429`,
      body: '{}',
      allowPrivateNetwork: true,
      maxRetries: 1,
      retryDelayMs: 15,
    });
    expect(recovered429.ok).toBe(true);
    expect(recovered429.attempts).toBe(2);
  });

  it('does not retry non-retryable 4xx responses and bounds maxRetries on persistent 500', async () => {
    const clientErr = await postJsonWithTimeout({
      url: `http://127.0.0.1:${serverPort}/bad-request-400`,
      body: '{}',
      allowPrivateNetwork: true,
      maxRetries: 3,
      retryDelayMs: 10,
    });
    expect(clientErr.ok).toBe(false);
    expect(clientErr.statusCode).toBe(400);
    expect(clientErr.attempts).toBe(1);
    expect(requestCounter).toBe(1);

    requestCounter = 0;
    const serverErr = await postJsonWithTimeout({
      url: `http://127.0.0.1:${serverPort}/fail-500`,
      body: '{}',
      allowPrivateNetwork: true,
      maxRetries: 2,
      retryDelayMs: 10,
    });
    expect(serverErr.ok).toBe(false);
    expect(serverErr.statusCode).toBe(500);
    expect(serverErr.attempts).toBe(3);
    expect(requestCounter).toBe(3);
  });
});
