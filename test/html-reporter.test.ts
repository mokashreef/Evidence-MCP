import { describe, it, expect } from 'vitest';
import { exportEvidenceReport, escapeHtml } from '../src/reporter.js';
import { EvidenceBundle, VerificationResult } from '../src/types.js';

describe('HTML Report Generation & Security Escaping', () => {
  it('correctly escapes dangerous HTML characters to prevent XSS', () => {
    const raw = '<script>alert("xss & \'injection\'")</script>';
    const escaped = escapeHtml(raw);
    expect(escaped).toBe('&lt;script&gt;alert(&quot;xss &amp; &#39;injection&#39;&quot;)&lt;/script&gt;');
    expect(escaped).not.toContain('<script>');
  });

  it('generates a complete, self-contained HTML report with responsive styling', () => {
    const bundle: EvidenceBundle = {
      id: 'bundle_html_test',
      task: 'Implement <secure> authentication feature & token check',
      workspacePath: 'D:/Projects/App',
      status: 'verified',
      createdAt: '2026-11-07T12:00:00Z',
      updatedAt: '2026-11-07T12:05:00Z',
      evidence: {
        git: [
          {
            id: 'git_1',
            type: 'git',
            capturedAt: '2026-11-07T12:01:00Z',
            branch: 'feat/auth',
            headCommit: 'abcdef1234567890',
            statusShort: 'M src/auth.ts',
            diffCheck: 'clean',
            isClean: false,
          },
        ],
        fileSnapshots: [
          {
            id: 'file_1',
            type: 'file_snapshot',
            capturedAt: '2026-11-07T12:02:00Z',
            path: 'src/auth.ts',
            absolutePath: 'D:/Projects/App/src/auth.ts',
            sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            sizeBytes: 1024,
          },
        ],
        commands: [
          {
            id: 'cmd_1',
            type: 'command',
            recordedAt: '2026-11-07T12:03:00Z',
            command: 'npm test -- auth.test.ts',
            exitCode: 0,
            stdout: 'PASS test/auth.test.ts\n✓ token parsed successfully',
            stderr: '',
            provenance: 'agent_reported',
          },
        ],
      },
      assertions: [
        {
          id: 'assert_1',
          claim: 'Token parsed & verified <securely>',
          evidenceIds: ['file_1', 'cmd_1'],
          createdAt: '2026-11-07T12:04:00Z',
        },
      ],
    };

    const verification: VerificationResult = {
      bundleId: bundle.id,
      status: 'verified',
      verifiedAt: '2026-11-07T12:06:00Z',
      summary: 'All assertions are backed by independently verified evidence.',
      reasons: [],
      items: [
        {
          id: 'file_1',
          type: 'file',
          status: 'verified',
          details: 'SHA-256 match and size 1024 bytes',
        },
        {
          id: 'cmd_1',
          type: 'command',
          status: 'unverifiable',
          details: 'Agent-reported execution record',
        },
        {
          id: 'assert_1',
          type: 'assertion',
          status: 'verified',
          details: 'Supported by independently verified evidence',
        },
      ],
    };

    const html = exportEvidenceReport(bundle, 'html', verification);

    // Verify HTML structure
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('<html lang="en">');
    expect(html).toContain('Evidence Bundle: <code>bundle_html_test</code>');
    expect(html).toContain('Implement &lt;secure&gt; authentication feature &amp; token check');
    expect(html).toContain('VERIFIED');

    // Verify escaped content
    expect(html).not.toContain('<secure>');
    expect(html).toContain('&lt;secure&gt;');

    // Verify evidence components
    expect(html).toContain('feat/auth');
    expect(html).toContain('src/auth.ts');
    expect(html).toContain('npm test -- auth.test.ts');
    expect(html).toContain('agent_reported');
    expect(html).toContain('Verification Details');
    expect(html).toContain('badge-success');
    expect(html).toContain('badge-info');
  });
});
