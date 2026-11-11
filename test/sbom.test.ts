import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { captureWorkspaceSbom, buildNpmPurl } from '../src/sbom.js';
import { signEvidenceBundle, verifyBundleAttestation } from '../src/attestation.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { evaluateEvidencePolicy } from '../src/policy.js';
import { exportEvidenceReport } from '../src/reporter.js';
import { createEvidenceServer } from '../src/server.js';
import { saveBundle, generateId } from '../src/storage.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle, EvidencePolicy, SarifReport } from '../src/types.js';

describe('Signed CycloneDX SBOM Integration', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-sbom-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, {
      recursive: true,
      force: true,
      maxRetries: 5,
      retryDelay: 100,
    });
  });

  async function writeManifestAndLockfile(options?: { withDisallowed?: boolean }) {
    await fs.promises.writeFile(
      path.join(tempWorkspace, 'package.json'),
      JSON.stringify(
        {
          name: 'demo-app',
          version: '1.0.0',
          license: 'MIT',
          dependencies: {
            zod: '^4.0.0',
            '@modelcontextprotocol/sdk': '^1.32.0',
          },
          devDependencies: {
            vitest: '^5.0.0',
          },
        },
        null,
        2
      ),
      'utf8'
    );

    const packages: Record<string, unknown> = {
      '': { name: 'demo-app', version: '1.0.0', license: 'MIT' },
      'node_modules/zod': {
        version: '4.6.7',
        license: 'MIT',
        integrity: 'sha512-zodhash',
      },
      'node_modules/@modelcontextprotocol/sdk': {
        version: '1.32.2',
        license: 'MIT',
        integrity: 'sha512-mcphash',
      },
      'node_modules/vitest': {
        version: '5.0.5',
        dev: true,
        license: 'MIT',
        integrity: 'sha512-vitesthash',
      },
    };

    if (options?.withDisallowed) {
      packages['node_modules/copyleft-lib'] = {
        version: '2.1.0',
        license: 'AGPL-3.0',
      };
    }

    await fs.promises.writeFile(
      path.join(tempWorkspace, 'package-lock.json'),
      JSON.stringify({ name: 'demo-app', version: '1.0.0', lockfileVersion: 3, packages }, null, 2),
      'utf8'
    );
  }

  it('captures CycloneDX 1.5 SBOM from package.json and package-lock.json with PURL encoding', async () => {
    expect(buildNpmPurl('@scope/pkg', '1.2.3')).toBe('pkg:npm/%40scope/pkg@1.2.3');
    await writeManifestAndLockfile();

    const { evidence, cycloneDxBom } = await captureWorkspaceSbom({
      workspacePath: tempWorkspace,
      includeDevDependencies: true,
    });

    expect(evidence.id).toMatch(/^sbom_/);
    expect(evidence.format).toBe('cyclonedx-1.5');
    expect(evidence.manifestPath).toBe('package.json');
    expect(evidence.lockfilePath).toBe('package-lock.json');
    expect(evidence.componentCount).toBe(3);
    expect(evidence.licenseSummary).toEqual({ MIT: 3 });
    expect(cycloneDxBom.bomFormat).toBe('CycloneDX');
    expect(cycloneDxBom.specVersion).toBe('1.5');

    const sdkComp = evidence.components.find((c) => c.name === '@modelcontextprotocol/sdk');
    expect(sdkComp?.purl).toBe('pkg:npm/%40modelcontextprotocol/sdk@1.32.2');
    expect(sdkComp?.scope).toBe('required');

    // Excluding devDependencies filters vitest
    const prodOnly = await captureWorkspaceSbom({
      workspacePath: tempWorkspace,
      includeDevDependencies: false,
    });
    expect(prodOnly.evidence.componentCount).toBe(2);
    expect(prodOnly.evidence.components.some((c) => c.name === 'vitest')).toBe(false);
  });

  it('cryptographically signs SBOM evidence and verifies freshness against disk manifests', async () => {
    await writeManifestAndLockfile();
    const { evidence } = await captureWorkspaceSbom({ workspacePath: tempWorkspace });
    const now = new Date().toISOString();

    const bundle: EvidenceBundle = {
      id: generateId('bundle'),
      task: 'SBOM signed verification test',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        sbom: [evidence],
      },
      assertions: [
        {
          id: generateId('assert'),
          claim: 'Workspace dependencies captured in SBOM',
          evidenceIds: [evidence.id],
          createdAt: now,
        },
      ],
    };

    bundle.attestation = await signEvidenceBundle(bundle);
    await saveBundle(bundle);

    expect(verifyBundleAttestation(bundle).valid).toBe(true);

    // 1. Fresh disk state -> verified
    const okVerify = await verifyEvidenceBundle(bundle);
    expect(okVerify.status).toBe('verified');
    expect(okVerify.items.find((i) => i.id === evidence.id)?.status).toBe('verified');

    // 2. Tamper component list without updating bomDigest -> signature & verifier catch it
    const tamperedBundle: EvidenceBundle = JSON.parse(JSON.stringify(bundle));
    tamperedBundle.evidence.sbom![0].bomDigest = '0'.repeat(64);
    expect(verifyBundleAttestation(tamperedBundle).valid).toBe(false);
    const tamperedVerify = await verifyEvidenceBundle(tamperedBundle);
    expect(tamperedVerify.status).toBe('failed');

    // 3. Modify package-lock.json on disk -> marks SBOM as stale
    await fs.promises.appendFile(path.join(tempWorkspace, 'package-lock.json'), '\n', 'utf8');
    const staleVerify = await verifyEvidenceBundle(bundle);
    expect(staleVerify.status).toBe('stale');
    expect(staleVerify.items.find((i) => i.id === evidence.id)?.status).toBe('stale');
  });

  it('enforces SBOM compliance rules in evaluateEvidencePolicy and exports SARIF locations', async () => {
    await writeManifestAndLockfile({ withDisallowed: true });
    const { evidence } = await captureWorkspaceSbom({ workspacePath: tempWorkspace });
    const now = new Date().toISOString();

    const bundle: EvidenceBundle = {
      id: generateId('bundle'),
      task: 'SBOM policy evaluation',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        sbom: [evidence],
      },
      assertions: [],
    };

    const policy: EvidencePolicy = {
      sbom: {
        requireSbom: true,
        disallowComponentLicenses: ['AGPL-3.0', 'GPL-3.0'],
        blockedPackages: ['copyleft-lib'],
        maxComponents: 2,
      },
    };

    const evalRes = evaluateEvidencePolicy({ bundle, policy });
    expect(evalRes.passed).toBe(false);
    expect(evalRes.evaluations.find((e) => e.rule === 'sbom.requireSbom')?.passed).toBe(true);
    expect(evalRes.evaluations.find((e) => e.rule === 'sbom.disallowComponentLicenses')?.passed).toBe(
      false
    );
    expect(evalRes.evaluations.find((e) => e.rule === 'sbom.blockedPackages')?.passed).toBe(false);
    expect(evalRes.evaluations.find((e) => e.rule === 'sbom.maxComponents')?.passed).toBe(false);

    // Export SARIF and confirm policy violation points to package-lock.json
    const sarif = JSON.parse(exportEvidenceReport(bundle, 'sarif', undefined, undefined, evalRes)) as SarifReport;
    const sbomSarif = sarif.runs[0].results.find(
      (r) => r.ruleId === 'POLICY-SBOM-DISALLOWCOMPONENTLICENSES'
    );
    expect(sbomSarif?.locations?.[0].physicalLocation.artifactLocation.uri).toBe('package-lock.json');
  });

  it('supports MCP capture_sbom_evidence tool, CLI sbom command, and rejects traversal on outputPath', async () => {
    await writeManifestAndLockfile();
    const now = new Date().toISOString();
    const bundle: EvidenceBundle = {
      id: 'bundle_sbom_e2e',
      task: 'E2E SBOM capture',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {},
      assertions: [],
    };
    await saveBundle(bundle);

    const server = createEvidenceServer();

    // 1. Rejects path traversal on outputPath
    const badRes = await (server as any)._registeredTools['capture_sbom_evidence'].handler({
      bundleId: bundle.id,
      outputPath: '../outside.cdx.json',
      workspacePath: tempWorkspace,
    });
    expect(badRes.isError).toBe(true);
    expect(badRes.content[0].text).toContain('Path traversal rejected');

    // 2. Writes valid CycloneDX BOM file within workspace
    const goodRes = await (server as any)._registeredTools['capture_sbom_evidence'].handler({
      bundleId: bundle.id,
      outputPath: 'artifacts/bom.cdx.json',
      workspacePath: tempWorkspace,
    });
    expect(goodRes.isError).toBeUndefined();
    const parsedMcp = JSON.parse(goodRes.content[0].text);
    expect(parsedMcp.componentCount).toBe(3);
    expect(fs.existsSync(path.join(tempWorkspace, 'artifacts', 'bom.cdx.json'))).toBe(true);

    // 3. CLI sbom command
    const cliBomOut = path.join(tempWorkspace, 'cli-bom.cdx.json');
    const exitCode = await runCli([
      'sbom',
      bundle.id,
      '--no-dev',
      '--output',
      cliBomOut,
      '--workspace',
      tempWorkspace,
    ]);
    expect(exitCode).toBe(0);
    expect(fs.existsSync(cliBomOut)).toBe(true);
    const cliBom = JSON.parse(await fs.promises.readFile(cliBomOut, 'utf8'));
    expect(cliBom.bomFormat).toBe('CycloneDX');
    expect(cliBom.components.length).toBe(2);
  });
});
