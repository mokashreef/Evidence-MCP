import fs from 'node:fs';
import crypto from 'node:crypto';
import { SbomComponent, SbomEvidence } from './types.js';
import { assertSafeFilePath } from './security.js';
import { computeFileSha256AndSize } from './hasher.js';
import { canonicalStringify } from './attestation.js';
import { generateId } from './storage.js';

/**
 * Generates a PURL (Package URL) identifier compliant with the npm purl specification.
 */
export function buildNpmPurl(name: string, version: string): string {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encodedName}@${version}`;
}

/**
 * Computes a deterministic SHA-256 digest over a sorted SBOM component list.
 */
export function computeSbomDigest(components: SbomComponent[]): string {
  const normalized = [...components]
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version))
    .map((c) => ({
      name: c.name,
      version: c.version,
      scope: c.scope || 'required',
      license: c.license || null,
      integrity: c.integrity || null,
    }));
  const payload = canonicalStringify(normalized);
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

function extractPkgNameFromLockPath(lockKey: string): string {
  const idx = lockKey.lastIndexOf('node_modules/');
  if (idx === -1) return lockKey;
  return lockKey.slice(idx + 'node_modules/'.length);
}

function collectLockfileV1Components(
  deps: Record<string, unknown>,
  includeDev: boolean,
  map: Map<string, SbomComponent>
): void {
  for (const [name, entry] of Object.entries(deps)) {
    if (!entry || typeof entry !== 'object') continue;
    const rec = entry as Record<string, unknown>;
    const version = typeof rec.version === 'string' ? rec.version : undefined;
    const isDev = rec.dev === true;
    const isOptional = rec.optional === true;

    if (version && (includeDev || !isDev)) {
      const key = `${name}@${version}`;
      if (!map.has(key)) {
        map.set(key, {
          name,
          version,
          purl: buildNpmPurl(name, version),
          scope: isDev ? 'dev' : isOptional ? 'optional' : 'required',
          integrity: typeof rec.integrity === 'string' ? rec.integrity : undefined,
        });
      }
    }

    if (rec.dependencies && typeof rec.dependencies === 'object') {
      collectLockfileV1Components(rec.dependencies as Record<string, unknown>, includeDev, map);
    }
  }
}

function extractLicenseString(rawLicense: unknown): string | undefined {
  if (typeof rawLicense === 'string') {
    return rawLicense.trim() || undefined;
  }
  if (rawLicense && typeof rawLicense === 'object') {
    const typeVal = (rawLicense as Record<string, unknown>).type;
    if (typeof typeVal === 'string') {
      return typeVal.trim() || undefined;
    }
  }
  return undefined;
}

/**
 * Generates a CycloneDX v1.5 compliant SBOM JSON document from SbomEvidence.
 */
export function generateCycloneDxDocument(
  evidence: SbomEvidence,
  rootName = 'workspace-root',
  rootVersion = '0.0.0'
): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: evidence.capturedAt,
      tools: [
        {
          vendor: 'Evidence MCP',
          name: 'evidence-mcp',
          version: '1.3.0',
        },
      ],
      component: {
        type: 'application',
        name: rootName,
        version: rootVersion,
      },
    },
    components: evidence.components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      scope: c.scope === 'dev' ? 'excluded' : c.scope === 'optional' ? 'optional' : 'required',
      purl: c.purl || buildNpmPurl(c.name, c.version),
      ...(c.license ? { licenses: [{ license: { id: c.license } }] } : {}),
      ...(c.integrity ? { hashes: [{ alg: 'SHA-512', content: c.integrity }] } : {}),
    })),
  };
}

/**
 * Inspects workspace manifests (package.json + optional package-lock.json) within
 * strict path boundaries to assemble verifiable CycloneDX SBOM evidence.
 */
export async function captureWorkspaceSbom(options: {
  workspacePath: string;
  workspaceName?: string;
  includeDevDependencies?: boolean;
}): Promise<{
  evidence: SbomEvidence;
  cycloneDxBom: Record<string, unknown>;
}> {
  const { workspacePath, workspaceName, includeDevDependencies = true } = options;

  const manifestSafe = assertSafeFilePath(workspacePath, 'package.json');
  if (!fs.existsSync(manifestSafe.absolutePath)) {
    throw new Error(`No package.json found at workspace root: ${manifestSafe.absolutePath}`);
  }

  const manifestHash = await computeFileSha256AndSize(manifestSafe.absolutePath);
  const manifestRaw = await fs.promises.readFile(manifestSafe.absolutePath, 'utf8');
  const manifestJson = JSON.parse(manifestRaw) as Record<string, unknown>;

  const rootName = typeof manifestJson.name === 'string' ? manifestJson.name : 'workspace-root';
  const rootVersion = typeof manifestJson.version === 'string' ? manifestJson.version : '0.0.0';

  const componentMap = new Map<string, SbomComponent>();

  let lockfilePath: string | undefined;
  let lockfileSha256: string | undefined;

  const lockSafe = assertSafeFilePath(workspacePath, 'package-lock.json');
  if (fs.existsSync(lockSafe.absolutePath)) {
    const lockHash = await computeFileSha256AndSize(lockSafe.absolutePath);
    lockfilePath = lockSafe.relativePath;
    lockfileSha256 = lockHash.sha256;

    const lockRaw = await fs.promises.readFile(lockSafe.absolutePath, 'utf8');
    const lockJson = JSON.parse(lockRaw) as Record<string, unknown>;

    if (lockJson.packages && typeof lockJson.packages === 'object') {
      const pkgs = lockJson.packages as Record<string, Record<string, unknown>>;
      for (const [pkgKey, meta] of Object.entries(pkgs)) {
        if (!pkgKey || !pkgKey.startsWith('node_modules/')) continue;
        if (!meta || meta.link === true) continue;
        const version = typeof meta.version === 'string' ? meta.version : undefined;
        if (!version) continue;

        const isDev = meta.dev === true;
        const isOptional = meta.optional === true;
        if (!includeDevDependencies && isDev) continue;

        const name = extractPkgNameFromLockPath(pkgKey);
        const dedupeKey = `${name}@${version}`;
        if (!componentMap.has(dedupeKey)) {
          componentMap.set(dedupeKey, {
            name,
            version,
            purl: buildNpmPurl(name, version),
            scope: isDev ? 'dev' : isOptional ? 'optional' : 'required',
            license: extractLicenseString(meta.license),
            integrity: typeof meta.integrity === 'string' ? meta.integrity : undefined,
          });
        }
      }
    } else if (lockJson.dependencies && typeof lockJson.dependencies === 'object') {
      collectLockfileV1Components(
        lockJson.dependencies as Record<string, unknown>,
        includeDevDependencies,
        componentMap
      );
    }
  } else {
    // Fallback to declared package.json dependencies when no lockfile exists
    const deps =
      manifestJson.dependencies && typeof manifestJson.dependencies === 'object'
        ? (manifestJson.dependencies as Record<string, unknown>)
        : {};
    for (const [name, ver] of Object.entries(deps)) {
      if (typeof ver !== 'string') continue;
      const cleanVer = ver.replace(/^[\^~>=<\s]+/, '') || ver;
      componentMap.set(`${name}@${cleanVer}`, {
        name,
        version: cleanVer,
        purl: buildNpmPurl(name, cleanVer),
        scope: 'required',
      });
    }

    if (includeDevDependencies && manifestJson.devDependencies && typeof manifestJson.devDependencies === 'object') {
      const devDeps = manifestJson.devDependencies as Record<string, unknown>;
      for (const [name, ver] of Object.entries(devDeps)) {
        if (typeof ver !== 'string') continue;
        const cleanVer = ver.replace(/^[\^~>=<\s]+/, '') || ver;
        const key = `${name}@${cleanVer}`;
        if (!componentMap.has(key)) {
          componentMap.set(key, {
            name,
            version: cleanVer,
            purl: buildNpmPurl(name, cleanVer),
            scope: 'dev',
          });
        }
      }
    }
  }

  const components = Array.from(componentMap.values()).sort(
    (a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version)
  );

  const licenseSummary: Record<string, number> = {};
  for (const comp of components) {
    const licKey = comp.license || 'UNKNOWN';
    licenseSummary[licKey] = (licenseSummary[licKey] || 0) + 1;
  }

  const evidence: SbomEvidence = {
    id: generateId('sbom'),
    type: 'sbom',
    capturedAt: new Date().toISOString(),
    format: 'cyclonedx-1.5',
    workspaceName,
    manifestPath: manifestSafe.relativePath,
    manifestSha256: manifestHash.sha256,
    lockfilePath,
    lockfileSha256,
    componentCount: components.length,
    components,
    licenseSummary,
    bomDigest: computeSbomDigest(components),
  };

  const cycloneDxBom = generateCycloneDxDocument(evidence, rootName, rootVersion);

  return {
    evidence,
    cycloneDxBom,
  };
}
