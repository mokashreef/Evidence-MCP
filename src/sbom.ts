import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { SbomComponent, SbomEvidence } from './types.js';
import { assertSafeFilePath } from './security.js';
import { computeFileSha256AndSize } from './hasher.js';
import { canonicalStringify } from './attestation.js';
import { generateId } from './storage.js';

export type SupportedSbomEcosystem = 'npm' | 'golang' | 'cargo' | 'pypi';

/**
 * Generates a PURL (Package URL) identifier compliant with the npm purl specification.
 */
export function buildNpmPurl(name: string, version: string): string {
  const encodedName = name.startsWith('@') ? `%40${name.slice(1)}` : name;
  return `pkg:npm/${encodedName}@${version}`;
}

/**
 * Generates a Package URL (PURL) identifier for the specified ecosystem.
 */
export function buildPurl(ecosystem: SupportedSbomEcosystem, name: string, version: string): string {
  switch (ecosystem) {
    case 'npm':
      return buildNpmPurl(name, version);
    case 'golang':
      return `pkg:golang/${name}@${version}`;
    case 'cargo':
      return `pkg:cargo/${name}@${version}`;
    case 'pypi': {
      const normalized = name.toLowerCase().replace(/_/g, '-');
      return `pkg:pypi/${normalized}@${version}`;
    }
  }
}

/**
 * Computes a deterministic SHA-256 digest over a sorted SBOM component list.
 */
export function computeSbomDigest(components: SbomComponent[]): string {
  const normalized = [...components]
    .sort(
      (a, b) =>
        a.name.localeCompare(b.name) ||
        a.version.localeCompare(b.version) ||
        (a.purl || '').localeCompare(b.purl || '')
    )
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

function addComponent(map: Map<string, SbomComponent>, component: SbomComponent): void {
  const dedupeKey = component.purl || `${component.name}@${component.version}`;
  if (!map.has(dedupeKey)) {
    map.set(dedupeKey, component);
  }
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
      addComponent(map, {
        name,
        version,
        purl: buildNpmPurl(name, version),
        scope: isDev ? 'dev' : isOptional ? 'optional' : 'required',
        integrity: typeof rec.integrity === 'string' ? rec.integrity : undefined,
      });
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

interface EcosystemScanResult {
  ecosystem: SupportedSbomEcosystem;
  rootName?: string;
  rootVersion?: string;
  manifestPath: string;
  manifestSha256: string;
  lockfilePath?: string;
  lockfileSha256?: string;
  extraFiles: Array<{ path: string; sha256: string }>;
}

function resolveOptionalManifest(
  workspacePath: string,
  filename: string
): ReturnType<typeof assertSafeFilePath> | null {
  const candidate = path.join(path.resolve(workspacePath), filename);
  try {
    fs.lstatSync(candidate);
  } catch {
    return null;
  }
  return assertSafeFilePath(workspacePath, filename);
}

async function scanNpmEcosystem(
  workspacePath: string,
  includeDevDependencies: boolean,
  componentMap: Map<string, SbomComponent>
): Promise<EcosystemScanResult | null> {
  const manifestSafe = resolveOptionalManifest(workspacePath, 'package.json');
  if (!manifestSafe) {
    return null;
  }

  const manifestHash = await computeFileSha256AndSize(manifestSafe.absolutePath);
  const manifestRaw = await fs.promises.readFile(manifestSafe.absolutePath, 'utf8');
  const manifestJson = JSON.parse(manifestRaw) as Record<string, unknown>;

  const rootName = typeof manifestJson.name === 'string' ? manifestJson.name : undefined;
  const rootVersion = typeof manifestJson.version === 'string' ? manifestJson.version : undefined;

  let lockfilePath: string | undefined;
  let lockfileSha256: string | undefined;

  const lockSafe = resolveOptionalManifest(workspacePath, 'package-lock.json');
  if (lockSafe) {
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
        addComponent(componentMap, {
          name,
          version,
          purl: buildNpmPurl(name, version),
          scope: isDev ? 'dev' : isOptional ? 'optional' : 'required',
          license: extractLicenseString(meta.license),
          integrity: typeof meta.integrity === 'string' ? meta.integrity : undefined,
        });
      }
    } else if (lockJson.dependencies && typeof lockJson.dependencies === 'object') {
      collectLockfileV1Components(
        lockJson.dependencies as Record<string, unknown>,
        includeDevDependencies,
        componentMap
      );
    }
  } else {
    const deps =
      manifestJson.dependencies && typeof manifestJson.dependencies === 'object'
        ? (manifestJson.dependencies as Record<string, unknown>)
        : {};
    for (const [name, ver] of Object.entries(deps)) {
      if (typeof ver !== 'string') continue;
      const cleanVer = ver.replace(/^[\^~>=<\s]+/, '') || ver;
      addComponent(componentMap, {
        name,
        version: cleanVer,
        purl: buildNpmPurl(name, cleanVer),
        scope: 'required',
      });
    }

    if (
      includeDevDependencies &&
      manifestJson.devDependencies &&
      typeof manifestJson.devDependencies === 'object'
    ) {
      const devDeps = manifestJson.devDependencies as Record<string, unknown>;
      for (const [name, ver] of Object.entries(devDeps)) {
        if (typeof ver !== 'string') continue;
        const cleanVer = ver.replace(/^[\^~>=<\s]+/, '') || ver;
        addComponent(componentMap, {
          name,
          version: cleanVer,
          purl: buildNpmPurl(name, cleanVer),
          scope: 'dev',
        });
      }
    }
  }

  return {
    ecosystem: 'npm',
    rootName,
    rootVersion,
    manifestPath: manifestSafe.relativePath,
    manifestSha256: manifestHash.sha256,
    lockfilePath,
    lockfileSha256,
    extraFiles: [],
  };
}

async function scanGoEcosystem(
  workspacePath: string,
  componentMap: Map<string, SbomComponent>
): Promise<EcosystemScanResult | null> {
  const goModSafe = resolveOptionalManifest(workspacePath, 'go.mod');
  if (!goModSafe) {
    return null;
  }

  const goModHash = await computeFileSha256AndSize(goModSafe.absolutePath);
  const goModRaw = await fs.promises.readFile(goModSafe.absolutePath, 'utf8');

  let rootName: string | undefined;
  let rootVersion: string | undefined;

  const goSumHashes = new Map<string, string>();
  let lockfilePath: string | undefined;
  let lockfileSha256: string | undefined;

  const goSumSafe = resolveOptionalManifest(workspacePath, 'go.sum');
  if (goSumSafe) {
    const goSumHash = await computeFileSha256AndSize(goSumSafe.absolutePath);
    lockfilePath = goSumSafe.relativePath;
    lockfileSha256 = goSumHash.sha256;

    const goSumRaw = await fs.promises.readFile(goSumSafe.absolutePath, 'utf8');
    for (const line of goSumRaw.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 3 && !parts[1].endsWith('/go.mod')) {
        goSumHashes.set(`${parts[0]}@${parts[1]}`, parts[2]);
      }
    }
  }

  let inRequireBlock = false;
  for (const rawLine of goModRaw.split(/\r?\n/)) {
    const commentIdx = rawLine.indexOf('//');
    const codePart = (commentIdx === -1 ? rawLine : rawLine.slice(0, commentIdx)).trim();
    if (!codePart) continue;

    if (!inRequireBlock) {
      const modMatch = /^module\s+(\S+)$/.exec(codePart);
      if (modMatch) {
        rootName = modMatch[1];
        continue;
      }
      const goVerMatch = /^go\s+(\S+)$/.exec(codePart);
      if (goVerMatch) {
        rootVersion = goVerMatch[1];
        continue;
      }
      if (/^require\s*\($/.test(codePart)) {
        inRequireBlock = true;
        continue;
      }
      const singleReq = /^require\s+(\S+)\s+(\S+)$/.exec(codePart);
      if (singleReq) {
        const [, modName, modVersion] = singleReq;
        addComponent(componentMap, {
          name: modName,
          version: modVersion,
          purl: buildPurl('golang', modName, modVersion),
          scope: 'required',
          integrity: goSumHashes.get(`${modName}@${modVersion}`),
        });
      }
    } else {
      if (codePart === ')') {
        inRequireBlock = false;
        continue;
      }
      const reqMatch = /^(\S+)\s+(\S+)$/.exec(codePart);
      if (reqMatch) {
        const [, modName, modVersion] = reqMatch;
        addComponent(componentMap, {
          name: modName,
          version: modVersion,
          purl: buildPurl('golang', modName, modVersion),
          scope: 'required',
          integrity: goSumHashes.get(`${modName}@${modVersion}`),
        });
      }
    }
  }

  return {
    ecosystem: 'golang',
    rootName,
    rootVersion,
    manifestPath: goModSafe.relativePath,
    manifestSha256: goModHash.sha256,
    lockfilePath,
    lockfileSha256,
    extraFiles: [],
  };
}

function parseCargoTomlDeps(
  cargoTomlRaw: string,
  includeDev: boolean
): { rootName?: string; rootVersion?: string; license?: string; deps: Array<{ name: string; version: string; scope: 'required' | 'dev' }> } {
  let section = '';
  let rootName: string | undefined;
  let rootVersion: string | undefined;
  let license: string | undefined;
  const deps: Array<{ name: string; version: string; scope: 'required' | 'dev' }> = [];

  for (const rawLine of cargoTomlRaw.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;

    const secMatch = /^\[([^\]]+)\]$/.exec(line);
    if (secMatch) {
      section = secMatch[1].trim();
      continue;
    }

    const kvMatch = /^([A-Za-z0-9_.-]+)\s*=\s*(.+)$/.exec(line);
    if (!kvMatch) continue;
    const key = kvMatch[1];
    const val = kvMatch[2].trim();

    if (section === 'package') {
      const strMatch = /^["']([^"']+)["']$/.exec(val);
      if (strMatch) {
        if (key === 'name') rootName = strMatch[1];
        else if (key === 'version') rootVersion = strMatch[1];
        else if (key === 'license') license = strMatch[1];
      }
    } else if (section === 'dependencies' || (includeDev && section === 'dev-dependencies')) {
      const scope = section === 'dev-dependencies' ? 'dev' : 'required';
      const simpleVer = /^["']([^"']+)["']$/.exec(val);
      const inlineTableVer = /version\s*=\s*["']([^"']+)["']/.exec(val);
      const rawVer = simpleVer?.[1] || inlineTableVer?.[1];
      if (rawVer) {
        deps.push({
          name: key,
          version: rawVer.replace(/^[\^~>=<\s]+/, '') || rawVer,
          scope,
        });
      }
    }
  }

  return { rootName, rootVersion, license, deps };
}

async function scanCargoEcosystem(
  workspacePath: string,
  includeDevDependencies: boolean,
  componentMap: Map<string, SbomComponent>
): Promise<EcosystemScanResult | null> {
  const tomlSafe = resolveOptionalManifest(workspacePath, 'Cargo.toml');
  const lockSafe = resolveOptionalManifest(workspacePath, 'Cargo.lock');

  if (!tomlSafe && !lockSafe) {
    return null;
  }

  let rootName: string | undefined;
  let rootVersion: string | undefined;
  let parsedToml: ReturnType<typeof parseCargoTomlDeps> | undefined;

  let manifestPath: string;
  let manifestSha256: string;
  let lockfilePath: string | undefined;
  let lockfileSha256: string | undefined;

  if (tomlSafe) {
    const tomlHash = await computeFileSha256AndSize(tomlSafe.absolutePath);
    manifestPath = tomlSafe.relativePath;
    manifestSha256 = tomlHash.sha256;
    const tomlRaw = await fs.promises.readFile(tomlSafe.absolutePath, 'utf8');
    parsedToml = parseCargoTomlDeps(tomlRaw, includeDevDependencies);
    rootName = parsedToml.rootName;
    rootVersion = parsedToml.rootVersion;
  } else {
    const lockHash = await computeFileSha256AndSize(lockSafe!.absolutePath);
    manifestPath = lockSafe!.relativePath;
    manifestSha256 = lockHash.sha256;
  }

  if (lockSafe) {
    const lockHash = await computeFileSha256AndSize(lockSafe.absolutePath);
    if (tomlSafe) {
      lockfilePath = lockSafe.relativePath;
      lockfileSha256 = lockHash.sha256;
    }

    const lockRaw = await fs.promises.readFile(lockSafe.absolutePath, 'utf8');
    const blocks = lockRaw.split(/\[\[package\]\]/).slice(1);
    for (const block of blocks) {
      const nameMatch = /(?:^|\r?\n)\s*name\s*=\s*"([^"]+)"/.exec(block);
      const versionMatch = /(?:^|\r?\n)\s*version\s*=\s*"([^"]+)"/.exec(block);
      const sourceMatch = /(?:^|\r?\n)\s*source\s*=\s*"([^"]+)"/.exec(block);
      const checksumMatch = /(?:^|\r?\n)\s*checksum\s*=\s*"([^"]+)"/.exec(block);

      if (!nameMatch || !versionMatch) continue;
      const pkgName = nameMatch[1];
      const pkgVersion = versionMatch[1];

      // Skip workspace root crate itself
      if (!sourceMatch && !checksumMatch && (!rootName || pkgName === rootName)) {
        if (!rootName) rootName = pkgName;
        if (!rootVersion) rootVersion = pkgVersion;
        continue;
      }

      addComponent(componentMap, {
        name: pkgName,
        version: pkgVersion,
        purl: buildPurl('cargo', pkgName, pkgVersion),
        scope: 'required',
        integrity: checksumMatch?.[1],
      });
    }
  } else if (parsedToml) {
    for (const dep of parsedToml.deps) {
      addComponent(componentMap, {
        name: dep.name,
        version: dep.version,
        purl: buildPurl('cargo', dep.name, dep.version),
        scope: dep.scope,
      });
    }
  }

  return {
    ecosystem: 'cargo',
    rootName,
    rootVersion,
    manifestPath,
    manifestSha256,
    lockfilePath,
    lockfileSha256,
    extraFiles: [],
  };
}

function parsePep508Requirement(rawSpec: string): { name: string; version: string } | null {
  const withoutComments = rawSpec.replace(/#.*$/, '').trim();
  if (!withoutComments || withoutComments.startsWith('-')) {
    return null;
  }
  const withoutMarkers = withoutComments.split(';')[0].trim();
  const match = /^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*(?:(===|==|~=|>=|<=|!=|>|<)\s*([^\s,;]+))?/.exec(
    withoutMarkers
  );
  if (!match) {
    return null;
  }
  const name = match[1];
  const rawVer = match[3] || 'unspecified';
  const version = rawVer.split(',')[0].trim();
  return { name, version };
}

async function scanPythonEcosystem(
  workspacePath: string,
  includeDevDependencies: boolean,
  componentMap: Map<string, SbomComponent>
): Promise<EcosystemScanResult | null> {
  const pyprojectSafe = resolveOptionalManifest(workspacePath, 'pyproject.toml');
  const reqSafe = resolveOptionalManifest(workspacePath, 'requirements.txt');

  if (!pyprojectSafe && !reqSafe) {
    return null;
  }

  let rootName: string | undefined;
  let rootVersion: string | undefined;
  let manifestPath = '';
  let manifestSha256 = '';
  const extraFiles: Array<{ path: string; sha256: string }> = [];

  if (pyprojectSafe) {
    const pyHash = await computeFileSha256AndSize(pyprojectSafe.absolutePath);
    manifestPath = pyprojectSafe.relativePath;
    manifestSha256 = pyHash.sha256;

    const raw = await fs.promises.readFile(pyprojectSafe.absolutePath, 'utf8');
    const nameMatch = /(?:^|\r?\n)\s*name\s*=\s*["']([^"']+)["']/.exec(raw);
    const verMatch = /(?:^|\r?\n)\s*version\s*=\s*["']([^"']+)["']/.exec(raw);
    rootName = nameMatch?.[1];
    rootVersion = verMatch?.[1];

    // Parse [project] dependencies = [ ... ]
    const depsBlock = /(?:^|\r?\n)\s*dependencies\s*=\s*\[([\s\S]*?)\]/.exec(raw);
    if (depsBlock) {
      for (const item of depsBlock[1].matchAll(/["']([^"']+)["']/g)) {
        const parsed = parsePep508Requirement(item[1]);
        if (parsed) {
          addComponent(componentMap, {
            name: parsed.name,
            version: parsed.version,
            purl: buildPurl('pypi', parsed.name, parsed.version),
            scope: 'required',
          });
        }
      }
    }

    // Parse [project.optional-dependencies] groups
    const optSec = /\[project\.optional-dependencies\]([\s\S]*?)(?:\r?\n\[|$)/.exec(raw);
    if (optSec) {
      for (const groupMatch of optSec[1].matchAll(/([A-Za-z0-9._-]+)\s*=\s*\[([\s\S]*?)\]/g)) {
        const groupName = groupMatch[1].toLowerCase();
        const isDevGroup = groupName === 'dev' || groupName === 'test' || groupName === 'lint';
        if (isDevGroup && !includeDevDependencies) continue;
        for (const item of groupMatch[2].matchAll(/["']([^"']+)["']/g)) {
          const parsed = parsePep508Requirement(item[1]);
          if (parsed) {
            addComponent(componentMap, {
              name: parsed.name,
              version: parsed.version,
              purl: buildPurl('pypi', parsed.name, parsed.version),
              scope: isDevGroup ? 'dev' : 'optional',
            });
          }
        }
      }
    }
  }

  if (reqSafe) {
    const reqHash = await computeFileSha256AndSize(reqSafe.absolutePath);
    if (!manifestPath) {
      manifestPath = reqSafe.relativePath;
      manifestSha256 = reqHash.sha256;
    } else {
      extraFiles.push({ path: reqSafe.relativePath, sha256: reqHash.sha256 });
    }

    const reqRaw = await fs.promises.readFile(reqSafe.absolutePath, 'utf8');
    for (const line of reqRaw.split(/\r?\n/)) {
      const parsed = parsePep508Requirement(line);
      if (parsed) {
        addComponent(componentMap, {
          name: parsed.name,
          version: parsed.version,
          purl: buildPurl('pypi', parsed.name, parsed.version),
          scope: 'required',
        });
      }
    }
  }

  return {
    ecosystem: 'pypi',
    rootName,
    rootVersion,
    manifestPath,
    manifestSha256,
    extraFiles,
  };
}

function mapCycloneDxHash(integrity: string): { alg: string; content: string } | null {
  if (integrity.startsWith('sha512-')) {
    return { alg: 'SHA-512', content: integrity };
  }
  if (/^[a-f0-9]{64}$/i.test(integrity) || integrity.startsWith('sha256-')) {
    return { alg: 'SHA-256', content: integrity };
  }
  return null;
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
          version: '1.5.0',
        },
      ],
      component: {
        type: 'application',
        name: rootName,
        version: rootVersion,
      },
    },
    components: evidence.components.map((c) => {
      const hashEntry = c.integrity ? mapCycloneDxHash(c.integrity) : null;
      return {
        type: 'library',
        name: c.name,
        version: c.version,
        scope: c.scope === 'dev' ? 'excluded' : c.scope === 'optional' ? 'optional' : 'required',
        purl: c.purl || buildNpmPurl(c.name, c.version),
        ...(c.license ? { licenses: [{ license: { id: c.license } }] } : {}),
        ...(hashEntry ? { hashes: [hashEntry] } : {}),
      };
    }),
  };
}

/**
 * Inspects workspace manifests across supported ecosystems (npm, Go, Rust, Python)
 * within strict path boundaries to assemble verifiable CycloneDX SBOM evidence.
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

  const componentMap = new Map<string, SbomComponent>();
  const scanResults: EcosystemScanResult[] = [];

  const npmRes = await scanNpmEcosystem(workspacePath, includeDevDependencies, componentMap);
  if (npmRes) scanResults.push(npmRes);

  const goRes = await scanGoEcosystem(workspacePath, componentMap);
  if (goRes) scanResults.push(goRes);

  const cargoRes = await scanCargoEcosystem(workspacePath, includeDevDependencies, componentMap);
  if (cargoRes) scanResults.push(cargoRes);

  const pyRes = await scanPythonEcosystem(workspacePath, includeDevDependencies, componentMap);
  if (pyRes) scanResults.push(pyRes);

  if (scanResults.length === 0) {
    throw new Error(
      `No supported package manifest found at workspace root "${workspacePath}" (supported: package.json, go.mod, Cargo.toml, Cargo.lock, pyproject.toml, requirements.txt).`
    );
  }

  const primary = scanResults[0];
  const rootName = primary.rootName || 'workspace-root';
  const rootVersion = primary.rootVersion || '0.0.0';

  const additionalManifests: Array<{ path: string; sha256: string }> = [...primary.extraFiles];
  for (let i = 1; i < scanResults.length; i++) {
    const sec = scanResults[i];
    additionalManifests.push({ path: sec.manifestPath, sha256: sec.manifestSha256 });
    if (sec.lockfilePath && sec.lockfileSha256) {
      additionalManifests.push({ path: sec.lockfilePath, sha256: sec.lockfileSha256 });
    }
    additionalManifests.push(...sec.extraFiles);
  }

  const components = Array.from(componentMap.values()).sort(
    (a, b) =>
      a.name.localeCompare(b.name) ||
      a.version.localeCompare(b.version) ||
      (a.purl || '').localeCompare(b.purl || '')
  );

  const licenseSummary: Record<string, number> = {};
  for (const comp of components) {
    const licKey = comp.license || 'UNKNOWN';
    licenseSummary[licKey] = (licenseSummary[licKey] || 0) + 1;
  }

  const ecosystem: SbomEvidence['ecosystem'] =
    scanResults.length === 1 ? primary.ecosystem : 'mixed';

  const evidence: SbomEvidence = {
    id: generateId('sbom'),
    type: 'sbom',
    capturedAt: new Date().toISOString(),
    format: 'cyclonedx-1.5',
    ecosystem,
    workspaceName,
    manifestPath: primary.manifestPath,
    manifestSha256: primary.manifestSha256,
    lockfilePath: primary.lockfilePath,
    lockfileSha256: primary.lockfileSha256,
    ...(additionalManifests.length > 0 ? { additionalManifests } : {}),
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
