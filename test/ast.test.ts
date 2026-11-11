import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync } from 'node:child_process';
import {
  parseSourceSymbols,
  computeSemanticDiff,
  captureFileAstEvidence,
  detectLanguage,
  parseParameters,
} from '../src/ast.js';
import { createEvidenceServer } from '../src/server.js';
import { loadBundle, saveBundle, generateId } from '../src/storage.js';
import { verifyEvidenceBundle } from '../src/verifier.js';
import { exportEvidenceReport } from '../src/reporter.js';
import { runCli } from '../src/cli.js';
import { EvidenceBundle } from '../src/types.js';

describe('AST & Semantic Diff Evidence Engine', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-ast-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors on Windows
    }
  });

  describe('detectLanguage', () => {
    it('detects typescript, javascript, json, and others', () => {
      expect(detectLanguage('index.ts')).toBe('typescript');
      expect(detectLanguage('component.tsx')).toBe('typescript');
      expect(detectLanguage('module.mts')).toBe('typescript');
      expect(detectLanguage('app.js')).toBe('javascript');
      expect(detectLanguage('app.jsx')).toBe('javascript');
      expect(detectLanguage('data.json')).toBe('json');
      expect(detectLanguage('script.py')).toBe('python');
      expect(detectLanguage('styles.css')).toBe('other');
    });
  });

  describe('parseParameters', () => {
    it('correctly parses parameters with nested types and defaults', () => {
      const raw = 'a: string, b?: number, callback: (res: { ok: boolean }) => void, def = 42';
      const parsed = parseParameters(raw);

      expect(parsed.length).toBe(4);
      expect(parsed[0].name).toBe('a');
      expect(parsed[0].optional).toBe(false);
      expect(parsed[0].type).toBe('string');

      expect(parsed[1].name).toBe('b');
      expect(parsed[1].optional).toBe(true);
      expect(parsed[1].type).toBe('number');

      expect(parsed[2].name).toBe('callback');
      expect(parsed[2].type).toBe('(res: { ok: boolean }) => void');

      expect(parsed[3].name).toBe('def');
      expect(parsed[3].defaultValue).toBe('42');
      expect(parsed[3].optional).toBe(true);
    });
  });

  describe('parseSourceSymbols', () => {
    it('extracts exported and internal TypeScript functions, interfaces, types, and classes', () => {
      const source = `
        export interface UserConfig {
          id: string;
          name?: string;
          roles: string[];
        }

        export type Status = 'active' | 'inactive';

        export enum RoleType {
          Admin = 'ADMIN',
          Guest = 'GUEST',
        }

        export class AuthService {
          private token: string;
          public validate(user: string): boolean {
            return true;
          }
        }

        export async function loginUser(username: string, pass: string): Promise<boolean> {
          return true;
        }

        export const calculateSum = (a: number, b: number = 0): number => a + b;

        function internalHelper(data: any): void {}
      `;

      const symbols = parseSourceSymbols(source, 'auth.ts');
      const symbolNames = symbols.map((s) => s.name);

      expect(symbolNames).toContain('UserConfig');
      expect(symbolNames).toContain('Status');
      expect(symbolNames).toContain('RoleType');
      expect(symbolNames).toContain('AuthService');
      expect(symbolNames).toContain('loginUser');
      expect(symbolNames).toContain('calculateSum');
      expect(symbolNames).toContain('internalHelper');

      const userConfig = symbols.find((s) => s.name === 'UserConfig')!;
      expect(userConfig.kind).toBe('interface');
      expect(userConfig.isExported).toBe(true);

      const login = symbols.find((s) => s.name === 'loginUser')!;
      expect(login.kind).toBe('function');
      expect(login.isExported).toBe(true);
      expect(login.isAsync).toBe(true);
      expect(login.returnType).toBe('Promise<boolean>');
      expect(login.parameters?.length).toBe(2);

      const internal = symbols.find((s) => s.name === 'internalHelper')!;
      expect(internal.kind).toBe('function');
      expect(internal.isExported).toBe(false);
    });

    it('extracts Python classes, methods, functions, and async def with parameters', () => {
      const pythonSource = `
class DataPipeline(BasePipeline):
    def __init__(self, name: str, batch_size: int = 100):
        self.name = name

    def process(self, item: dict) -> bool:
        return True

    def _internal_clean(self):
        pass

async def fetch_remote_metrics(endpoint: str, timeout: int = 30) -> list:
    pass

def _private_worker():
    pass
      `;

      const symbols = parseSourceSymbols(pythonSource, 'pipeline.py');
      const names = symbols.map((s) => s.name);

      expect(names).toContain('DataPipeline');
      expect(names).toContain('DataPipeline.__init__');
      expect(names).toContain('DataPipeline.process');
      expect(names).toContain('DataPipeline._internal_clean');
      expect(names).toContain('fetch_remote_metrics');
      expect(names).toContain('_private_worker');

      const proc = symbols.find((s) => s.name === 'DataPipeline.process');
      expect(proc?.kind).toBe('method');
      expect(proc?.isExported).toBe(true);
      expect(proc?.returnType).toBe('bool');

      const fetchMetrics = symbols.find((s) => s.name === 'fetch_remote_metrics');
      expect(fetchMetrics?.kind).toBe('function');
      expect(fetchMetrics?.isAsync).toBe(true);
      expect(fetchMetrics?.isExported).toBe(true);
      expect(fetchMetrics?.parameters?.length).toBe(2);
      expect(fetchMetrics?.parameters?.[1].name).toBe('timeout');
      expect(fetchMetrics?.parameters?.[1].defaultValue).toBe('30');
    });

    it('extracts Go structs, interfaces, functions, grouped parameters, receiver methods, and detects breaking diffs', () => {
      expect(detectLanguage('server.go')).toBe('go');

      const goSource = `
package server

/* Commented struct should be ignored:
type Ghost struct {}
*/

type TokenStore interface {
  Get(id string) (string, error)
}

type AuthServer struct {
  port int
}

type ServerID = string

// NewServer constructs an AuthServer instance
func NewServer(host, bindAddr string, port int) (*AuthServer, error) {
  return &AuthServer{port: port}, nil
}

func (s *AuthServer) Validate(ctx context.Context, strict bool) error {
  return nil
}

func internalSanitize(raw string) string {
  return raw
}
`;

      const symbols = parseSourceSymbols(goSource, 'server.go');
      const names = symbols.map((s) => s.name);

      expect(names).not.toContain('Ghost');
      expect(names).toContain('TokenStore');
      expect(names).toContain('AuthServer');
      expect(names).toContain('ServerID');
      expect(names).toContain('NewServer');
      expect(names).toContain('AuthServer.Validate');
      expect(names).toContain('internalSanitize');

      const store = symbols.find((s) => s.name === 'TokenStore')!;
      expect(store.kind).toBe('interface');
      expect(store.isExported).toBe(true);

      const newServer = symbols.find((s) => s.name === 'NewServer')!;
      expect(newServer.kind).toBe('function');
      expect(newServer.isExported).toBe(true);
      expect(newServer.returnType).toBe('(*AuthServer, error)');
      expect(newServer.parameters).toEqual([
        { name: 'host', optional: false, type: 'string' },
        { name: 'bindAddr', optional: false, type: 'string' },
        { name: 'port', optional: false, type: 'int' },
      ]);

      const validate = symbols.find((s) => s.name === 'AuthServer.Validate')!;
      expect(validate.kind).toBe('method');
      expect(validate.isExported).toBe(true);
      expect(validate.returnType).toBe('error');

      const helper = symbols.find((s) => s.name === 'internalSanitize')!;
      expect(helper.isExported).toBe(false);

      // Verify breaking change detection when required parameter is added to exported Go method
      const modifiedGo = goSource.replace(
        'func (s *AuthServer) Validate(ctx context.Context, strict bool) error {',
        'func (s *AuthServer) Validate(ctx context.Context, strict bool, scope string) error {'
      );
      const nextSymbols = parseSourceSymbols(modifiedGo, 'server.go');
      const diff = computeSemanticDiff(symbols, nextSymbols, 'server.go');
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(true);
    });

    it('extracts Rust traits, structs, enums, async fn, generic parameters, impl methods, and detects breaking diffs', () => {
      expect(detectLanguage('verifier.rs')).toBe('rust');

      const rustSource = `
#[derive(Debug, Clone)]
pub struct TokenConfig {
    pub timeout_ms: u64,
}

pub enum AuthMode {
    Strict,
    Permissive,
}

pub trait TokenVerifier {
    fn scheme(&self) -> &str;
}

pub type ClaimsMap = HashMap<String, Vec<u8>>;

impl TokenConfig {
    pub async fn verify_claims(&self, token: &str, headers: HashMap<String, Vec<u8>>) -> Result<bool, String> {
        Ok(true)
    }

    pub(crate) fn helper_flag(&self) -> bool {
        true
    }
}

pub async fn bootstrap_verifier(endpoint: &str) -> Result<TokenConfig, String> {
    todo!()
}

fn private_hash(input: &[u8]) -> u64 {
    0
}
`;

      const symbols = parseSourceSymbols(rustSource, 'verifier.rs');
      const names = symbols.map((s) => s.name);

      expect(names).toContain('TokenConfig');
      expect(names).toContain('AuthMode');
      expect(names).toContain('TokenVerifier');
      expect(names).toContain('TokenVerifier.scheme');
      expect(names).toContain('ClaimsMap');
      expect(names).toContain('TokenConfig.verify_claims');
      expect(names).toContain('TokenConfig.helper_flag');
      expect(names).toContain('bootstrap_verifier');
      expect(names).toContain('private_hash');

      const verifyClaims = symbols.find((s) => s.name === 'TokenConfig.verify_claims')!;
      expect(verifyClaims.kind).toBe('method');
      expect(verifyClaims.isExported).toBe(true);
      expect(verifyClaims.isAsync).toBe(true);
      expect(verifyClaims.returnType).toBe('Result<bool, String>');
      // Generic commas inside HashMap<String, Vec<u8>> must stay together as 2 parameters (after stripping &self)
      expect(verifyClaims.parameters?.length).toBe(2);
      expect(verifyClaims.parameters?.[1]).toEqual({
        name: 'headers',
        optional: false,
        type: 'HashMap<String, Vec<u8>>',
        defaultValue: undefined,
      });

      const crateHelper = symbols.find((s) => s.name === 'TokenConfig.helper_flag')!;
      expect(crateHelper.isExported).toBe(false);

      const privHash = symbols.find((s) => s.name === 'private_hash')!;
      expect(privHash.isExported).toBe(false);

      // Verify breaking change detection when pub fn becomes private or removed
      const brokenRust = rustSource.replace(
        'pub async fn bootstrap_verifier',
        'fn bootstrap_verifier'
      );
      const nextSymbols = parseSourceSymbols(brokenRust, 'verifier.rs');
      const diff = computeSemanticDiff(symbols, nextSymbols, 'verifier.rs');
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(true);
    });

    it('extracts Java classes, interfaces, records, enums, constructors, generic params, and detects breaking diffs', () => {
      expect(detectLanguage('TokenService.java')).toBe('java');

      const javaSource = `
package com.evidence.auth;

import java.util.List;
import java.util.Map;

public interface TokenVerifier {
    boolean verifyToken(String token);
    private void auditInternal(String msg) {}
}

public enum AuthLevel {
    STRICT,
    PERMISSIVE
}

public record UserClaims(String userId, int ttlSeconds) {}

public class TokenService implements TokenVerifier {
    public TokenService(String secretKey) {
    }

    @Override
    public Map<String, List<Integer>> inspectClaims(@NotNull String token, final Map<String, List<Integer>> claims) {
        return claims;
    }

    private String hashRaw(String raw) {
        return raw;
    }
}
`;

      const symbols = parseSourceSymbols(javaSource, 'TokenService.java');
      const names = symbols.map((s) => s.name);

      expect(names).toContain('TokenVerifier');
      expect(names).toContain('TokenVerifier.verifyToken');
      expect(names).toContain('TokenVerifier.auditInternal');
      expect(names).toContain('AuthLevel');
      expect(names).toContain('UserClaims');
      expect(names).toContain('TokenService');
      expect(names).toContain('TokenService.TokenService');
      expect(names).toContain('TokenService.inspectClaims');
      expect(names).toContain('TokenService.hashRaw');

      const ifaceMethod = symbols.find((s) => s.name === 'TokenVerifier.verifyToken')!;
      expect(ifaceMethod.kind).toBe('method');
      expect(ifaceMethod.isExported).toBe(true);
      expect(ifaceMethod.returnType).toBe('boolean');

      const ifacePriv = symbols.find((s) => s.name === 'TokenVerifier.auditInternal')!;
      expect(ifacePriv.isExported).toBe(false);

      const claimsRecord = symbols.find((s) => s.name === 'UserClaims')!;
      expect(claimsRecord.kind).toBe('class');
      expect(claimsRecord.isExported).toBe(true);
      expect(claimsRecord.parameters?.length).toBe(2);

      const inspect = symbols.find((s) => s.name === 'TokenService.inspectClaims')!;
      expect(inspect.isExported).toBe(true);
      expect(inspect.returnType).toBe('Map<String, List<Integer>>');
      expect(inspect.parameters).toEqual([
        { name: 'token', type: 'String', optional: false, defaultValue: undefined },
        { name: 'claims', type: 'Map<String, List<Integer>>', optional: false, defaultValue: undefined },
      ]);

      const privHelper = symbols.find((s) => s.name === 'TokenService.hashRaw')!;
      expect(privHelper.isExported).toBe(false);

      // Adding a required parameter to exported Java method triggers breaking change
      const modifiedJava = javaSource.replace(
        'public boolean verifyToken(String token);',
        'boolean verifyToken(String token);'
      );
      const removedJava = javaSource.replace('    boolean verifyToken(String token);\n', '');
      const diff = computeSemanticDiff(
        symbols,
        parseSourceSymbols(removedJava, 'TokenService.java'),
        'TokenService.java'
      );
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(true);
      expect(modifiedJava).toContain('TokenService');
    });

    it('extracts C# namespaces, structs, classes, async methods, optional params, and detects breaking diffs', () => {
      expect(detectLanguage('Verifier.cs')).toBe('csharp');

      const csSource = `
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Evidence.Verification {
    public struct Point2D {
        public double DistanceTo(Point2D other) => 0;
    }

    public class BundleValidator {
        public BundleValidator(string workspacePath) {
        }

        [HttpPost("verify")]
        public async Task<bool> ValidateAsync([FromBody] Dictionary<string, List<int>> payload, bool strict = true) {
            return await Task.FromResult(strict);
        }

        internal void ResetCache() {
        }
    }
}
`;

      const symbols = parseSourceSymbols(csSource, 'Verifier.cs');
      const names = symbols.map((s) => s.name);

      expect(names).toContain('Point2D');
      expect(names).toContain('Point2D.DistanceTo');
      expect(names).toContain('BundleValidator');
      expect(names).toContain('BundleValidator.BundleValidator');
      expect(names).toContain('BundleValidator.ValidateAsync');
      expect(names).toContain('BundleValidator.ResetCache');

      const validate = symbols.find((s) => s.name === 'BundleValidator.ValidateAsync')!;
      expect(validate.kind).toBe('method');
      expect(validate.isExported).toBe(true);
      expect(validate.isAsync).toBe(true);
      expect(validate.returnType).toBe('Task<bool>');
      expect(validate.parameters).toEqual([
        {
          name: 'payload',
          type: 'Dictionary<string, List<int>>',
          optional: false,
          defaultValue: undefined,
        },
        {
          name: 'strict',
          type: 'bool',
          optional: true,
          defaultValue: 'true',
        },
      ]);

      const reset = symbols.find((s) => s.name === 'BundleValidator.ResetCache')!;
      expect(reset.isExported).toBe(false);

      // Adding a required parameter to public async method triggers breaking change
      const modifiedCs = csSource.replace(
        'public async Task<bool> ValidateAsync([FromBody] Dictionary<string, List<int>> payload, bool strict = true)',
        'public async Task<bool> ValidateAsync([FromBody] Dictionary<string, List<int>> payload, bool strict = true, string tenantId)'
      );
      const nextSymbols = parseSourceSymbols(modifiedCs, 'Verifier.cs');
      const diff = computeSemanticDiff(symbols, nextSymbols, 'Verifier.cs');
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(true);
    });

    it('extracts top-level keys from JSON files', () => {
      const jsonSource = JSON.stringify({
        name: 'evidence-mcp',
        version: '0.6.0',
        scripts: { test: 'vitest' },
      });

      const symbols = parseSourceSymbols(jsonSource, 'package.json');
      expect(symbols.length).toBe(3);
      expect(symbols.map((s) => s.name)).toEqual(['name', 'version', 'scripts']);
    });
  });

  describe('computeSemanticDiff', () => {
    it('detects added and removed symbols', () => {
      const prevSource = `
        export function foo(): void {}
        export function bar(): void {}
      `;
      const currSource = `
        export function foo(): void {}
        export function baz(): void {}
      `;

      const prev = parseSourceSymbols(prevSource, 'test.ts');
      const curr = parseSourceSymbols(currSource, 'test.ts');

      const diff = computeSemanticDiff(prev, curr, 'test.ts');
      expect(diff.hasChanges).toBe(true);
      expect(diff.removedSymbols.map((s) => s.name)).toEqual(['bar']);
      expect(diff.addedSymbols.map((s) => s.name)).toEqual(['baz']);
      // Removing an exported function is a breaking change
      expect(diff.isBreakingChange).toBe(true);
    });

    it('detects breaking changes when adding required parameters to exported functions', () => {
      const prevSource = `export function greet(name: string): string { return name; }`;
      const currSource = `export function greet(name: string, greeting: string): string { return greeting + name; }`;

      const prev = parseSourceSymbols(prevSource, 'greet.ts');
      const curr = parseSourceSymbols(currSource, 'greet.ts');

      const diff = computeSemanticDiff(prev, curr, 'greet.ts');
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(true);
      expect(diff.modifiedSymbols.length).toBe(1);
      expect(diff.modifiedSymbols[0].changes).toContain('New required parameter added to exported signature.');
    });

    it('treats adding optional parameters as non-breaking', () => {
      const prevSource = `export function greet(name: string): string { return name; }`;
      const currSource = `export function greet(name: string, greeting?: string): string { return (greeting || 'Hi') + name; }`;

      const prev = parseSourceSymbols(prevSource, 'greet.ts');
      const curr = parseSourceSymbols(currSource, 'greet.ts');

      const diff = computeSemanticDiff(prev, curr, 'greet.ts');
      expect(diff.hasChanges).toBe(true);
      expect(diff.isBreakingChange).toBe(false);
      expect(diff.modifiedSymbols.length).toBe(1);
    });
  });

  describe('captureFileAstEvidence with Git repository', () => {
    it('captures AST evidence and computes semantic diff against Git HEAD', async () => {
      // Initialize Git repo in tempDir
      execSync('git init -b main', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.name "Test Agent"', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.email "test@example.com"', { cwd: tempDir, stdio: 'ignore' });

      const filePath = path.join(tempDir, 'service.ts');
      fs.writeFileSync(
        filePath,
        `export function executeTask(id: string): boolean { return true; }\n`
      );

      execSync('git add service.ts', { cwd: tempDir, stdio: 'ignore' });
      execSync('git commit -m "feat: initial service"', { cwd: tempDir, stdio: 'ignore' });

      // Modify file in working tree: add new function
      fs.writeFileSync(
        filePath,
        `export function executeTask(id: string): boolean { return true; }\n` +
          `export function cancelTask(id: string): void {}\n`
      );

      const evidence = await captureFileAstEvidence({
        filePath: 'service.ts',
        workspacePath: tempDir,
        compareWithGitHead: true,
      });

      expect(evidence.filePath).toBe('service.ts');
      expect(evidence.language).toBe('typescript');
      expect(evidence.symbolsCount).toBe(2);
      expect(evidence.diff).toBeDefined();
      expect(evidence.diff?.hasChanges).toBe(true);
      expect(evidence.diff?.isBreakingChange).toBe(false);
      expect(evidence.diff?.addedSymbols.map((s) => s.name)).toEqual(['cancelTask']);
      expect(evidence.diff?.removedSymbols.length).toBe(0);
    });

    it('rejects path traversal outside workspace', async () => {
      await expect(
        captureFileAstEvidence({
          filePath: '../external.ts',
          workspacePath: tempDir,
        })
      ).rejects.toThrow(/outside/i);
    });
  });

  describe('MCP Tool & Verification Integration', () => {
    it('captures AST evidence via MCP server, verifies cleanly, and detects stale on symbol alteration', async () => {
      // Setup Git repo
      execSync('git init -b main', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.name "Test Agent"', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.email "test@example.com"', { cwd: tempDir, stdio: 'ignore' });

      const mathFile = path.join(tempDir, 'math.ts');
      fs.writeFileSync(
        mathFile,
        `export function add(a: number, b: number): number { return a + b; }\n`
      );
      execSync('git add math.ts', { cwd: tempDir, stdio: 'ignore' });
      execSync('git commit -m "feat: math lib"', { cwd: tempDir, stdio: 'ignore' });

      const server = createEvidenceServer();

      // Create bundle
      const createRes = await (server as any)._registeredTools['create_evidence_bundle'].handler({
        task: 'Implement math functions with AST verification',
        workspacePath: tempDir,
      });
      const createData = JSON.parse(createRes.content[0].text);
      const bundleId = createData.bundleId;

      // Capture AST evidence via MCP tool
      const astRes = await (server as any)._registeredTools['capture_ast_evidence'].handler({
        bundleId,
        files: ['math.ts'],
        workspacePath: tempDir,
      });
      expect(astRes.isError).toBeUndefined();
      const astData = JSON.parse(astRes.content[0].text);
      expect(astData.astEvidence.length).toBe(1);
      expect(astData.astEvidence[0].symbolsCount).toBe(1);
      const astEvidenceId = astData.astEvidence[0].id;

      // Add assertion linking to AST evidence
      await (server as any)._registeredTools['add_assertion'].handler({
        bundleId,
        claim: 'math.ts exports add function with valid signatures',
        evidenceIds: [astEvidenceId],
        workspacePath: tempDir,
      });

      // Verify bundle: should be verified
      const verifyRes1 = await (server as any)._registeredTools['verify_evidence_bundle'].handler({
        bundleId,
        workspacePath: tempDir,
      });
      const verifyData1 = JSON.parse(verifyRes1.content[0].text);
      expect(verifyData1.status).toBe('verified');
      expect(verifyData1.items.some((i: any) => i.type === 'ast' && i.status === 'verified')).toBe(true);

      // Now alter the file on disk: rename the function so AST symbols no longer match
      fs.writeFileSync(
        mathFile,
        `export function addNumbers(a: number, b: number): number { return a + b; }\n`
      );

      // Verify bundle again: should be stale
      const verifyRes2 = await (server as any)._registeredTools['verify_evidence_bundle'].handler({
        bundleId,
        workspacePath: tempDir,
      });
      const verifyData2 = JSON.parse(verifyRes2.content[0].text);
      expect(verifyData2.status).toBe('stale');
      expect(verifyData2.reasons.some((r: string) => r.includes('AST evidence'))).toBe(true);
    });
  });

  describe('CLI and Reporting Integration', () => {
    it('supports evidence-mcp ast command and formats Markdown & HTML reports', async () => {
      // Setup Git repo
      execSync('git init -b main', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.name "Test Agent"', { cwd: tempDir, stdio: 'ignore' });
      execSync('git config user.email "test@example.com"', { cwd: tempDir, stdio: 'ignore' });

      const libFile = path.join(tempDir, 'lib.ts');
      fs.writeFileSync(
        libFile,
        `export interface Config { timeout: number; }\nexport function run(cfg: Config): void {}\n`
      );
      execSync('git add lib.ts', { cwd: tempDir, stdio: 'ignore' });
      execSync('git commit -m "initial lib"', { cwd: tempDir, stdio: 'ignore' });

      const bundle: EvidenceBundle = {
        id: generateId('bundle'),
        task: 'CLI AST Test',
        workspacePath: tempDir,
        status: 'in_progress',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        evidence: {},
        assertions: [],
      };
      await saveBundle(bundle);

      // Run CLI ast command
      const code = await runCli(['ast', bundle.id, 'lib.ts', '--workspace', tempDir]);
      expect(code).toBe(0);

      // Load bundle and verify AST evidence was added
      const loaded = await loadBundle(bundle.id, tempDir);
      expect(loaded.evidence.ast?.length).toBe(1);
      expect(loaded.evidence.ast![0].symbolsCount).toBe(2);

      // Verify Markdown report contains AST section
      const mdReport = exportEvidenceReport(loaded, 'markdown');
      expect(mdReport).toContain('AST & Semantic Diff Evidence');
      expect(mdReport).toContain('`lib.ts`');
      expect(mdReport).toContain('`interface`');
      expect(mdReport).toContain('`run`');

      // Verify HTML report contains AST card
      const htmlReport = exportEvidenceReport(loaded, 'html');
      expect(htmlReport).toContain('AST & Semantic Diff Evidence');
      expect(htmlReport).toContain('lib.ts');
      expect(htmlReport).toContain('Clean (No Diff)');
    });
  });
});
