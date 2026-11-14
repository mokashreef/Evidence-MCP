import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  registerAstPlugin,
  unregisterAstPlugin,
  getAstPluginForFile,
  getAstPluginForLanguage,
  listRegisteredAstPlugins,
  resetAstPluginRegistry,
  detectLanguage,
  parseSourceSymbols,
  captureFileAstEvidence,
} from '../src/ast.js';
import { AstSymbol, AstParserPlugin } from '../src/types.js';
import { runCli } from '../src/cli.js';

describe('Modular AST Parser Plugin Bridge', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-ast-plugins-test-'));
    resetAstPluginRegistry();
  });

  afterEach(async () => {
    resetAstPluginRegistry();
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('Default Built-in AST Plugins', () => {
    it('initializes with all 8 standard built-in language plugins', () => {
      const plugins = listRegisteredAstPlugins();
      const languages = plugins.map((p) => p.language);

      expect(languages).toContain('typescript');
      expect(languages).toContain('javascript');
      expect(languages).toContain('python');
      expect(languages).toContain('go');
      expect(languages).toContain('rust');
      expect(languages).toContain('java');
      expect(languages).toContain('csharp');
      expect(languages).toContain('json');
    });

    it('resolves correct built-in plugins by file extension', () => {
      expect(getAstPluginForFile('src/index.ts')?.language).toBe('typescript');
      expect(getAstPluginForFile('src/App.tsx')?.language).toBe('typescript');
      expect(getAstPluginForFile('src/util.js')?.language).toBe('javascript');
      expect(getAstPluginForFile('backend/main.py')?.language).toBe('python');
      expect(getAstPluginForFile('cmd/server/main.go')?.language).toBe('go');
      expect(getAstPluginForFile('core/lib.rs')?.language).toBe('rust');
      expect(getAstPluginForFile('src/Service.java')?.language).toBe('java');
      expect(getAstPluginForFile('api/Controller.cs')?.language).toBe('csharp');
      expect(getAstPluginForFile('config.json')?.language).toBe('json');
      expect(getAstPluginForFile('README.md')).toBeUndefined();
    });

    it('detectLanguage delegates to registered plugin extensions', () => {
      expect(detectLanguage('index.ts')).toBe('typescript');
      expect(detectLanguage('index.js')).toBe('javascript');
      expect(detectLanguage('main.py')).toBe('python');
      expect(detectLanguage('main.go')).toBe('go');
      expect(detectLanguage('lib.rs')).toBe('rust');
      expect(detectLanguage('App.java')).toBe('java');
      expect(detectLanguage('App.cs')).toBe('csharp');
      expect(detectLanguage('unknown.xyz')).toBe('other');
    });
  });

  describe('Custom Language Plugin Registration', () => {
    it('registers a custom language parser plugin and detects language', () => {
      const rubyPlugin: AstParserPlugin = {
        language: 'ruby',
        extensions: ['.rb'],
        description: 'Mock Ruby function parser',
        parseSymbols: (code: string): AstSymbol[] => {
          const symbols: AstSymbol[] = [];
          const lines = code.split('\n');
          for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            if (line.startsWith('def ')) {
              const name = line.replace(/^def\s+/, '').split('(')[0].trim();
              symbols.push({
                name,
                kind: 'function',
                isExported: true,
                startLine: i + 1,
                endLine: i + 1,
              });
            }
          }
          return symbols;
        },
      };

      registerAstPlugin(rubyPlugin);

      expect(getAstPluginForFile('app/models/user.rb')).toBeDefined();
      expect(detectLanguage('app/models/user.rb')).toBe('ruby');
      expect(getAstPluginForLanguage('ruby')).toBeDefined();

      const rubyCode = `
def calculate_tax(amount)
  amount * 0.15
end

def format_currency(val)
  "$\#{val}"
end
      `;

      const parsed = parseSourceSymbols(rubyCode, 'app/models/user.rb');
      expect(parsed).toHaveLength(2);
      expect(parsed[0].name).toBe('calculate_tax');
      expect(parsed[1].name).toBe('format_currency');
    });

    it('supports unregistering plugins by language name', () => {
      const customPlugin: AstParserPlugin = {
        language: 'kotlin',
        extensions: ['.kt'],
        parseSymbols: () => [],
      };

      registerAstPlugin(customPlugin);
      expect(getAstPluginForFile('Main.kt')).toBeDefined();

      const unregistered = unregisterAstPlugin('kotlin');
      expect(unregistered).toBe(true);
      expect(getAstPluginForFile('Main.kt')).toBeUndefined();
    });

    it('supports priority overrides for custom grammar parsers', () => {
      const customTsPlugin: AstParserPlugin = {
        language: 'typescript-custom',
        extensions: ['.ts'],
        priority: 100, // Higher than default 10
        parseSymbols: (): AstSymbol[] => [
          {
            name: 'customOverrideSymbol',
            kind: 'function',
            isExported: true,
          },
        ],
      };

      registerAstPlugin(customTsPlugin);

      const plugin = getAstPluginForFile('index.ts');
      expect(plugin?.language).toBe('typescript-custom');

      const symbols = parseSourceSymbols('function whatever() {}', 'index.ts');
      expect(symbols[0].name).toBe('customOverrideSymbol');

      // Reset restores default built-in
      resetAstPluginRegistry();
      const restoredPlugin = getAstPluginForFile('index.ts');
      expect(restoredPlugin?.language).toBe('typescript');
    });
  });

  describe('End-to-End Evidence Capture with Custom Plugin', () => {
    it('captures AST evidence for custom plugin file and calculates semantic diff', async () => {
      // Register custom plugin for .sql files
      registerAstPlugin({
        language: 'sql',
        extensions: ['.sql'],
        description: 'SQL table and procedure parser',
        parseSymbols: (code: string): AstSymbol[] => {
          const symbols: AstSymbol[] = [];
          const matches = code.matchAll(/CREATE\s+TABLE\s+([A-Za-z0-9_]+)/gi);
          for (const m of matches) {
            symbols.push({
              name: m[1],
              kind: 'class',
              isExported: true,
            });
          }
          return symbols;
        },
      });

      const sqlFilePath = path.join(tempWorkspace, 'schema.sql');
      await fs.promises.writeFile(
        sqlFilePath,
        'CREATE TABLE users (id INT);\nCREATE TABLE orders (id INT);',
        'utf8'
      );

      const astEvidence = await captureFileAstEvidence({
        filePath: 'schema.sql',
        workspacePath: tempWorkspace,
        compareWithGitHead: false,
      });

      expect(astEvidence.language).toBe('sql');
      expect(astEvidence.symbolsCount).toBe(2);
      expect(astEvidence.symbols[0].name).toBe('users');
      expect(astEvidence.symbols[1].name).toBe('orders');
    });
  });

  describe('CLI Integration', () => {
    it('lists registered AST language plugins via evidence-mcp ast --list-languages', async () => {
      const exitCode = await runCli(['ast', '--list-languages']);
      expect(exitCode).toBe(0);
    });
  });
});
