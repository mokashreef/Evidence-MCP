import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { assertSafeFilePath, isSensitivePath, validateWorkspacePath } from '../src/security.js';

describe('Security & Path Confinement', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-sec-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  describe('validateWorkspacePath', () => {
    it('accepts valid existing workspace directory', () => {
      const validated = validateWorkspacePath(tempWorkspace);
      expect(validated).toBe(path.resolve(tempWorkspace));
    });

    it('rejects non-existent directory', () => {
      const nonExistent = path.join(tempWorkspace, 'does-not-exist');
      expect(() => validateWorkspacePath(nonExistent)).toThrow(/does not exist/);
    });

    it('rejects file path when directory is required', async () => {
      const filePath = path.join(tempWorkspace, 'test.txt');
      await fs.promises.writeFile(filePath, 'hello');
      expect(() => validateWorkspacePath(filePath)).toThrow(/not a directory/);
    });

    it('rejects empty or whitespace workspace path', () => {
      expect(() => validateWorkspacePath('')).toThrow(/non-empty string/);
      expect(() => validateWorkspacePath('   ')).toThrow(/non-empty string/);
    });
  });

  describe('Path Traversal Prevention', () => {
    it('allows valid relative files within workspace', async () => {
      const target = path.join(tempWorkspace, 'src', 'index.ts');
      await fs.promises.mkdir(path.dirname(target), { recursive: true });
      await fs.promises.writeFile(target, 'console.log(1);');

      const result = assertSafeFilePath(tempWorkspace, 'src/index.ts');
      expect(result.absolutePath).toBe(path.resolve(target));
      expect(result.relativePath).toBe('src/index.ts');
    });

    it('rejects upward traversal using ../', () => {
      expect(() => assertSafeFilePath(tempWorkspace, '../secret.txt')).toThrow(/Path traversal rejected/);
      expect(() => assertSafeFilePath(tempWorkspace, 'foo/../../secret.txt')).toThrow(/Path traversal rejected/);
    });

    it('rejects absolute paths outside workspace', () => {
      const outsidePath = path.resolve(tempWorkspace, '..', 'other.txt');
      expect(() => assertSafeFilePath(tempWorkspace, outsidePath)).toThrow(/Path traversal rejected/);
    });

    it('rejects paths containing null bytes', () => {
      expect(() => assertSafeFilePath(tempWorkspace, 'foo\0bar.txt')).toThrow(/Null bytes/);
    });
  });

  describe('Sensitive Files Rejection', () => {
    const sensitiveNames = [
      '.env',
      '.env.local',
      '.env.production',
      '.env.staging',
      'id_rsa',
      'id_rsa.pub',
      'id_ed25519',
      'server.key',
      'cert.pem',
      'bundle.pfx',
      'credentials.json',
      'client_secret.json',
      'service-account-key.json',
      'token.json',
      '.npmrc',
      '.pypirc',
      '.git/config',
    ];

    for (const name of sensitiveNames) {
      it(`identifies "${name}" as sensitive`, () => {
        expect(isSensitivePath(name)).toBe(true);
      });

      it(`assertSafeFilePath blocks "${name}"`, () => {
        expect(() => assertSafeFilePath(tempWorkspace, name)).toThrow(/sensitive file blocked/i);
      });
    }

    it('allows non-sensitive standard files', () => {
      expect(isSensitivePath('package.json')).toBe(false);
      expect(isSensitivePath('src/index.ts')).toBe(false);
      expect(isSensitivePath('README.md')).toBe(false);
      expect(isSensitivePath('.env.example')).toBe(false);
    });
  });
});
