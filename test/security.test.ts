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
      expect(validated).toBe(fs.realpathSync(tempWorkspace));
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
      expect(result.absolutePath).toBe(fs.realpathSync(target));
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

  describe('Symbolic Link Escapes Prevention', () => {
    it('allows a normal internal file continuing to work', async () => {
      const normalFile = path.join(tempWorkspace, 'app.ts');
      await fs.promises.writeFile(normalFile, 'export const ready = true;\n', 'utf8');

      const result = assertSafeFilePath(tempWorkspace, 'app.ts');
      expect(result.relativePath).toBe('app.ts');
      expect(result.absolutePath).toBe(fs.realpathSync(normalFile));
    });

    it('rejects a symlink inside the workspace pointing outside it', async () => {
      const outsideDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-out-'));
      const outsideFile = path.join(outsideDir, 'external.txt');
      await fs.promises.writeFile(outsideFile, 'external secret data');

      const linkPath = path.join(tempWorkspace, 'link_outside.txt');
      let symlinkCreated = false;

      try {
        await fs.promises.symlink(outsideFile, linkPath);
        symlinkCreated = true;
      } catch (err: unknown) {
        const error = err as { code?: string };
        // On Windows without Developer Mode, creating symlinks may fail with EPERM/EACCES
        console.warn(`[SKIP] Symlink creation denied by OS (${error.code}). Skipping symlink check.`);
      }

      if (symlinkCreated) {
        expect(() => assertSafeFilePath(tempWorkspace, 'link_outside.txt')).toThrow(
          /Symbolic links are rejected|Symlink escape rejected/
        );
      }

      await fs.promises.rm(outsideDir, { recursive: true, force: true });
    });

    it('rejects a symlink pointing to a sensitive external file', async () => {
      const outsideDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-env-out-'));
      const sensitiveFile = path.join(outsideDir, '.env');
      await fs.promises.writeFile(sensitiveFile, 'DATABASE_URL=postgres://...');

      const linkPath = path.join(tempWorkspace, 'link_to_env.txt');
      let symlinkCreated = false;

      try {
        await fs.promises.symlink(sensitiveFile, linkPath);
        symlinkCreated = true;
      } catch (err: unknown) {
        const error = err as { code?: string };
        console.warn(`[SKIP] Symlink creation denied by OS (${error.code}). Skipping symlink check.`);
      }

      if (symlinkCreated) {
        expect(() => assertSafeFilePath(tempWorkspace, 'link_to_env.txt')).toThrow(
          /Symbolic links are rejected|sensitive file blocked|Symlink escape rejected/
        );
      }

      await fs.promises.rm(outsideDir, { recursive: true, force: true });
    });
  });
});
