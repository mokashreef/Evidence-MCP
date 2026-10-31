import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { computeFileSha256AndSize, computeSha256 } from '../src/hasher.js';

describe('Hasher & File Integrity', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-hash-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  it('correctly hashes strings and buffers with computeSha256', () => {
    const text = 'Evidence MCP test string';
    const expected = crypto.createHash('sha256').update(text).digest('hex');
    expect(computeSha256(text)).toBe(expected);
  });

  it('computes accurate SHA-256 and byte size for files', async () => {
    const filePath = path.join(tempWorkspace, 'test.txt');
    const content = 'Hello world from Evidence MCP!';
    await fs.promises.writeFile(filePath, content, 'utf8');

    const result = await computeFileSha256AndSize(filePath);
    const expectedHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');

    expect(result.sha256).toBe(expectedHash);
    expect(result.sizeBytes).toBe(Buffer.byteLength(content, 'utf8'));
  });

  it('throws when attempting to hash a non-existent file', async () => {
    const missingPath = path.join(tempWorkspace, 'missing.txt');
    await expect(computeFileSha256AndSize(missingPath)).rejects.toThrow(/does not exist/);
  });

  it('throws when target path is a directory instead of a regular file', async () => {
    const dirPath = path.join(tempWorkspace, 'sub-dir');
    await fs.promises.mkdir(dirPath);
    await expect(computeFileSha256AndSize(dirPath)).rejects.toThrow(/not a regular file/);
  });
});
