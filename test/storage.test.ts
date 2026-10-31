import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import {
  generateId,
  saveBundle,
  loadBundle,
  listBundles,
  getBundleFilePath,
} from '../src/storage.js';
import { EvidenceBundle } from '../src/types.js';

describe('Storage & Persistence Layer', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-mcp-store-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  it('generates IDs with expected prefixes', () => {
    expect(generateId('bundle')).toMatch(/^bundle_[a-f0-9]{8}$/);
    expect(generateId('git')).toMatch(/^git_[a-f0-9]{8}$/);
    expect(generateId('cmd')).toMatch(/^cmd_[a-f0-9]{8}$/);
    expect(generateId('file')).toMatch(/^file_[a-f0-9]{8}$/);
    expect(generateId('assert')).toMatch(/^assert_[a-f0-9]{8}$/);
  });

  it('saves and loads bundle with atomic persistence', async () => {
    const bundleId = generateId('bundle');
    const now = new Date().toISOString();
    const bundle: EvidenceBundle = {
      id: bundleId,
      task: 'Fix authentication bug',
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {
        git: [],
        commands: [],
        fileSnapshots: [],
      },
      assertions: [],
    };

    await saveBundle(bundle);

    const filePath = getBundleFilePath(tempWorkspace, bundleId);
    expect(fs.existsSync(filePath)).toBe(true);

    const loaded = await loadBundle(bundleId, tempWorkspace);
    expect(loaded.id).toBe(bundleId);
    expect(loaded.task).toBe('Fix authentication bug');
    expect(loaded.status).toBe('in_progress');
  });

  it('lists bundles stored in a workspace', async () => {
    const b1Id = generateId('bundle');
    const b2Id = generateId('bundle');
    const now = new Date().toISOString();

    const makeBundle = (id: string, task: string): EvidenceBundle => ({
      id,
      task,
      workspacePath: tempWorkspace,
      status: 'in_progress',
      createdAt: now,
      updatedAt: now,
      evidence: {},
      assertions: [],
    });

    await saveBundle(makeBundle(b1Id, 'Task 1'));
    await saveBundle(makeBundle(b2Id, 'Task 2'));

    const bundles = await listBundles(tempWorkspace);
    expect(bundles.length).toBe(2);
    const ids = bundles.map((b) => b.id);
    expect(ids).toContain(b1Id);
    expect(ids).toContain(b2Id);
  });

  it('throws for missing bundle', async () => {
    await expect(loadBundle('bundle_nonexistent', tempWorkspace)).rejects.toThrow(/not found/);
  });

  it('rejects invalid or traversal bundle IDs', () => {
    expect(() => getBundleFilePath(tempWorkspace, '../bad-id')).toThrow(/Invalid bundleId format/);
    expect(() => getBundleFilePath(tempWorkspace, 'foo/bar')).toThrow(/Invalid bundleId format/);
  });
});
