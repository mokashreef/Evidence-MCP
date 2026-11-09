import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { runConsensusScenario } from '../examples/multi-agent-consensus/orchestrate.js';

describe('Examples: Multi-Agent Consensus Orchestration', () => {
  let tempWorkspace: string;

  beforeEach(async () => {
    tempWorkspace = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'evidence-example-test-'));
  });

  afterEach(async () => {
    await fs.promises.rm(tempWorkspace, { recursive: true, force: true });
  });

  it('runs complete multi-agent consensus scenario and satisfies quorum and policy', async () => {
    const result = await runConsensusScenario(tempWorkspace);
    expect(result.bundleId).toMatch(/^bundle_/);
    expect(result.quorumPassed).toBe(true);
    expect(result.policyPassed).toBe(true);
  });
});
