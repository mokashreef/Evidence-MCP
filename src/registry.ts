import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { AgentRegistry, AgentRegistryStatus, RegisteredAgent } from './types.js';
import { validateWorkspacePath } from './security.js';
import { computeKeyFingerprint } from './attestation.js';
import { getEvidenceDir } from './storage.js';

export function getRegistryDir(workspacePath: string): string {
  return path.join(getEvidenceDir(workspacePath), 'registry');
}

export function getRegistryFilePath(workspacePath: string): string {
  return path.join(getRegistryDir(workspacePath), 'agent-registry.json');
}

/**
 * Loads the trusted agent key registry for a workspace.
 * Returns an empty initialized registry if no registry file exists yet.
 */
export async function loadAgentRegistry(workspacePath: string): Promise<AgentRegistry> {
  const ws = validateWorkspacePath(workspacePath);
  const filePath = getRegistryFilePath(ws);

  if (!fs.existsSync(filePath)) {
    return {
      version: '1',
      workspacePath: ws,
      updatedAt: new Date().toISOString(),
      agents: {},
    };
  }

  try {
    const content = await fs.promises.readFile(filePath, 'utf8');
    const parsed = JSON.parse(content) as AgentRegistry;
    return parsed;
  } catch (err: unknown) {
    throw new Error(`Failed to load agent registry at "${filePath}": ${(err as Error).message}`);
  }
}

/**
 * Persists the agent registry atomically to disk.
 */
export async function saveAgentRegistry(
  registry: AgentRegistry,
  workspacePath: string
): Promise<void> {
  const ws = validateWorkspacePath(workspacePath);
  const dir = getRegistryDir(ws);

  await fs.promises.mkdir(dir, { recursive: true });

  const targetPath = getRegistryFilePath(ws);
  const tempPath = `${targetPath}.${crypto.randomUUID()}.tmp`;

  registry.updatedAt = new Date().toISOString();
  registry.workspacePath = ws;

  const serialized = JSON.stringify(registry, null, 2);
  await fs.promises.writeFile(tempPath, serialized, 'utf8');
  await fs.promises.rename(tempPath, targetPath);
}

/**
 * Registers or updates a trusted agent in the workspace registry.
 */
export async function registerTrustedAgent(options: {
  workspacePath: string;
  agentId: string;
  name: string;
  role: string;
  publicKeyPem: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}): Promise<RegisteredAgent> {
  const { workspacePath, agentId, name, role, publicKeyPem, expiresAt, metadata } = options;

  if (!agentId || agentId.trim() === '') {
    throw new Error('agentId cannot be empty.');
  }

  // Validate public key format
  try {
    crypto.createPublicKey(publicKeyPem);
  } catch (err: unknown) {
    throw new Error(`Invalid PEM public key: ${(err as Error).message}`);
  }

  const fingerprint = computeKeyFingerprint(publicKeyPem);
  const registry = await loadAgentRegistry(workspacePath);

  const registeredAgent: RegisteredAgent = {
    agentId: agentId.trim(),
    name: name.trim(),
    role: role.trim(),
    publicKeyPem: publicKeyPem.trim(),
    keyFingerprint: fingerprint,
    registeredAt: new Date().toISOString(),
    expiresAt,
    status: 'active',
    metadata: metadata || {},
  };

  registry.agents[registeredAgent.agentId] = registeredAgent;
  await saveAgentRegistry(registry, workspacePath);

  return registeredAgent;
}

/**
 * Revokes an existing trusted agent in the registry.
 */
export async function revokeTrustedAgent(options: {
  workspacePath: string;
  agentId: string;
  reason: string;
}): Promise<RegisteredAgent> {
  const { workspacePath, agentId, reason } = options;

  const registry = await loadAgentRegistry(workspacePath);
  const agent = registry.agents[agentId];

  if (!agent) {
    throw new Error(`Agent "${agentId}" is not registered in this workspace registry.`);
  }

  agent.status = 'revoked';
  agent.revokedAt = new Date().toISOString();
  agent.revocationReason = reason.trim();

  await saveAgentRegistry(registry, workspacePath);
  return agent;
}

/**
 * Evaluates whether a registered agent record is currently active (not revoked, suspended, or expired).
 */
export function checkRegisteredAgentActive(agent: RegisteredAgent): {
  active: boolean;
  reason?: string;
} {
  if (agent.status === 'revoked') {
    return {
      active: false,
      reason: `Agent "${agent.agentId}" key was revoked on ${agent.revokedAt}: ${agent.revocationReason}`,
    };
  }

  if (agent.status === 'suspended') {
    return {
      active: false,
      reason: `Agent "${agent.agentId}" is currently suspended.`,
    };
  }

  if (agent.expiresAt) {
    const now = new Date();
    const expiry = new Date(agent.expiresAt);
    if (now > expiry) {
      return {
        active: false,
        reason: `Agent "${agent.agentId}" key expired on ${agent.expiresAt}.`,
      };
    }
  }

  return { active: true };
}

/**
 * Synchronously loads the trusted agent key registry if it exists on disk.
 * Never swallows JSON parse errors if the registry file is corrupted.
 */
export function loadAgentRegistrySync(workspacePath: string): {
  exists: boolean;
  registry: AgentRegistry;
} {
  if (!workspacePath || !fs.existsSync(path.resolve(workspacePath))) {
    return {
      exists: false,
      registry: {
        version: '1',
        workspacePath: workspacePath || '',
        updatedAt: new Date().toISOString(),
        agents: {},
      },
    };
  }

  const ws = validateWorkspacePath(workspacePath);
  const filePath = getRegistryFilePath(ws);

  if (!fs.existsSync(filePath)) {
    return {
      exists: false,
      registry: {
        version: '1',
        workspacePath: ws,
        updatedAt: new Date().toISOString(),
        agents: {},
      },
    };
  }

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(content) as AgentRegistry;
    return { exists: true, registry: parsed };
  } catch (err: unknown) {
    throw new Error(`Failed to load agent registry at "${filePath}": ${(err as Error).message}`);
  }
}

export interface RegistryVerificationStatus {
  registryExists: boolean;
  registered: boolean;
  active: boolean;
  agent?: RegisteredAgent;
  reason?: string;
}

/**
 * Synchronously verifies a signer against the workspace trusted agent key registry,
 * checking revocation, suspension, expiration, and cryptographic fingerprint binding.
 */
export function verifyAgentKeyStatusSync(options: {
  workspacePath: string;
  agentId?: string;
  keyFingerprint: string;
}): RegistryVerificationStatus {
  const { workspacePath, agentId, keyFingerprint } = options;
  const { exists, registry } = loadAgentRegistrySync(workspacePath);
  const agentsList = Object.values(registry.agents || {});

  const byFp = agentsList.find((a) => a.keyFingerprint === keyFingerprint);
  const byId = agentId ? registry.agents?.[agentId] : undefined;

  // Reject any explicitly revoked/suspended/expired key fingerprint regardless of claimed agentId
  if (byFp) {
    const fpActive = checkRegisteredAgentActive(byFp);
    if (!fpActive.active) {
      return {
        registryExists: exists,
        registered: true,
        active: false,
        agent: byFp,
        reason: fpActive.reason,
      };
    }
  }

  if (byId) {
    const idActive = checkRegisteredAgentActive(byId);
    if (!idActive.active) {
      return {
        registryExists: exists,
        registered: true,
        active: false,
        agent: byId,
        reason: idActive.reason,
      };
    }

    if (byId.keyFingerprint !== keyFingerprint) {
      return {
        registryExists: exists,
        registered: true,
        active: false,
        agent: byId,
        reason: `Agent "${byId.agentId}" presented public key fingerprint "${keyFingerprint}", which does not match registered fingerprint "${byId.keyFingerprint}".`,
      };
    }

    return {
      registryExists: exists,
      registered: true,
      active: true,
      agent: byId,
    };
  }

  if (byFp) {
    return {
      registryExists: exists,
      registered: true,
      active: true,
      agent: byFp,
    };
  }

  const label = agentId ? `${agentId} (${keyFingerprint.slice(0, 12)}...)` : keyFingerprint;
  return {
    registryExists: exists,
    registered: false,
    active: false,
    reason: `Signer "${label}" is not registered in the workspace trusted agent key registry.`,
  };
}

/**
 * Checks whether an agent identity or public key fingerprint is registered and currently active.
 */
export async function getAgentKeyStatus(
  workspacePath: string,
  identifier: string // agentId or keyFingerprint
): Promise<{
  registered: boolean;
  agent?: RegisteredAgent;
  active: boolean;
  reason?: string;
}> {
  const registry = await loadAgentRegistry(workspacePath);

  // Search by agentId or fingerprint
  let foundAgent: RegisteredAgent | undefined = registry.agents[identifier];
  if (!foundAgent) {
    foundAgent = Object.values(registry.agents).find(
      (a) => a.keyFingerprint === identifier || a.agentId === identifier
    );
  }

  if (!foundAgent) {
    return {
      registered: false,
      active: false,
      reason: `Agent key "${identifier}" is not found in trusted registry.`,
    };
  }

  const activeCheck = checkRegisteredAgentActive(foundAgent);
  return {
    registered: true,
    agent: foundAgent,
    active: activeCheck.active,
    reason: activeCheck.reason,
  };
}

/**
 * Lists all registered agents in the workspace.
 */
export async function listTrustedAgents(
  workspacePath: string,
  filterStatus: 'active' | 'revoked' | 'suspended' | 'all' = 'all'
): Promise<RegisteredAgent[]> {
  const registry = await loadAgentRegistry(workspacePath);
  const list = Object.values(registry.agents);

  if (filterStatus === 'all') {
    return list;
  }

  return list.filter((a) => a.status === filterStatus);
}

