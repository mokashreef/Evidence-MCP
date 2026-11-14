import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  SupportedMcpClient,
  GenerateClientConfigOptions,
  ClientConfigResult,
  WriteClientConfigOptions,
  WriteClientConfigResult,
} from './types.js';

export const SUPPORTED_MCP_CLIENTS: SupportedMcpClient[] = [
  'claude',
  'cursor',
  'gemini',
  'vscode-cline',
];

/**
 * Resolves the absolute path to dist/cli.js relative to the current module.
 */
export function getDefaultCliScriptPath(): string {
  try {
    const currentDir = path.dirname(fileURLToPath(import.meta.url));
    const candidate = path.join(currentDir, 'cli.js');
    if (fs.existsSync(candidate)) {
      return candidate;
    }
    const distCandidate = path.join(currentDir, '..', 'dist', 'cli.js');
    if (fs.existsSync(distCandidate)) {
      return path.resolve(distCandidate);
    }
    return candidate;
  } catch {
    return path.resolve(process.cwd(), 'dist', 'cli.js');
  }
}

/**
 * Returns the standard configuration file path for the requested AI client
 * on the target operating system.
 */
export function getDefaultConfigPath(
  client: SupportedMcpClient,
  workspacePath?: string,
  platform: NodeJS.Platform = process.platform,
  homeDir: string = os.homedir()
): string {
  const p = platform === 'win32' ? path.win32 : path.posix;
  const ws = workspacePath ? path.resolve(workspacePath) : process.cwd();

  switch (client) {
    case 'cursor':
      return path.join(ws, '.cursor', 'mcp.json');

    case 'claude': {
      if (platform === 'win32') {
        const appData = process.env.APPDATA || p.join(homeDir, 'AppData', 'Roaming');
        return p.join(appData, 'Claude', 'claude_desktop_config.json');
      }
      if (platform === 'darwin') {
        return p.join(homeDir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
      }
      // Linux / Unix fallback
      return p.join(homeDir, '.config', 'Claude', 'claude_desktop_config.json');
    }

    case 'gemini': {
      return p.join(homeDir, '.gemini', 'antigravity', 'mcp_config.json');
    }

    case 'vscode-cline': {
      if (platform === 'win32') {
        const appData = process.env.APPDATA || p.join(homeDir, 'AppData', 'Roaming');
        return p.join(
          appData,
          'Code',
          'User',
          'globalStorage',
          'saoudrizwan.claude-dev',
          'settings',
          'cline_mcp_settings.json'
        );
      }
      if (platform === 'darwin') {
        return p.join(
          homeDir,
          'Library',
          'Application Support',
          'Code',
          'User',
          'globalStorage',
          'saoudrizwan.claude-dev',
          'settings',
          'cline_mcp_settings.json'
        );
      }
      // Linux / Unix fallback
      return p.join(
        homeDir,
        '.config',
        'Code',
        'User',
        'globalStorage',
        'saoudrizwan.claude-dev',
        'settings',
        'cline_mcp_settings.json'
      );
    }

    default: {
      const exhaustiveCheck: never = client;
      throw new Error(`Unsupported client: ${String(exhaustiveCheck)}`);
    }
  }
}

/**
 * Generates an MCP server configuration snippet tailored for a specific client.
 */
export function generateClientConfig(options: GenerateClientConfigOptions): ClientConfigResult {
  const {
    client,
    workspacePath,
    serverName = 'evidence',
    useGlobalBinary = false,
    cliScriptPath,
    environmentVariables,
  } = options;

  let command: string;
  let args: string[];

  if (useGlobalBinary) {
    command = 'evidence-mcp';
    args = [];
  } else {
    command = 'node';
    const script = cliScriptPath ? path.resolve(cliScriptPath) : getDefaultCliScriptPath();
    args = [script.replace(/\\/g, '/')];
  }

  if (workspacePath) {
    args.push('--workspace', path.resolve(workspacePath).replace(/\\/g, '/'));
  }

  const serverEntry: Record<string, unknown> = {
    command,
    args,
  };

  if (environmentVariables && Object.keys(environmentVariables).length > 0) {
    serverEntry.env = environmentVariables;
  }

  if (client === 'vscode-cline') {
    serverEntry.disabled = false;
    serverEntry.autoApprove = [];
  }

  const configSnippet: Record<string, unknown> = {
    mcpServers: {
      [serverName]: serverEntry,
    },
  };

  const targetConfigPath = getDefaultConfigPath(client, workspacePath);

  return {
    client,
    serverName,
    targetConfigPath,
    configSnippet,
    command,
    args,
    env: environmentVariables,
  };
}

/**
 * Safely writes or merges the generated configuration snippet into the client's configuration file.
 * Preserves other configured MCP servers.
 */
export async function writeClientConfig(
  options: WriteClientConfigOptions
): Promise<WriteClientConfigResult> {
  const configRes = generateClientConfig(options);
  const targetPath = options.targetPath
    ? path.resolve(options.targetPath)
    : configRes.targetConfigPath;

  let existingData: Record<string, unknown> = {};
  let mergedWithExisting = false;

  if (fs.existsSync(targetPath)) {
    try {
      const raw = await fs.promises.readFile(targetPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        existingData = parsed as Record<string, unknown>;
        mergedWithExisting = true;
      }
    } catch (err: unknown) {
      if (!options.force) {
        throw new Error(
          `Failed to parse existing config at "${targetPath}": ${(err as Error).message}. Pass force: true to overwrite.`
        );
      }
    }
  }

  const existingMcpServers =
    typeof existingData.mcpServers === 'object' && existingData.mcpServers !== null
      ? (existingData.mcpServers as Record<string, unknown>)
      : {};

  const serverSnippet = (configRes.configSnippet.mcpServers as Record<string, unknown>)[
    configRes.serverName
  ];

  const mergedConfig: Record<string, unknown> = {
    ...existingData,
    mcpServers: {
      ...existingMcpServers,
      [configRes.serverName]: serverSnippet,
    },
  };

  const totalServersInFile = Object.keys(
    mergedConfig.mcpServers as Record<string, unknown>
  ).length;

  await fs.promises.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.promises.writeFile(targetPath, JSON.stringify(mergedConfig, null, 2) + '\n', 'utf8');

  return {
    ...configRes,
    writtenToPath: targetPath,
    mergedWithExisting,
    totalServersInFile,
  };
}
