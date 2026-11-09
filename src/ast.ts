import fs from 'node:fs';
import path from 'node:path';
import {
  AstEvidence,
  AstParameter,
  AstSemanticDiff,
  AstSymbol,
  AstSymbolKind,
} from './types.js';
import { assertSafeFilePath } from './security.js';
import { getFileContentAtGitHead } from './git.js';
import { generateId } from './storage.js';

export function detectLanguage(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  switch (ext) {
    case '.ts':
    case '.tsx':
    case '.mts':
    case '.cts':
      return 'typescript';
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return 'javascript';
    case '.json':
      return 'json';
    case '.py':
      return 'python';
    default:
      return 'other';
  }
}

/**
 * Splits parameter list string respecting nested brackets and strings.
 */
export function parseParameters(rawParams: string): AstParameter[] {
  const cleaned = rawParams.trim().replace(/^\(|\)$/g, '').trim();
  if (!cleaned) return [];

  const params: AstParameter[] = [];
  let depthParen = 0;
  let depthBrace = 0;
  let depthBracket = 0;
  let inQuote: string | null = null;
  let current = '';

  for (let i = 0; i < cleaned.length; i++) {
    const char = cleaned[i];

    if (inQuote) {
      if (char === inQuote && cleaned[i - 1] !== '\\') {
        inQuote = null;
      }
      current += char;
      continue;
    }

    if (char === '"' || char === "'" || char === '`') {
      inQuote = char;
      current += char;
      continue;
    }

    if (char === '(') depthParen++;
    else if (char === ')') depthParen--;
    else if (char === '{') depthBrace++;
    else if (char === '}') depthBrace--;
    else if (char === '[') depthBracket++;
    else if (char === ']') depthBracket--;

    if (char === ',' && depthParen === 0 && depthBrace === 0 && depthBracket === 0) {
      if (current.trim()) {
        params.push(parseSingleParameter(current.trim()));
      }
      current = '';
    } else {
      current += char;
    }
  }

  if (current.trim()) {
    params.push(parseSingleParameter(current.trim()));
  }

  return params;
}

function parseSingleParameter(paramStr: string): AstParameter {
  let colonIdx = -1;
  let eqIdx = -1;

  let depthParen = 0;
  let depthBrace = 0;
  let depthBracket = 0;
  let inQuote: string | null = null;

  for (let i = 0; i < paramStr.length; i++) {
    const ch = paramStr[i];
    if (inQuote) {
      if (ch === inQuote && paramStr[i - 1] !== '\\') inQuote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      inQuote = ch;
      continue;
    }
    if (ch === '(') depthParen++;
    else if (ch === ')') depthParen--;
    else if (ch === '{') depthBrace++;
    else if (ch === '}') depthBrace--;
    else if (ch === '[') depthBracket++;
    else if (ch === ']') depthBracket--;

    if (depthParen === 0 && depthBrace === 0 && depthBracket === 0) {
      if (ch === ':' && colonIdx === -1 && eqIdx === -1) {
        colonIdx = i;
      } else if (ch === '=' && paramStr[i + 1] !== '>' && eqIdx === -1) {
        eqIdx = i;
      }
    }
  }

  let namePart = '';
  let typePart: string | undefined;
  let defaultPart: string | undefined;

  if (eqIdx !== -1) {
    defaultPart = paramStr.slice(eqIdx + 1).trim();
    const beforeEq = paramStr.slice(0, eqIdx).trim();
    if (colonIdx !== -1 && colonIdx < eqIdx) {
      namePart = beforeEq.slice(0, colonIdx).trim();
      typePart = beforeEq.slice(colonIdx + 1).trim();
    } else {
      namePart = beforeEq;
    }
  } else if (colonIdx !== -1) {
    namePart = paramStr.slice(0, colonIdx).trim();
    typePart = paramStr.slice(colonIdx + 1).trim();
  } else {
    namePart = paramStr.trim();
  }

  const isOptional = namePart.endsWith('?') || defaultPart !== undefined;
  const name = namePart.replace(/\?$/, '').trim();

  return {
    name,
    optional: isOptional,
    type: typePart,
    defaultValue: defaultPart,
  };
}

/**
 * Parses source code into semantic AST symbols.
 */
export function parseSourceSymbols(sourceCode: string, filePath: string): AstSymbol[] {
  const lang = detectLanguage(filePath);

  if (lang === 'json') {
    return parseJsonSymbols(sourceCode);
  }

  if (lang === 'typescript' || lang === 'javascript') {
    return parseTsJsSymbols(sourceCode);
  }

  if (lang === 'python') {
    return parsePythonSymbols(sourceCode);
  }

  return [];
}

function parseJsonSymbols(jsonContent: string): AstSymbol[] {
  try {
    const data = JSON.parse(jsonContent);
    if (!data || typeof data !== 'object') return [];

    const symbols: AstSymbol[] = [];
    const keys = Object.keys(data);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const val = (data as Record<string, unknown>)[key];
      const valType = Array.isArray(val) ? 'array' : typeof val;
      symbols.push({
        name: key,
        kind: 'variable',
        isExported: true,
        signature: `${key}: ${valType}`,
        startLine: i + 1,
        endLine: i + 1,
      });
    }
    return symbols;
  } catch {
    return [];
  }
}

function parseTsJsSymbols(sourceCode: string): AstSymbol[] {
  const symbols: AstSymbol[] = [];
  const lines = sourceCode.split('\n');

  // Regex patterns for top-level / class-level declarations
  const interfaceRegex = /^(?:export\s+)?interface\s+([A-Za-z0-9_$]+)/;
  const typeRegex = /^(?:export\s+)?type\s+([A-Za-z0-9_$]+)/;
  const classRegex = /^(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z0-9_$]+)/;
  const enumRegex = /^(?:export\s+)?enum\s+([A-Za-z0-9_$]+)/;
  const functionRegex = /^(?:export\s+)?(?:async\s+)?function\s+([A-Za-z0-9_$]+)\s*\((.*?)\)(?:\s*:\s*([^;{]+))?/;
  const arrowFunctionRegex =
    /^(?:export\s+)?(?:const|let)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\((.*?)\)(?:\s*:\s*([^;=]+))?\s*=>/;
  const exportConstRegex =
    /^export\s+(?:const|let|var)\s+([A-Za-z0-9_$]+)(?:\s*:\s*([^;=]+))?(?:\s*=\s*([^;]+))?/;
  const methodRegex =
    /^\s+(?:(?:public|private|protected|static|async)\s+)*([A-Za-z0-9_$]+)\s*\((.*?)\)(?:\s*:\s*([^;{]+))?/;

  let insideClass = false;
  let currentClassName = '';

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    const lineNum = i + 1;

    // Skip empty lines or comment-only lines
    if (!line || line.startsWith('//') || line.startsWith('/*') || line.startsWith('*')) {
      continue;
    }

    // Check Class
    const classMatch = line.match(classRegex);
    if (classMatch) {
      insideClass = true;
      currentClassName = classMatch[1];
      const isExported = line.startsWith('export');
      symbols.push({
        name: currentClassName,
        kind: 'class',
        isExported,
        signature: `class ${currentClassName}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Interface
    const ifaceMatch = line.match(interfaceRegex);
    if (ifaceMatch) {
      symbols.push({
        name: ifaceMatch[1],
        kind: 'interface',
        isExported: line.startsWith('export'),
        signature: `interface ${ifaceMatch[1]}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Type Alias
    const typeMatch = line.match(typeRegex);
    if (typeMatch) {
      symbols.push({
        name: typeMatch[1],
        kind: 'type',
        isExported: line.startsWith('export'),
        signature: `type ${typeMatch[1]}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Enum
    const enumMatch = line.match(enumRegex);
    if (enumMatch) {
      symbols.push({
        name: enumMatch[1],
        kind: 'enum',
        isExported: line.startsWith('export'),
        signature: `enum ${enumMatch[1]}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Function Declaration
    const funcMatch = line.match(functionRegex);
    if (funcMatch) {
      const name = funcMatch[1];
      const rawParams = funcMatch[2] || '';
      const returnType = funcMatch[3]?.trim();
      const params = parseParameters(rawParams);
      const isExported = line.startsWith('export');
      const isAsync = line.includes('async ');

      symbols.push({
        name,
        kind: 'function',
        isExported,
        isAsync,
        parameters: params,
        returnType,
        signature: `function ${name}(${params.map((p) => `${p.name}${p.optional ? '?' : ''}${p.type ? `: ${p.type}` : ''}`).join(', ')})${returnType ? `: ${returnType}` : ''}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Arrow Function
    const arrowMatch = line.match(arrowFunctionRegex);
    if (arrowMatch) {
      const name = arrowMatch[1];
      const rawParams = arrowMatch[2] || '';
      const returnType = arrowMatch[3]?.trim();
      const params = parseParameters(rawParams);
      const isExported = line.startsWith('export');
      const isAsync = line.includes('async');

      symbols.push({
        name,
        kind: 'function',
        isExported,
        isAsync,
        parameters: params,
        returnType,
        signature: `const ${name} = (${params.map((p) => `${p.name}${p.optional ? '?' : ''}${p.type ? `: ${p.type}` : ''}`).join(', ')})${returnType ? `: ${returnType}` : ''} =>`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Exported Constant
    const constMatch = line.match(exportConstRegex);
    if (constMatch) {
      const name = constMatch[1];
      const type = constMatch[2]?.trim();
      symbols.push({
        name,
        kind: 'variable',
        isExported: true,
        signature: `const ${name}${type ? `: ${type}` : ''}`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Class Method
    if (insideClass) {
      if (line === '}') {
        insideClass = false;
        currentClassName = '';
        continue;
      }
      const methodMatch = lines[i].match(methodRegex);
      if (
        methodMatch &&
        !['if', 'for', 'while', 'switch', 'catch', 'constructor'].includes(methodMatch[1])
      ) {
        const name = methodMatch[1];
        const rawParams = methodMatch[2] || '';
        const returnType = methodMatch[3]?.trim();
        const params = parseParameters(rawParams);
        symbols.push({
          name: `${currentClassName}.${name}`,
          kind: 'method',
          isExported: true,
          parameters: params,
          returnType,
          signature: `${name}(${params.map((p) => `${p.name}${p.optional ? '?' : ''}${p.type ? `: ${p.type}` : ''}`).join(', ')})${returnType ? `: ${returnType}` : ''}`,
          startLine: lineNum,
          endLine: lineNum,
        });
      }
    }
  }

  return symbols;
}

function parsePythonSymbols(sourceCode: string): AstSymbol[] {
  const symbols: AstSymbol[] = [];
  const lines = sourceCode.split('\n');

  const classRegex = /^(?:class\s+)([A-Za-z0-9_]+)(?:\((.*?)\))?\s*:/;
  const defRegex = /^(\s*)(async\s+)?def\s+([A-Za-z0-9_]+)\s*\((.*?)\)(?:\s*->\s*([^:]+))?\s*:/;

  let currentClassName = '';
  let classIndentLevel = -1;

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    const trimmed = rawLine.trim();
    const lineNum = i + 1;

    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const currentIndent = rawLine.search(/\S/);

    // If inside class and indent drops to <= class indent, exit class
    if (classIndentLevel !== -1 && currentIndent <= classIndentLevel && !trimmed.startsWith('@')) {
      currentClassName = '';
      classIndentLevel = -1;
    }

    // Check Class declaration
    const classMatch = rawLine.trim().match(classRegex);
    if (classMatch && currentIndent === 0) {
      const name = classMatch[1];
      const bases = classMatch[2]?.trim();
      const isExported = !name.startsWith('_');
      currentClassName = name;
      classIndentLevel = currentIndent;

      symbols.push({
        name,
        kind: 'class',
        isExported,
        signature: `class ${name}${bases ? `(${bases})` : ''}:`,
        startLine: lineNum,
        endLine: lineNum,
      });
      continue;
    }

    // Check Function or Method declaration
    const defMatch = rawLine.match(defRegex);
    if (defMatch) {
      const indentStr = defMatch[1] || '';
      const isAsync = Boolean(defMatch[2]);
      const name = defMatch[3];
      const rawParams = defMatch[4] || '';
      const returnType = defMatch[5]?.trim();
      const isInsideClass = currentClassName !== '' && indentStr.length > classIndentLevel;

      const isExported = !name.startsWith('_') || name === '__init__';
      const kind: AstSymbolKind = isInsideClass ? 'method' : 'function';
      const fullName = isInsideClass ? `${currentClassName}.${name}` : name;
      const params = parseParameters(rawParams);

      const asyncPrefix = isAsync ? 'async ' : '';
      const returnSuffix = returnType ? ` -> ${returnType}` : '';
      const signature = `${asyncPrefix}def ${name}(${params.map((p) => `${p.name}${p.type ? `: ${p.type}` : ''}${p.defaultValue ? `=${p.defaultValue}` : ''}`).join(', ')})${returnSuffix}:`;

      symbols.push({
        name: fullName,
        kind,
        isExported,
        isAsync,
        parameters: params,
        returnType,
        signature,
        startLine: lineNum,
        endLine: lineNum,
      });
    }
  }

  return symbols;
}

/**
 * Computes the semantic diff between a previous set of symbols and the current set.
 */
export function computeSemanticDiff(
  previousSymbols: AstSymbol[],
  currentSymbols: AstSymbol[],
  filePath: string
): AstSemanticDiff {
  const prevMap = new Map<string, AstSymbol>();
  for (const s of previousSymbols) {
    prevMap.set(`${s.kind}:${s.name}`, s);
  }

  const currMap = new Map<string, AstSymbol>();
  for (const s of currentSymbols) {
    currMap.set(`${s.kind}:${s.name}`, s);
  }

  const addedSymbols: AstSymbol[] = [];
  const removedSymbols: AstSymbol[] = [];
  const modifiedSymbols: { symbol: AstSymbol; previous: AstSymbol; changes: string[] }[] = [];
  let isBreakingChange = false;

  // Detect Added Symbols
  for (const curr of currentSymbols) {
    const key = `${curr.kind}:${curr.name}`;
    if (!prevMap.has(key)) {
      addedSymbols.push(curr);
    }
  }

  // Detect Removed and Modified Symbols
  for (const prev of previousSymbols) {
    const key = `${prev.kind}:${prev.name}`;
    const curr = currMap.get(key);

    if (!curr) {
      removedSymbols.push(prev);
      if (prev.isExported) {
        isBreakingChange = true;
      }
    } else {
      // Check for signature or modifier modifications
      const changes: string[] = [];

      if (prev.isExported && !curr.isExported) {
        changes.push(`Visibility changed: symbol is no longer exported.`);
        isBreakingChange = true;
      }

      const prevSig = prev.signature || '';
      const currSig = curr.signature || '';
      if (prevSig !== currSig) {
        changes.push(`Signature changed from "${prevSig}" to "${currSig}".`);
      }

      // Parameter checks for functions/methods
      if (prev.parameters && curr.parameters) {
        const prevParams = prev.parameters;
        const currParams = curr.parameters;

        // If new non-optional parameter added to exported function, that's a breaking change
        if (curr.isExported && currParams.length > prevParams.length) {
          const addedParams = currParams.slice(prevParams.length);
          const hasRequiredAdded = addedParams.some((p) => !p.optional);
          if (hasRequiredAdded) {
            changes.push(`New required parameter added to exported signature.`);
            isBreakingChange = true;
          }
        }
      }

      if (changes.length > 0) {
        modifiedSymbols.push({
          symbol: curr,
          previous: prev,
          changes,
        });
      }
    }
  }

  const hasChanges =
    addedSymbols.length > 0 || removedSymbols.length > 0 || modifiedSymbols.length > 0;

  return {
    filePath,
    hasChanges,
    isBreakingChange,
    addedSymbols,
    removedSymbols,
    modifiedSymbols,
  };
}

/**
 * Captures semantic AST evidence for a given file within a workspace.
 */
export async function captureFileAstEvidence(options: {
  filePath: string;
  workspacePath: string;
  workspaceName?: string;
  compareWithGitHead?: boolean;
}): Promise<AstEvidence> {
  const { filePath, workspacePath, workspaceName, compareWithGitHead = true } = options;

  const safePath = assertSafeFilePath(workspacePath, filePath);
  const currentContent = await fs.promises.readFile(safePath.absolutePath, 'utf8');
  const language = detectLanguage(safePath.relativePath);
  const currentSymbols = parseSourceSymbols(currentContent, safePath.relativePath);

  let diff: AstSemanticDiff | undefined;

  if (compareWithGitHead) {
    const headContent = await getFileContentAtGitHead(workspacePath, safePath.relativePath);
    if (headContent !== null) {
      const previousSymbols = parseSourceSymbols(headContent, safePath.relativePath);
      diff = computeSemanticDiff(previousSymbols, currentSymbols, safePath.relativePath);
    } else {
      // Newly added file not present in HEAD
      diff = {
        filePath: safePath.relativePath,
        hasChanges: true,
        isBreakingChange: false,
        addedSymbols: currentSymbols,
        removedSymbols: [],
        modifiedSymbols: [],
      };
    }
  }

  return {
    id: generateId('ast'),
    type: 'ast',
    capturedAt: new Date().toISOString(),
    filePath: safePath.relativePath,
    workspaceName,
    language,
    symbolsCount: currentSymbols.length,
    symbols: currentSymbols,
    diff,
  };
}
