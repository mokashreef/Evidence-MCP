# Evidence MCP

> **Verifiable evidence collection and validation MCP server for AI coding agents.**  
> Replace unverified agent text claims ("Tests pass", "Bug fixed") with structured, verifiable local evidence.

[![CI](https://github.com/mokashreef/Evidence-MCP/actions/workflows/ci.yml/badge.svg)](https://github.com/mokashreef/Evidence-MCP/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-1.32-green.svg)](https://modelcontextprotocol.io/)

---

## The Problem

Modern AI coding agents frequently output declarations like:
- *"I have executed the test suite and all 42 tests passed."*
- *"I fixed the null pointer bug in `auth.ts`."*
- *"The repository working tree is clean and ready to deploy."*

In practice, agents may hallucinate command outputs, report results from outdated runs, or edit files without running the necessary verifications. Human reviewers and downstream agents have no systematic way to distinguish authentic execution results from plausible text assertions.

## The Solution: Evidence Bundles

**Evidence MCP** introduces the **Evidence Bundle** pattern. Instead of trusting raw text claims, coding agents assemble a structured, machine-verifiable audit trail stored locally in the workspace:

1. **Git State Capture:** Snapshots commit hashes, current branch, and clean status without mutating repository state.
2. **Command Recording:** Logs exact commands, exit codes, stdout, and stderr from executions previously conducted by the agent, explicitly tagged with `provenance: 'agent_reported'`.
3. **File Snapshots & Hashes:** Computes SHA-256 hashes and file byte sizes within strict workspace boundaries.
4. **Substantiated Assertions:** Requires every claimed achievement to be backed by at least one valid evidence reference.
5. **Freshness & Integrity Verification:** Allows reviewers or subsequent agents to re-evaluate the bundle against disk state. If any tracked file is modified or deleted, or if the Git branch/HEAD has moved, the bundle is instantly flagged as **`stale`** or **`failed`**.

```
+-------------------------------------------------------------+
|                     EVIDENCE BUNDLE                         |
|  - Task: "Refactor total discount calculation"              |
|  - Status: verified | stale | failed | unverifiable         |
+-------------------------------------------------------------+
         |                       |                     |
         v                       v                     v
  +--------------+       +---------------+      +--------------+
  |  Git State   |       | Command Logs  |      | File Hashes  |
  |  - Branch    |       | (Agent-       |      |  - SHA-256   |
  |  - HEAD SHA  |       |  Reported)    |      |  - File Size |
  |  - Status    |       |  - Exit Code  |      |  - Path      |
  | (Verified)   |       | (Unverified)  |      | (Verified)   |
  +--------------+       +---------------+      +--------------+
         \                       |                     /
          \                      |                    /
           +---------------------+-------------------+
                                 |
                                 v
                     +-----------------------+
                     | Assertions & Claims   |
                     | (Must link to proof)  |
                     +-----------------------+
```

---

## Trust Model & Verification Boundaries

Evidence MCP establishes an explicit, honest trust boundary between what can and cannot be independently verified:

| Evidence Type | Source | Verification Mechanism | Status during `verify_evidence_bundle` |
|---|---|---|---|
| **File Snapshots** | Local Filesystem | Recomputed SHA-256 hash and byte size against on-disk files | `verified`, `stale`, or `failed` |
| **Git State** | Git Repository | Re-queried Git CLI for branch, HEAD commit, and working tree cleanliness | `verified`, `stale`, or `failed` |
| **Command Execution** | Agent Input | Recorded as self-reported execution logs (`provenance: 'agent_reported'`) | `unverifiable` (acknowledged log, not verified) |

### Assertion Verification Rules
- **Independently Backed:** An assertion supported by at least one verified file snapshot or Git state receives `verified` status.
- **Agent-Reported Only:** An assertion relying *exclusively* on command evidence is marked as `unverifiable`. It cannot receive `verified` status because the server does not execute or sandbox the command in v0.1.
- **Integrity Invalidation:** If any supporting file is altered (`stale`) or removed (`failed`), the assertion is marked accordingly.

---

## Architecture & Storage

All data is stored locally in human-readable JSON files inside the workspace root:

```text
<workspace>/
├── .evidence-mcp/
│   ├── .gitignore             # Automatically ignores .evidence-mcp/ from Git
│   └── bundles/
│       └── bundle_<id>.json   # Individual evidence bundle file
```

- **Zero Remote Dependencies:** Operates entirely offline with standard Node.js runtime.
- **Atomic Writes:** Bundle updates are written to temporary files and renamed atomically to prevent corrupted files.
- **Clean Git Integration:** The `.evidence-mcp/` folder creates its own internal `.gitignore` so bundle persistence never pollutes repository status.

---

## Tools Catalog (v0.1.1)

Evidence MCP provides seven focused tools through the Model Context Protocol:

| Tool | Purpose | Key Inputs | Output |
|---|---|---|---|
| `create_evidence_bundle` | Initializes a new evidence bundle for a task | `task`, `workspacePath`, `metadata?` | `bundleId`, initial status (`in_progress`) |
| `capture_git_evidence` | Safely records Git HEAD, branch, and status | `bundleId`, `workspacePath?` | `evidenceId`, `branch`, `headCommit`, `isClean` |
| `record_command_result` | Logs agent-reported command execution result (provenance: agent_reported) | `bundleId`, `command`, `exitCode`, `stdout`, `stderr` | `evidenceId`, `command`, `exitCode`, `provenance` |
| `snapshot_files` | Computes SHA-256 and size for regular files inside workspace | `bundleId`, `paths` | `snapshots: [{ evidenceId, path, sha256, sizeBytes }]` |
| `add_assertion` | Attaches a claim linked to supporting evidence | `bundleId`, `claim`, `evidenceIds` (min 1) | `assertionId`, `claim`, `evidenceIds` |
| `verify_evidence_bundle` | Validates file hashes and Git state against live workspace | `bundleId`, `workspacePath?` | `status` (`verified` \| `stale` \| `failed` \| `unverifiable`), `items`, `reasons` |
| `export_evidence_report` | Generates a shareable Markdown or JSON report | `bundleId`, `format` (`markdown` \| `json`) | Formatted report ready for PR or handoff |

---

## Step-by-Step Usage Example

Here is how an agent interacts with Evidence MCP during a coding assignment:

### 1. Initialize a Bundle
```json
// Call: create_evidence_bundle
{
  "task": "Add email validation to user registration schema",
  "workspacePath": "/path/to/project"
}
```
*Returns:* `{ "bundleId": "bundle_9a41f0bc", "status": "in_progress" }`

### 2. Capture Git State Before or During Changes
```json
// Call: capture_git_evidence
{
  "bundleId": "bundle_9a41f0bc"
}
```
*Returns:* `{ "evidenceId": "git_7b2e11d0", "branch": "feat/email-validation", "headCommit": "4f9d2a1...", "isClean": true }`

### 3. Snapshot Changed Files
```json
// Call: snapshot_files
{
  "bundleId": "bundle_9a41f0bc",
  "paths": ["src/validators/email.ts", "test/email.test.ts"]
}
```
*Returns:*
```json
{
  "snapshots": [
    {
      "evidenceId": "file_81c4e101",
      "path": "src/validators/email.ts",
      "sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      "sizeBytes": 482
    }
  ]
}
```

### 4. Record Command Execution Results
```json
// Call: record_command_result
{
  "bundleId": "bundle_9a41f0bc",
  "command": "npm test -- email.test.ts",
  "exitCode": 0,
  "stdout": "PASS test/email.test.ts\n✓ validates standard emails (12ms)\n✓ rejects missing TLD (4ms)",
  "stderr": ""
}
```
*Returns:* `{ "evidenceId": "cmd_43a0e991", "provenance": "agent_reported", "exitCode": 0 }`

### 5. Link Claims to Evidence
```json
// Call: add_assertion
{
  "bundleId": "bundle_9a41f0bc",
  "claim": "Email validation logic implemented and passes all unit tests",
  "evidenceIds": ["file_81c4e101", "cmd_43a0e991", "git_7b2e11d0"]
}
```
*Notice: Submitting claims without supporting evidence IDs is strictly rejected. Claims backed only by command results will be marked as `unverifiable`.*

### 6. Verify Bundle Freshness
```json
// Call: verify_evidence_bundle
{
  "bundleId": "bundle_9a41f0bc"
}
```
*Returns:*
```json
{
  "status": "verified",
  "summary": "All assertions are backed by independently verified evidence.",
  "reasons": [],
  "items": [...]
}
```

### 7. Export Handoff Report
```json
// Call: export_evidence_report
{
  "bundleId": "bundle_9a41f0bc",
  "format": "markdown"
}
```
*Returns a structured GitHub Flavored Markdown report ready to paste directly into a PR description or issue.*

---

## Security & Privacy Model

- **Zero Telemetry & Tracking:** Evidence MCP contains no analytics, telemetry, or network calls.
- **Strict Path Sandboxing:** Prevents path traversal (`../`) and verifies that every snapshotted file strictly resides within the declared `workspacePath`.
- **Symlink Protection:** Resolves canonical real filesystem paths (`fs.realpathSync`) for both workspace and targets. In v0.1, symbolic links are explicitly rejected for file snapshots to prevent symlink traversal and confusion attacks.
- **Sensitive File Blocklist:** Automatically blocks snapshotting of secret files:
  - Environment variables: `.env`, `.env.*` (e.g., `.env.local`, `.env.production`)
  - Private keys: `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, `*.pfx`, `*.p12`
  - Secrets and credentials: `credentials.json`, `service-account*.json`, `token.json`
  - VCS & auth configs: `.git/config`, `.npmrc`, `.pypirc`
- **Safe Read-Only Git:** Uses strict `execFile` without shell invocation and only runs non-mutating Git inspection commands (`status`, `rev-parse`, `diff --check`).

---

## Local Installation & Setup

### Requirements
- Node.js `>= 20.0.0`
- Git `>= 2.25.0`

### Build from Source
```bash
git clone https://github.com/mokashreef/Evidence-MCP.git
cd Evidence-MCP
npm install
npm run build
```

### MCP Client Configuration

Add Evidence MCP to your client configuration file:

```json
{
  "mcpServers": {
    "evidence-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/Evidence-MCP/dist/cli.js"]
    }
  }
}
```

---

## Development & Testing

```bash
# Typecheck
npm run typecheck

# Run test suite
npm test

# Run tests in watch mode
npm run test:watch

# Compile TypeScript
npm run build
```

---

## Scope & Boundaries (v0.1.1)

### Strictly In Scope for v0.1.1
- Local file persistence under `.evidence-mcp/bundles/`.
- Safe Git state capture (read-only).
- Recording command outputs provided by the agent (explicitly marked with `agent_reported` provenance).
- Workspace-confined SHA-256 file snapshots (regular files only; symlinks rejected).
- Mandatory evidence-linked assertions.
- Live verification of file hashes and Git status.
- Clear distinction between verified on-disk evidence and unverifiable agent logs.
- Markdown and JSON report exporting.

### Out of Scope for v0.1.1
- **Direct Shell Command Execution:** In v0.1.1, `record_command_result` records results provided by agents. The server does not execute arbitrary shell strings from client inputs.
- **Remote Publishing / Cloud Syncing:** Evidence bundles are local to the workspace. There is no auto-pushing to remote cloud APIs or external issue trackers.
- **Cryptographic Signatures (PKI):** Bundles rely on SHA-256 content hashes and Git commit trees; asymmetric GPG/Ed25519 bundle signing is reserved for future versions.

---

## Roadmap

- **v0.2:** Containerized sandbox execution runner for reproducible, server-verified command execution.
- **v0.3:** Asymmetric cryptographic signatures for bundle author attestation.
- **v0.4:** Multi-workspace support for cross-repository monorepo changes.
- **v0.5:** Diff-level syntax tree (AST) evidence capturing.

---

## License

This project is licensed under the [MIT License](LICENSE).
