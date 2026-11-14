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
                     | (Evidence links)      |
                     +-----------------------+
```

---

## Trust Model & Verification Boundaries

Evidence MCP establishes an explicit, honest trust boundary between what can and cannot be independently verified:

| Evidence Type | Source | Verification Mechanism | Status during `verify_evidence_bundle` |
|---|---|---|---|
| **File Snapshots** | Local Filesystem | Recomputed SHA-256 hash and byte size against on-disk files | `verified`, `stale`, or `failed` |
| **Git State** | Git Repository | Re-queried Git CLI for branch, HEAD commit, and working tree cleanliness | `verified`, `stale`, or `failed` |
| **AST & Semantic Evidence** | Local Source Files & Git HEAD | Zero-dependency structural symbol parsing and live disk comparison | `verified`, `stale`, or `failed` |
| **Server-Executed Commands** | Sandboxed Process Runner | Directly spawned by Evidence MCP (`provenance: 'server_executed'`) with real exit code, duration, and output | `verified` (exit 0) or `failed` (exit != 0) |
| **Agent-Reported Commands** | Agent Client Input | Recorded as self-reported execution logs (`provenance: 'agent_reported'`) | `unverifiable` (acknowledged log, not verified) |
| **Cryptographic Attestation** | Ed25519 Keypair | Asymmetric digital signature verified over canonical recursive JSON payload | `verified` (authentic) or `failed` (tampered) |

### Assertion Verification Rules
- **Independently Backed:** An assertion supported by at least one verified file snapshot, Git state, AST semantic evidence, or server-executed command receives `verified` status.
- **Agent-Reported Only:** An assertion relying *exclusively* on self-reported command evidence is marked as `unverifiable`. It cannot receive `verified` status because the server did not execute or observe the process.
- **Integrity Invalidation:** If any supporting file is altered (`stale`) or removed (`failed`), or if a supporting server-executed command failed with non-zero exit code, the assertion is marked accordingly.

---

## Architecture & Storage

All data is stored locally in human-readable JSON files inside the workspace root:

```text
<workspace>/
├── .evidence-mcp/
│   ├── .gitignore             # Automatically ignores .evidence-mcp/ from Git
│   ├── bundles/
│   │   └── bundle_<id>.json   # Individual evidence bundle file
│   ├── keys/
│   │   ├── agent.key          # Local Ed25519 private key
│   │   └── agent.pub          # Local Ed25519 public key
│   └── proofs/
│       └── proof_<id>.json    # Cryptographically signed portable verification proofs
```

- **Zero Remote Dependencies:** Operates entirely offline with standard Node.js runtime.
- **Atomic Writes:** Bundle and proof updates are written to temporary files and renamed atomically to prevent corrupted files.
- **Clean Git Integration:** The `.evidence-mcp/` folder creates its own internal `.gitignore` so bundle persistence never pollutes repository status.

---

## Tools Catalog (v1.5.0)

Evidence MCP provides twenty-four focused tools through the Model Context Protocol:

| Tool | Purpose | Key Inputs | Output |
|---|---|---|---|
| `create_evidence_bundle` | Initializes a new evidence bundle for a task | `task`, `workspacePath`, `metadata?`, `additionalWorkspaces?` | `bundleId`, initial status (`in_progress`) |
| `register_workspace` | Dynamically binds a named monorepo package or secondary repository | `bundleId`, `name`, `path` | `workspaceName`, `workspacePath`, `allWorkspaces` |
| `capture_git_evidence` | Safely records Git HEAD, branch, and status in targeted workspace | `bundleId`, `workspaceName?`, `workspacePath?` | `evidenceId`, `branch`, `headCommit`, `isClean` |
| `capture_ast_evidence` | Extracts multi-language AST symbols and semantic diffs via modular plugins | `bundleId`, `files`, `workspaceName?`, `compareWithGitHead?` | `astEvidence: [{ id, filePath, symbolsCount, hasSemanticChanges, isBreakingChange }]` |
| `execute_verified_command` | Spawns an approved command in sandboxed runner with concurrency bounds | `bundleId`, `command`, `args?`, `cwd?`, `workspaceName?` | `evidenceId`, `exitCode`, `durationMs`, `provenance: server_executed` |
| `record_command_result` | Logs agent-reported command execution result (provenance: agent_reported) | `bundleId`, `command`, `exitCode`, `stdout`, `stderr`, `workspaceName?` | `evidenceId`, `command`, `exitCode`, `provenance` |
| `snapshot_files` | Computes SHA-256 and size for regular files inside workspace boundary | `bundleId`, `paths`, `workspaceName?` | `snapshots: [{ evidenceId, workspaceName, path, sha256 }]` |
| `add_assertion` | Attaches a claim linked to supporting evidence | `bundleId`, `claim`, `evidenceIds` (min 1) | `assertionId`, `claim`, `evidenceIds` |
| `sign_evidence_bundle` | Cryptographically signs the bundle using native Ed25519 | `bundleId`, `agentId?`, `privateKeyPath?` | `attestation: { agentId, algorithm, publicKey, signature }` |
| `verify_evidence_bundle` | Validates file hashes, Git state, AST symbols, command results, signatures, and registry state | `bundleId`, `workspacePath?` | `status` (`verified` \| `stale` \| `failed` \| `unverifiable`), `items`, `reasons` |
| `export_evidence_report` | Generates a shareable Markdown, JSON, HTML, or SARIF v2.1.0 report | `bundleId`, `format` (`markdown` \| `json` \| `html` \| `sarif`), `policyPath?` | Formatted report ready for PR, handoff, or GitHub Code Scanning |
| `export_verification_proof` | Issues an Ed25519 cryptographically signed portable verification proof | `bundleId`, `privateKeyPem?`, `workspacePath?` | `proofId`, `verdict`, `bundleDigest`, `signature` |
| `verify_replay_proof` | Verifies cryptographic signature and digest consistency of an exported proof | `proofId?`, `proofJson?`, `bundleId?` | `valid` (boolean), `verdict`, `bundleDigestMatches` |
| `endorse_evidence_bundle` | Cryptographically signs a multi-agent peer review endorsement or veto | `bundleId`, `agentId`, `role`, `verdict`, `comment`, `privateKeyPem?` | `endorsementId`, `verdict`, `signature`, `totalEndorsements` |
| `check_bundle_quorum` | Evaluates multi-agent peer endorsements against quorum and registry rules | `bundleId`, `minEndorsements?`, `requiredRoles?`, `requireUniqueSigners?`, `disallowRejections?`, `requireTrustedRegistry?` | `satisfied` (boolean), `approvedCount`, `rejectionsCount`, `verifiedSignatures`, `reasons` |
| `evaluate_evidence_policy` | Evaluates bundle compliance against declarative rules in `evidence.policy.json` | `bundleId`, `policyPath?`, `policy?`, `strict?`, `workspacePath?` | `passed` (boolean), `summary`, `rulesEvaluated`, `evaluations` |
| `dispatch_webhook_audit` | Dispatches an HMAC-SHA256 authenticated audit payload to a webhook URL | `bundleId`, `webhookUrl`, `secretToken?`, `includeProof?`, `headers?`, `timeoutMs?` | `delivered` (boolean), `statusCode`, `signatureHeader`, `durationMs` |
| `register_trusted_agent` | Registers an authorized agent public key and role in the workspace registry | `agentId`, `name`, `role`, `publicKeyPem`, `expiresAt?`, `metadata?` | `agentId`, `name`, `role`, `keyFingerprint`, `status`, `registeredAt` |
| `revoke_trusted_agent` | Revokes a trusted agent key in the registry with an audit reason | `agentId`, `reason`, `workspacePath?` | `agentId`, `status: 'revoked'`, `revokedAt`, `revocationReason` |
| `capture_sbom_evidence` | Generates a verifiable CycloneDX v1.5 SBOM from manifests/lockfiles | `bundleId`, `workspaceName?`, `includeDevDependencies?`, `outputPath?` | `evidenceId`, `componentCount`, `bomDigest`, `licenseSummary` |
| `notarize_evidence_bundle` | Anchors anonymized bundle SHA-256 digest to a remote transparency notary | `bundleId`, `notaryUrl`, `authToken?`, `timeoutMs?`, `allowPrivateNetwork?` | `receiptId`, `logIndex`, `merkleLeafHash`, `notaryKeyFingerprint` |
| `export_slsa_provenance` | Generates and Ed25519-signs an in-toto v1 / SLSA v1.0 provenance envelope | `bundleId`, `builderId?`, `sign?`, `outputPath?` | `statementDigest`, `subjectCount`, `dependencyCount`, `provenance` |
| `generate_client_config` | Generates MCP client configuration for Claude, Cursor, Gemini, or Cline | `client`, `write?`, `path?`, `serverName?`, `globalBin?`, `workspace?` | `client`, `configPath`, `snippet`, `written` |
| `submit_rekor_entry` | Submits bundle attestation to Sigstore Rekor and verifies RFC 6962 proof | `bundleId`, `rekorUrl?`, `privateKeyPem?`, `allowPrivateNetwork?` | `entryUuid`, `logIndex`, `inclusionProof`, `verified` |

---

## Standalone CLI & CI Verification

In addition to serving AI coding agents over MCP, Evidence MCP provides a direct command-line interface for human engineers, scripts, and automated CI/CD pipelines:

### 1. List All Recorded Bundles
```bash
node dist/cli.js list
# Or list bundles for a specific workspace directory:
node dist/cli.js list /path/to/project
```

### 2. Verify an Agent's Bundle (Exit Code for CI)
```bash
node dist/cli.js verify bundle_9a41f0bc
# Exits with 0 if verified; exits with 1 if stale, failed, or unverifiable
```

### 3. Multi-Workspace & Monorepo Package Management
```bash
# Register a monorepo package into an existing evidence bundle:
node dist/cli.js workspace add bundle_9a41f0bc frontend ./packages/frontend

# List all registered workspaces for a bundle:
node dist/cli.js workspace list bundle_9a41f0bc
```

### 4. Execute an Approved Command in Sandboxed Runner
```bash
# Run npm test directly in the workspace and record server_executed evidence:
node dist/cli.js exec bundle_9a41f0bc npm test

# Run a test command with custom working directory and timeout:
node dist/cli.js exec bundle_9a41f0bc vitest run --cwd packages/core --timeout 45000
```

### 5. Cryptographically Sign a Bundle
```bash
# Sign using workspace default Ed25519 key (auto-generated if absent):
node dist/cli.js sign bundle_9a41f0bc

# Sign with a specific PEM private key:
node dist/cli.js sign bundle_9a41f0bc --key /path/to/agent_private.pem
```

### 6. Export Interactive HTML, Markdown, or SARIF v2.1.0 Reports
```bash
# Export standalone, offline-safe interactive HTML report:
node dist/cli.js report bundle_9a41f0bc --format html --output ./reports/evidence.html

# Export OASIS SARIF v2.1.0 report for GitHub Code Scanning (including policy violations):
node dist/cli.js report bundle_9a41f0bc --format sarif --policy evidence.policy.json --output ./results.sarif

# Output formatted Markdown to stdout:
node dist/cli.js report bundle_9a41f0bc --format markdown
```

### 7. Capture AST Symbols & Semantic Diffs
```bash
# Analyze source files, extract symbols, and compute semantic diff against Git HEAD:
node dist/cli.js ast bundle_9a41f0bc src/index.ts src/utils.ts

# Capture AST evidence for a specific monorepo package without Git HEAD diff:
node dist/cli.js ast bundle_9a41f0bc src/types.ts --package backend --no-diff

# List all registered AST language plugins and supported file extensions:
node dist/cli.js ast --list-languages
```

### 8. Export Cryptographically Signed Verification Proofs
```bash
# Verify a bundle and issue an Ed25519-signed verification proof:
node dist/cli.js proof create bundle_9a41f0bc --output ./proofs/release-v1.proof.json

# Verify an exported proof file (validates signature and checks bundle digest):
node dist/cli.js proof verify ./proofs/release-v1.proof.json
```

### 9. Sequential Evidence Replay & Reproducibility Check
```bash
# Replay all evidence chronologically against live workspace state:
node dist/cli.js replay bundle_9a41f0bc

# Re-execute server-executed commands during replay to confirm output reproducibility:
node dist/cli.js replay bundle_9a41f0bc --re-execute
```

### 10. Multi-Agent Peer Endorsement (Consensus Protocol)
```bash
# Endorse a bundle as an independent tester agent with Ed25519 signature:
node dist/cli.js endorse bundle_9a41f0bc --agent agent:tester --role tester --verdict approved --comment "All 42 integration tests passed on Node 22"

# Submit a rejection veto as a security auditor:
node dist/cli.js endorse bundle_9a41f0bc --agent agent:sec-guard --role security_auditor --verdict rejected --comment "Unsanitized path parameter in upload handler"
```

### 11. Multi-Agent Quorum Evaluation
```bash
# Evaluate consensus with minimum endorsement count and required roles:
node dist/cli.js quorum bundle_9a41f0bc --min 2 --roles tester,security_auditor

# Strict evaluation enforcing the workspace Trusted Agent Key Registry:
node dist/cli.js quorum bundle_9a41f0bc --min 2 --roles tester,security_auditor --require-registry
# Exits with 0 if quorum is satisfied; exits with 1 if quorum failed
```

### 12. GitHub Actions Step Summary Generation
```bash
# Print formatted GitHub Step Summary Markdown to stdout:
node dist/cli.js summary bundle_9a41f0bc

# Automatically append to $GITHUB_STEP_SUMMARY in CI workflows:
node dist/cli.js summary bundle_9a41f0bc --github
```

### 13. Declarative Policy Compliance Evaluation
```bash
# Evaluate compliance against workspace evidence.policy.json:
node dist/cli.js policy bundle_9a41f0bc

# Evaluate with custom policy file, strict mode, and JSON output:
node dist/cli.js policy bundle_9a41f0bc --policy .compliance/strict.policy.json --strict --output ./eval.json
# Exits with 0 if compliant; exits with 1 if violations are found
```

### 14. Remote Audit Webhook Dispatch
```bash
# Dispatch HMAC-SHA256 authenticated audit payload to remote webhook:
node dist/cli.js webhook bundle_9a41f0bc https://audit.example.com/api/v1/evidence --secret my-secret-token

# Dispatch including cryptographic Ed25519 verification proof:
node dist/cli.js webhook bundle_9a41f0bc https://audit.example.com/api/v1/evidence --secret my-secret-token --proof
```

### 15. Distributed Agent Key Registry Management
```bash
# Register a trusted agent public key with specific functional role:
node dist/cli.js registry add agent:security-guard ./keys/sec_agent.pub --name "SecBot" --role security_auditor

# List all registered agents and their statuses (active, revoked, suspended):
node dist/cli.js registry list

# Revoke a compromised or decommissioned agent key:
node dist/cli.js registry revoke agent:security-guard "Key rotated for next sprint"
```

### 16. Automated Policy Bootstrapping Wizard
```bash
# Generate recommended evidence.policy.json and add .evidence-mcp/ to .gitignore:
node dist/cli.js init

# Bootstrap using the strict production preset (forces overwrite if exists):
node dist/cli.js init --preset strict --force
```

### 17. Capture CycloneDX v1.5 SBOM Evidence
```bash
# Capture dependency inventory & CycloneDX v1.5 SBOM for workspace:
node dist/cli.js sbom bundle_9a41f0bc --output ./artifacts/bom.cdx.json

# Production dependencies only (exclude devDependencies):
node dist/cli.js sbom bundle_9a41f0bc --no-dev
```

### 18. Remote Transparency Notary Attestation
```bash
# Anchor anonymized bundle SHA-256 digest to a remote transparency log:
node dist/cli.js notarize bundle_9a41f0bc https://notary.example.com/v1/notarize --token $NOTARY_TOKEN
```

### 19. SLSA v1.0 Provenance Attestation Export
```bash
# Generate and Ed25519-sign an in-toto v1 / SLSA Provenance v1.0 attestation:
node dist/cli.js slsa bundle_9a41f0bc --output ./artifacts/release.slsa.json
```

### 20. MCP Client Configuration Generator
```bash
# Print configuration JSON snippet for Claude, Cursor, Gemini, or Cline:
node dist/cli.js client config cursor

# Automatically merge and write configuration directly to target client file:
node dist/cli.js client config claude --write

# Target Cline with a custom workspace path and global binary command:
node dist/cli.js client config vscode-cline --write --workspace /path/to/project --global-bin
```

### 21. Sigstore Rekor Transparency Log Integration
```bash
# Submit bundle attestation to Sigstore Rekor and verify Merkle inclusion proof:
node dist/cli.js rekor submit bundle_9a41f0bc

# Audit an existing bundle against Rekor and verify offline RFC 6962 proofs:
node dist/cli.js rekor verify bundle_9a41f0bc
```

> **Interactive Tutorial:** See [examples/multi-agent-consensus/TUTORIAL.md](examples/multi-agent-consensus/TUTORIAL.md) and run `npx tsx examples/multi-agent-consensus/orchestrate.ts` for a complete end-to-end 3-agent orchestration simulation.

### CI/CD Pipeline Integration (GitHub Actions)

Evidence MCP provides an official composite action (`action.yml`) for seamless GitHub Actions CI/CD pipeline integration:

```yaml
- name: Verify Agent Evidence, Quorum & Compliance Policy
  uses: mokashreef/Evidence-MCP@v1.5.0
  with:
    bundle-id: ${{ env.BUNDLE_ID }}
    capture-sbom: 'true'
    require-quorum: 'true'
    min-endorsements: '2'
    required-roles: 'tester,security_auditor'
    require-policy: 'true'
    policy-file: 'evidence.policy.json'
    sarif-output: 'evidence-results.sarif'
    slsa-output: 'release.slsa.json'
    webhook-url: ${{ secrets.AUDIT_WEBHOOK_URL }}
    webhook-secret: ${{ secrets.AUDIT_WEBHOOK_SECRET }}
```

Or manually via CLI commands:
```yaml
- name: Verify Agent Evidence Bundle
  run: |
    node dist/cli.js verify ${{ env.BUNDLE_ID }}
    node dist/cli.js quorum ${{ env.BUNDLE_ID }} --min 2 --roles tester,security_auditor
    node dist/cli.js policy ${{ env.BUNDLE_ID }} --strict
    node dist/cli.js summary ${{ env.BUNDLE_ID }} --github
```

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

### 7. Cryptographically Sign the Bundle (Attestation)
```json
// Call: sign_evidence_bundle
{
  "bundleId": "bundle_9a41f0bc",
  "agentId": "agent-primary"
}
```
*Returns:*
```json
{
  "bundleId": "bundle_9a41f0bc",
  "attestation": {
    "agentId": "agent-primary",
    "algorithm": "ed25519",
    "publicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...",
    "signature": "3a8f1b2c4d..."
  }
}
```

### 8. Export Handoff Report
```json
// Call: export_evidence_report
{
  "bundleId": "bundle_9a41f0bc",
  "format": "markdown" // or "html" / "json"
}
```
*Returns a structured GitHub Flavored Markdown report ready to paste directly into a PR description or issue.*

### 9. Multi-Agent Peer Review & Quorum Endorsement
```json
// Call: endorse_evidence_bundle
{
  "bundleId": "bundle_9a41f0bc",
  "agentId": "agent-security-guard",
  "role": "security_auditor",
  "verdict": "approved",
  "comments": "No CVE vulnerabilities or path traversal risks detected."
}
```

```json
// Call: check_bundle_quorum
{
  "bundleId": "bundle_9a41f0bc",
  "policy": {
    "minEndorsements": 2,
    "requiredRoles": ["tester", "security_auditor"],
    "disallowRejections": true,
    "requireUniqueSigners": true
  }
}
```
*Returns:* `{ "satisfied": true, "verdict": "approved", "approvedCount": 2, "rejectedCount": 0, "missingRoles": [], "failures": [] }`

### 10. Automated Declarative Policy Compliance
```json
// Call: evaluate_evidence_policy
{
  "bundleId": "bundle_9a41f0bc",
  "policy": {
    "git": { "requireCleanWorkingTree": true, "allowedBranches": ["main", "feat/*"] },
    "commands": { "requireServerExecutedCommands": true, "disallowNonZeroExitCodes": true },
    "ast": { "disallowBreakingChanges": true }
  }
}
```
*Returns:* `{ "passed": true, "summary": "Policy compliance PASSED (3/3 rules satisfied).", "rulesEvaluated": 3, "evaluations": [...] }`

### 11. Dispatch Cryptographically Authenticated Webhook
```json
// Call: dispatch_webhook_audit
{
  "bundleId": "bundle_9a41f0bc",
  "webhookUrl": "https://compliance.internal/api/v1/evidence",
  "secretToken": "ci-secret-token",
  "includeProof": true
}
```
*Returns:* `{ "delivered": true, "statusCode": 200, "signatureHeader": "sha256=...", "durationMs": 45 }`

### 12. Register and Manage Trusted Agent Keys
```json
// Call: register_trusted_agent
{
  "agentId": "agent:sec-auditor-1",
  "name": "Security Auditor Agent",
  "role": "security_auditor",
  "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...",
  "expiresAt": "2027-12-31T23:59:59Z"
}
```
*Returns:* `{ "agentId": "agent:sec-auditor-1", "status": "active", "keyFingerprint": "8f3d1b...", "registeredAt": "2026-11-09T..." }`

---

## Security & Privacy Model

- **Zero Telemetry & Tracking:** Evidence MCP contains no analytics, telemetry, or network calls.
- **Ed25519 Cryptographic Attestation:** Native Ed25519 asymmetric signatures ensure bundle integrity. Any post-signing tampering with task definitions, assertions, file hashes, or command outputs immediately invalidates the signature during verification.
- **Strict Path Sandboxing:** Prevents path traversal (`../`) and verifies that every snapshotted file strictly resides within the declared `workspacePath`.
- **Symlink Protection & Boundary Re-evaluation:** Resolves canonical real filesystem paths (`fs.realpathSync`) for both workspace and targets. In v0.1, symbolic links are explicitly rejected for file snapshots. This security boundary is strictly re-evaluated during `verify_evidence_bundle`, immediately failing any file that was replaced by a symlink or moved outside the workspace after capture without reading or hashing the target.
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

## Scope & Boundaries (v1.5.0)

### Strictly In Scope for v1.5.0
- Sigstore Rekor Transparency Log Integration (`submit_rekor_entry` tool, `evidence-mcp rekor submit|verify` CLI, `buildHashedRekordPayload`, `verifyRekorEntryReceipt`, and pure Node.js RFC 6962 Merkle tree inclusion proof verification `verifyRfc6962InclusionProof`) with policy enforcement (`policy.rekor.requireRekor`, `minRekorCount`, `allowedRekorLogIds`).
- SLSA Provenance & SBOM Package Policy Rules (`EvidencePolicy.slsa` requiring provenance/signature/allowed builders, and `EvidencePolicy.sbom` requiring PURLs and prefix-matching for `blockedPackages`) with SARIF v2.1.0 and Markdown compliance mapping.
- MCP Client Configuration Generator (`generate_client_config` tool and `evidence-mcp client config` CLI) with OS-aware path detection (`getDefaultConfigPath`) and atomic merging across Claude, Cursor, Gemini Code Assist, and Cline.
- Modular AST Parser Plugin Bridge (`AstParserPlugin` registry with `registerAstPlugin`, `unregisterAstPlugin`, `listRegisteredAstPlugins`, and `evidence-mcp ast --list-languages` CLI discovery) supporting custom grammar extensions and priority overrides alongside built-in parsers (TypeScript, JavaScript, Python, Go, Rust, Java, C#, JSON).
- Distributed Trusted Agent Key Registry (`register_trusted_agent` & `revoke_trusted_agent` tools, and `evidence-mcp registry` CLI) with active enforcement in verification, quorum, and policy checks (`requireTrustedRegistry`).
- Remote transparency notary attestation (`notarize_evidence_bundle` tool, `evidence-mcp notarize` CLI, `verifyNotaryReceipt`, and policy `attestation.requireNotary` / `allowedNotaryFingerprints` / `minNotaryCount` multi-notary quorum) anchoring anonymized SHA-256 digests with zero source code leakage.
- Signed CycloneDX v1.5 SBOM supply-chain evidence (`capture_sbom_evidence` tool, `evidence-mcp sbom` CLI) across **npm, Go, Rust, and Python** ecosystems with polyglot secondary manifest verification (`additionalManifests`), `sbom` policy compliance rules, and attestation digest binding.
- SLSA v1.0 Provenance attestation export (`export_slsa_provenance` tool, `evidence-mcp slsa` CLI, `generateSlsaProvenance`, `verifySlsaProvenanceSignature`) producing signed in-toto v1 envelopes linking artifacts, Git commits, SBOM dependencies, commands, and notary receipts.
- SSRF-hardened outbound HTTP networking (`src/network.ts`) blocking private/loopback/metadata IP ranges and DNS rebinds by default (`allowPrivateNetwork` opt-in) alongside bounded exponential backoff retries.
- Workspace-level cryptographic agent identity lifecycle management (`active`, `revoked`, `suspended`) with expiration and fingerprint binding verification.
- Declarative Automated Evidence Policy Engine (`evaluate_evidence_policy` tool, `evidence-mcp policy`, and `evidence-mcp init` bootstrapping wizard with `recommended`/`strict`/`permissive` presets).
- Multi-dimensional compliance rules evaluated against Git state, file patterns, server command execution, AST breaking change detection, assertion backing, signatures, notary receipts, consensus quorum, package licenses (`license`), and SBOM components (`sbom`).
- Zero-external-dependency glob-like file pattern matcher supporting wildcards, extensions, and directory prefixes.
- HMAC-SHA256 authenticated audit webhook dispatcher (`dispatch_webhook_audit` tool and `evidence-mcp webhook` CLI).
- Safe network execution with timeouts via `AbortController` and signature generation (`X-Evidence-Signature`).
- Official GitHub Actions composite action (`action.yml`) with automated policy checks, SARIF export (`sarif-output`), webhook delivery, and step summaries.
- Multi-agent consensus protocol with Ed25519 peer endorsements (`endorse_evidence_bundle` tool and `evidence-mcp endorse` CLI).
- Peer endorsement roles (`tester`, `security_auditor`, `architect`, `peer_reviewer`) and verdicts (`approved`, `rejected`, `changes_requested`).
- Flexible quorum policy engine (`check_bundle_quorum` tool and `evidence-mcp quorum` CLI) supporting threshold counting, mandatory roles, rejection vetoes, unique signer checks, and `--require-registry`.
- GitHub Step Summary Markdown generation (`generateGitHubStepSummary` and `evidence-mcp summary` CLI) displaying visual badge grids, AST breaking change alerts, and endorsement audit trails.
- Offline-safe HTML, Markdown, JSON, and OASIS SARIF v2.1.0 report exporting (`export_evidence_report` and `evidence-mcp report`).
- Cryptographic verification proofs (`export_verification_proof` tool and `evidence-mcp proof create` CLI).
- Proof verification and digest validation (`verify_replay_proof` tool and `evidence-mcp proof verify` CLI).
- Sequential evidence replay and reproducibility auditing (`replayEvidenceBundle` and `evidence-mcp replay`).
- AST structural symbol extraction and semantic diff computation (`capture_ast_evidence` tool and `evidence-mcp ast` CLI) for TypeScript, JavaScript, Python, Go, Rust, Java, and C#.
- Breaking change detection flagging removed exported symbols, visibility downgrades, and added required parameters.
- Independent verification of AST code structures in `verify_evidence_bundle` against live on-disk symbols.
- Multi-workspace and monorepo package support (`register_workspace` tool and `additionalWorkspaces`).
- CLI workspace management (`evidence-mcp workspace add` and `evidence-mcp workspace list`).
- Targeted multi-workspace evidence collection for file snapshots, Git inspection, command execution, AST, and SBOM evidence.
- Strict per-workspace sandboxing and boundary validation preventing cross-package escapes.
- Multi-repository and submodule Git state verification.
- Sandboxed process execution runner (`execute_verified_command` and `evidence-mcp exec`) with active process concurrency semaphore guards.
- Strict security allowlist for developer tooling (`npm`, `npx`, `node`, `git`, `tsc`, `vitest`, `cargo`, `go`, etc.) and blocklist for dangerous interpreters/subshells and downloaders (`sh`, `bash`, `powershell`, `rm`, `curl`, `wget`).
- Zero shell injection vulnerability (`shell: false` across all platforms).
- Automatic environment variable sanitization (scrubbing secrets, API tokens, passwords, private keys).
- Resource bounds (timeouts up to 120s with process killing, 512KB stdout/stderr buffer caps, concurrency semaphore limits).
- Independent verification of server-executed commands in `verify_evidence_bundle` (exit 0 = verified, exit != 0 = failed).
- Native Ed25519 asymmetric cryptographic attestation and bundle signing (`sign_evidence_bundle` and `evidence-mcp sign`).
- Deterministic canonical payload serialization (`getCanonicalPayload`) for tamper resistance.
- Cryptographic signature re-verification in `verify_evidence_bundle` and CLI `verify`.
- Local file persistence under `.evidence-mcp/bundles/`, `.evidence-mcp/proofs/`, `.evidence-mcp/registry/`, and key pairs under `.evidence-mcp/keys/`.
- Standalone CLI interface (`verify`, `list`, `report`, `sign`, `exec`, `workspace`, `ast`, `proof`, `replay`, `endorse`, `quorum`, `summary`, `policy`, `webhook`, `registry`, `init`, `sbom`, `notarize`, `slsa`, `client`, `rekor`) with CI exit codes.
- Interactive, responsive, offline-safe HTML report generation with multi-workspace tables, AST symbol catalogs, SBOM supply-chain summaries, peer endorsements, and badges.
- Mandatory evidence-linked assertions.
- Live verification of file hashes, Git status, AST symbols, SBOM manifests, notary receipts, Rekor log proofs, and cryptographic signatures.

### Out of Scope for v1.5.0
- **Direct Arbitrary Shell Command Execution:** Raw shell strings (e.g. `bash -c "..."`) without security boundaries are strictly rejected.
- **Remote Publishing / Cloud Source Uploads:** Evidence bundles stay local to the workspace. Remote notary and Rekor endpoints receive only cryptographic bundle SHA-256 digests (`bundleDigest`) — never source code or file contents.

---

## Roadmap

- **v0.3 (Completed):** Native Ed25519 cryptographic attestation, bundle signing, and tamper verification.
- **v0.4 (Completed):** Sandboxed execution runner for reproducible, server-verified command execution.
- **v0.5 (Completed):** Multi-workspace support for cross-repository monorepo changes.
- **v0.6 (Completed):** Diff-level syntax tree (AST) evidence capturing with breaking change detection.
- **v0.7 (Completed):** Signed reproducible evidence replay & bundle verification proofs.
- **v0.8 (Completed):** Multi-agent cross-verification consensus protocol & GitHub Step Summary composite action.
- **v0.9 (Completed):** Automated evidence policy engine & HMAC-signed audit webhooks.
- **v1.0 (Completed):** Stable API freeze, distributed agent attestation registry, and multi-tenant bundle signing.
- **v1.1 (Completed):** Python AST symbol parsing, runner concurrency semaphore, `evidence-mcp init` wizard, license compliance policy rules, multi-agent consensus tutorial, and enforced registry verification.
- **v1.2 (Completed):** Structural AST parsers & semantic diffing for Go & Rust, and SARIF v2.1.0 report export for GitHub Code Scanning.
- **v1.3 (Completed):** Java & C# structural AST parsing, signed CycloneDX v1.5 SBOM integration, and remote transparency notary attestations.
- **v1.4 (Completed):** Multi-notary threshold quorum policies (`minNotaryCount`), SSRF-hardened networking with exponential backoff, multi-ecosystem SBOM scanning (npm, Go, Rust, Python), SLSA v1.0 provenance attestation export, and automated release/npm publishing workflow.
- **v1.5 (Current Release):** Sigstore Rekor transparency log integration & RFC 6962 inclusion proof verification, SLSA & SBOM package policy enforcement rules, MCP client config generator for Claude/Cursor/Gemini/Cline, and modular AST parser plugin bridge with CLI discovery.
- **v1.6:** Distributed multi-log consensus auditing, WebAssembly sandboxed parser execution, and interactive terminal dashboard UI.

---

## License

This project is licensed under the [MIT License](LICENSE).
