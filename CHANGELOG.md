# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-11-09

### Added
- **Automated Evidence Policy Engine (`src/policy.ts`):**
  - Declarative policy rules evaluation from `evidence.policy.json` (or `.evidence-policy.json`) across seven operational dimensions:
    - `git`: required clean working tree, allowed branch patterns (`main`, `release/*`), and detached HEAD checks.
    - `files`: maximum snapshot limits, mandatory file patterns (`src/**/*.ts`), and blocked file patterns (`.env*`, `*.key`).
    - `commands`: server-executed runner enforcement, non-zero exit code restrictions, and required command pattern verification.
    - `ast`: mandatory structural AST capture and strict breaking change prohibitions.
    - `assertions`: minimum assertion counts and prohibition of unverifiable agent-only claims.
    - `attestation`: mandatory cryptographic Ed25519 signatures and authorized signer key fingerprint allowlists.
    - `consensus`: seamless delegation to multi-agent consensus quorum policies (`QuorumPolicy`).
  - New MCP tool `evaluate_evidence_policy` (Tool 16): evaluates declarative compliance rules against an evidence bundle with detailed violation tracking and rule-by-rule reporting.
  - New CLI command `evidence-mcp policy <bundleId> [--policy <file>] [--strict] [--output <file>]`: evaluates compliance and outputs formatted ASCII status tables with exit code 0/1 for CI/CD gates.
- **Audit Webhook Dispatch & Notification System (`src/webhook.ts`):**
  - Remote audit webhook dispatch with HMAC-SHA256 signature generation (`X-Evidence-Signature`) using secret tokens.
  - Standard headers: `X-Evidence-Bundle-Id`, `X-Evidence-Digest`, `X-Evidence-Timestamp`, `X-Evidence-Event`.
  - Optional inclusion of portable Ed25519 verification proofs (`includeProof: true`) directly in the webhook payload.
  - Safe network execution with `AbortController` timeouts and graceful error handling.
  - New MCP tool `dispatch_webhook_audit` (Tool 17): dispatches cryptographically authenticated audit payloads to remote HTTP/HTTPS webhook endpoints.
  - New CLI command `evidence-mcp webhook <bundleId> <url> [--secret <token>] [--proof] [--timeout <ms>]`: dispatches audit notifications directly from the terminal.
- **GitHub Actions Integration (`action.yml`):**
  - Added `require-policy`, `policy-file`, `webhook-url`, and `webhook-secret` inputs for seamless CI/CD compliance gating.
- **Comprehensive Test Coverage:**
  - Added `test/policy.test.ts` (10 tests) and `test/webhook.test.ts` (5 tests) bringing total passing test suite to 155 tests across 15 test suites (100% green).

## [0.8.0] - 2026-11-09

### Added
- **Multi-Agent Consensus & Quorum Endorsement Protocol:**
  - Multi-agent peer review protocol (`src/consensus.ts`) allowing independent reviewing agents (tester, security auditor, architect, peer reviewer) to inspect, endorse, or veto evidence bundles.
  - New MCP tool `endorse_evidence_bundle` (Tool 14): appends an Ed25519-signed peer review endorsement with agent role, verdict (`approved`, `rejected`, `changes_requested`), and commentary to the bundle.
  - New MCP tool `check_bundle_quorum` (Tool 15): validates quorum policies (minimum approved endorsements, required reviewer roles, unique signer enforcement, and rejection veto checks).
  - New CLI commands:
    - `evidence-mcp endorse <bundleId> --agent <id> --role <role> --verdict <verdict> [--comment <text>] [--key <file>]`
    - `evidence-mcp quorum <bundleId> [--min <count>] [--roles <roles...>]`
    - `evidence-mcp summary <bundleId> [--output <file>] [--github]`
- **Official GitHub Actions Composite Action & Step Summary Integration:**
  - Reusable GitHub Action definition (`action.yml`) enabling automated CI verification, quorum policy checks, and step summaries with zero configuration.
  - Native GitHub Step Summary formatter (`src/github-summary.ts`) writing formatted audit tables, badge grids, AST breaking change alerts, and consensus tables to `$GITHUB_STEP_SUMMARY`.
  - Comprehensive test suite in `test/consensus.test.ts` bringing total passing test suite to 140 tests across 13 test suites.

## [0.7.0] - 2026-11-08

### Added
- **Cryptographic Verification Proofs & Replay Engine:**
  - Portable, signed verification proofs (`src/proof.ts`) that certify the verified verdict of an evidence bundle with an asymmetric Ed25519 digital signature.
  - New MCP tool `export_verification_proof` (Tool 12): verifies an evidence bundle and exports a signed verification proof file under `.evidence-mcp/proofs/` containing verdict, bundle digest, item count, and cryptographic signature.
  - New MCP tool `verify_replay_proof` (Tool 13): verifies the authenticity of exported proof files both online against the workspace bundle and offline via public key and fingerprint validation.
  - Deterministic Evidence Replay Engine (`replayEvidenceBundle`): executes chronological sequence validation of Git states, file hashes, command records, and AST symbols with optional sandboxed re-execution of server-executed commands (`--re-execute`) to verify deterministic reproducibility.
  - New CLI commands:
    - `evidence-mcp proof create <bundleId> [--output <file>] [--key <file>]`
    - `evidence-mcp proof verify <file|id> [--bundle <bundleId>]`
    - `evidence-mcp replay <bundleId> [--re-execute]`
  - Reporting enhancements: Markdown and responsive HTML reports now display active verification proofs and signatures in the bundle metadata header.
  - Comprehensive test suite in `test/proof.test.ts` bringing total passing test suite to 132 tests across 12 test suites.

## [0.6.0] - 2026-11-08

### Added
- **AST & Semantic Diff Evidence Engine:**
  - Zero-dependency semantic code analysis engine (`src/ast.ts`) extracting symbols, signatures, visibility, parameters, return types, and class/interface/type structures across TypeScript, JavaScript, and JSON files.
  - New MCP tool `capture_ast_evidence` (Tool 11): records code structural symbols and compares them against Git HEAD (`git show HEAD:<relativePath>`) to detect semantic additions, deletions, and modifications.
  - Automated breaking change detection: flags API contract violations such as removing exported symbols, visibility downgrades, or adding new required parameters to exported functions (`isBreakingChange: true`).
  - Independent AST verification: `verify_evidence_bundle` re-parses live files on disk and independently verifies symbol presence and signature consistency; flags bundles as `stale` when symbols or signatures are modified, and `failed` if files are removed or moved.
  - New CLI command: `evidence-mcp ast <bundleId> <files...> [--workspace <path>] [--package <name>] [--no-diff]` to capture AST symbols and semantic diffs directly from the terminal.
  - Reporting enhancements: Markdown and responsive HTML reports now include an AST & Semantic Diff Evidence section with interactive symbol catalogs, diff summaries, and breaking change alert banners.
  - Comprehensive test suite in `test/ast.test.ts` bringing total passing test suite to 125 tests across 11 test suites.

## [0.5.0] - 2026-11-08

### Added
- **Multi-Workspace & Monorepo Support:**
  - Full support for multi-package and monorepo architectures: bundles can now track evidence across multiple named workspaces (e.g. `root`, `frontend`, `backend`, `core`).
  - New MCP tool `register_workspace` (Tool 10): dynamically binds named package roots or secondary repositories to an active bundle.
  - Monorepo initialization: `create_evidence_bundle` supports optional `additionalWorkspaces` map to declare package roots upfront.
  - New CLI commands: `evidence-mcp workspace add <bundleId> <name> <path>` and `evidence-mcp workspace list <bundleId>`.
  - Targeted evidence tools: `snapshot_files`, `capture_git_evidence`, `execute_verified_command`, and `record_command_result` accept optional `workspaceName` targeting specific sub-projects.
  - Strict workspace-confined sandboxing: path traversal and symlink boundary validations are strictly enforced relative to each target workspace's root.
  - Multi-repository Git inspection: verifies independent Git commit trees and working directories across submodules and secondary repositories.
  - Reporting: Markdown and HTML reports include a Registered Workspaces table and display workspace tags on all evidence entries.
  - Comprehensive test suite in `test/multi-workspace.test.ts` bringing total passing test suite to 114 tests across 10 test suites.

## [0.4.0] - 2026-11-08

### Added
- **Sandboxed Command Runner & Independently Verified Execution:**
  - Secure process execution runner (`src/runner.ts`) enabling the server to run tests, linters, and compilers directly rather than relying solely on self-reported agent claims.
  - Strict security policy: Allowed developer tools (`npm`, `npx`, `node`, `git`, `tsc`, `vitest`, `jest`, `cargo`, `go`, etc.) and blocked raw shells (`sh`, `bash`, `powershell`, `cmd`), destroyers (`rm`, `del`), and network exfiltration tools (`curl`, `wget`).
  - Direct execution with `shell: false` across all platforms to eliminate shell injection vulnerabilities.
  - Automatic environment sanitization: Scrubs secret keys, API tokens, credentials, and passwords from child process environments.
  - Workspace containment enforcement: Validates working directory boundaries against workspace root and rejects path escapes.
  - Resource bounds: Enforces configurable timeouts (default 30s) with graceful and force termination, and 512KB buffer caps on stdout/stderr.
  - New MCP tool `execute_verified_command` (Tool 9) with explicit `provenance: 'server_executed'`.
  - New CLI command `evidence-mcp exec <bundleId> <command> [args...] [--timeout <ms>] [--cwd <dir>]`.
  - Verification engine enhancement: `verify_evidence_bundle` verifies `server_executed` commands (exit 0 = verified, exit != 0 = failed), allowing assertions backed by server-executed test suites to achieve authentic `verified` status.
  - Visual provenance badges and execution durations displayed in Markdown and HTML reports.
  - Comprehensive test suite in `test/runner.test.ts` bringing total passing test suite to 106 tests across 9 test suites.

## [0.3.0] - 2026-11-07

### Added
- **Native Ed25519 Cryptographic Attestation & Bundle Signing:**
  - Zero-dependency asymmetric cryptographic signing using native Node.js `node:crypto` (`ed25519`).
  - Canonical deterministic JSON payload serialization (`getCanonicalPayload`) with recursive key sorting to eliminate serialization jitter.
  - New MCP tool `sign_evidence_bundle`: enables coding agents to digitally sign bundles using a persistent agent key pair stored in `.evidence-mcp/keys/` or custom key paths.
  - New CLI command `evidence-mcp sign <bundleId> [--key <path>]` for signing bundles directly from the terminal.
  - Cryptographic attestation verification integrated into `verify_evidence_bundle` and `evidence-mcp verify`: tamper detection immediately fails verification if any bundle property (task, assertions, file hashes, command records) is altered post-attestation.
  - Attestation badges and public key metadata displayed in Markdown and responsive HTML reports.
  - Added comprehensive test suite in `test/attestation.test.ts` (87 total passing tests).

## [0.2.0] - 2026-11-07

### Added
- **Standalone CLI Commands:** Direct CLI interface for developers and CI/CD pipelines without requiring an MCP client:
  - `evidence-mcp list [workspace]`: Displays all recorded bundles in a clean tabular view.
  - `evidence-mcp verify <bundleId>`: Verifies a bundle against disk and Git state, exiting with `0` on verification success or `1` on failure/stale status.
  - `evidence-mcp report <bundleId> [--format markdown|json|html] [--output <file>]`: Exports verification reports to stdout or files.
- **Standalone Interactive HTML Reports:** Added `html` format to `export_evidence_report` and the CLI. Produces a self-contained, offline-safe, responsive HTML report with light/dark theme support and XSS protection.
- **Comprehensive Test Coverage:** Added unit test suites for CLI commands (`test/cli.test.ts`) and HTML report rendering (`test/html-reporter.test.ts`), bringing total passing test suite to 80 tests.

## [0.1.2] - 2026-10-31

### Security
- **Re-evaluate Safe Path Boundary in Verifier:** In `verify_evidence_bundle`, re-apply strict `assertSafeFilePath` validation to every file snapshot path before existence checking or hashing.
- **Post-capture Symlink Replacement Defense:** If an initially captured file is replaced with a symbolic link, resolves outside the workspace, or targets sensitive credentials, verification immediately fails the item with a clear security reason without reading or hashing the target.

### Documentation
- **Diagram Wording Correction:** Replaced the remaining diagram text `(Must link to proof)` with `(Evidence links)` in `README.md`.

## [0.1.1] - 2026-10-31

### Security
- **Symlink Escape Prevention:** Enforced canonical path resolution (`realpath`) for workspace boundaries and target file paths.
- **Symbolic Link Rejection:** Explicitly rejects symbolic links for file snapshots in v0.1 to establish an unambiguous security boundary.
- **Symlink to Sensitive Files:** Rejects symlinks pointing to sensitive external credential files (e.g., `.env`, keys).

### Trust Model & Correctness
- **Explicit Provenance for Commands:** Added `provenance: 'agent_reported'` to `CommandEvidence`. The server accepts command lines, exit codes, and stdout/stderr as supplied by the client without executing them.
- **Unverifiable Status for Command Records:** During `verify_evidence_bundle`, command results are reported as `unverifiable` rather than `verified`.
- **Honest Assertion Verification:** Assertions relying solely on agent-reported command evidence receive `unverifiable` status instead of receiving false `verified` status.
- **Terminology Alignment:** Removed claims of "tamper-evident proof" to reflect that command executions and bundles without cryptographic signatures or sandboxed runners are structured audit records rather than cryptographic proofs.

### Documentation & Packaging
- **Local Configuration:** Removed unreleased `npx -y evidence-mcp` snippet from `README.md` in favor of the supported local build path.
- **Documented Trust Boundaries:** Clearly separated file hash verification, Git state inspection, and agent-reported command logging in documentation.

## [0.1.0] - 2026-10-31

### Added
- Initial v0.1 release of Evidence MCP server.
- Seven core MCP tools: `create_evidence_bundle`, `capture_git_evidence`, `record_command_result`, `snapshot_files`, `add_assertion`, `verify_evidence_bundle`, `export_evidence_report`.
- Workspace-confined file hashing with SHA-256.
- Safe read-only Git status and HEAD commit capture.
- Path traversal protection and sensitive file blocklist.
- Local atomic storage under `.evidence-mcp/bundles/`.
