# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
