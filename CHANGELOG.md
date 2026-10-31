# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
