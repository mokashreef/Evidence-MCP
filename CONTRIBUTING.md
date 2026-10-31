# Contributing to Evidence MCP

Thank you for your interest in improving Evidence MCP! We welcome contributions that help make AI coding agents more transparent, accountable, and verifiable.

## Core Principle: No Claims Without Tests

Every pull request or code contribution must adhere to our core philosophy:
1. **Include Tests:** Any new feature, bug fix, or security update must include corresponding unit or integration tests that prove it works and prevent regressions.
2. **Documented Rationale:** If a contribution does not include tests (e.g., pure documentation typo fixes or CI pipeline adjustments), you must explicitly state the documented reason in your contribution description.

## Development Workflow

1. **Clone the repository:**
   ```bash
   git clone https://github.com/mokashreef/Evidence-MCP.git
   cd Evidence-MCP
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Verify typecheck:**
   ```bash
   npm run typecheck
   ```

4. **Run test suite:**
   ```bash
   npm test
   ```

5. **Build project:**
   ```bash
   npm run build
   ```

## Commit Conventions

We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New features or tools
- `fix:` Bug fixes
- `test:` Adding or updating tests
- `docs:` Documentation changes
- `chore:` Maintenance, build, or configuration updates

## Security & Privacy Guidelines

- **No Remote Telemetry:** Evidence MCP is strictly a local tool. Do not introduce network calls, external tracking, or telemetry.
- **Path Sandboxing:** All file operations must respect workspace boundaries to prevent directory traversal.
- **Secret Protection:** Never commit secrets, credentials, API keys, or `.env` files. Ensure the sensitive file blocklist is kept up-to-date.
