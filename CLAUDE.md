# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development Commands
```bash
npm test                 # Run all tests
npm run test:watch       # Run tests in watch mode  
npm run test:coverage    # Run tests with coverage report (must meet 95% thresholds)
npm run build           # Build dist/index.js using @vercel/ncc
npm run test:local      # Run local integration test
```

### Testing Specific Files
```bash
npx jest test/parser.test.js        # Run specific test file
npx jest --coverage lib/parser.js   # Coverage for specific module
```

### Local Testing
```bash
node run-local.js       # Test action locally with example/
node test-local.js      # Run govulncheck directly on example/
```

## Architecture Overview

This is a GitHub Action that runs Go vulnerability scanning. The workflow is:

1. **index.js** - Entry point that orchestrates the entire process:
   - Changes to working directory if specified
   - Installs govulncheck if needed
   - Runs vulnerability scan
   - Parses results and creates annotations
   - Generates workflow summary
   - Sets outputs (vulnerabilities-found, vulnerability-count)

2. **lib/govulncheck.js** - Manages the govulncheck tool:
   - Checks if already installed via `govulncheck -version`
   - Installs via `go install` if needed
   - Runs with JSON output format

3. **lib/parser.js** - Parses govulncheck JSON output:
   - Handles both JSON lines and multi-line JSON formats
   - Extracts vulnerability findings with OSV details
   - Identifies vulnerable modules and call sites
   - Attaches OSV metadata to vulnerabilities

4. **lib/annotator.js** - Creates GitHub annotations:
   - **go.mod annotations**: Warns about vulnerable dependencies with fix suggestions
   - **Source code annotations**: Marks lines that call vulnerable functions
   - Distinguishes between dependencies with vulnerabilities vs. code actively using them
   - Provides context-aware fix suggestions

5. **lib/summary.js** - Generates detailed workflow summary:
   - Overview statistics
   - Vulnerability tables grouped by module
   - Vulnerable code locations
   - Actionable recommendations with latest fixed versions

## Key Design Patterns

- **Dependency Injection**: The main `run()` function accepts all dependencies for testability
- **Class-based Modules**: Each lib file exports a class with focused responsibilities
- **Mock-friendly**: External dependencies (@actions/core, fs, exec) are injected
- **Error Propagation**: Errors bubble up to index.js which calls `core.setFailed()`

## Testing Strategy

- Tests require 95% coverage for statements, lines, and functions
- Each module has a corresponding test file
- Mocks are used extensively for GitHub Actions APIs
- The dist/ directory must be rebuilt and committed when source changes

## Important Notes

- The action outputs both inline annotations and a workflow summary for maximum visibility
- Annotations are smart - they only suggest fixes for dependencies that have vulnerable code being called
- The govulncheck tool requires Go to be installed in the runner
- The action uses Node.js 20 runtime as specified in action.yml