# Go Vulnerability Check Action

[![CI](https://github.com/imjasonh/govulncheck-action/actions/workflows/ci.yml/badge.svg)](https://github.com/imjasonh/govulncheck-action/actions/workflows/ci.yml)

A GitHub Action that runs `govulncheck` on your Go code and creates annotations for vulnerable dependencies and code paths directly in your pull requests.

## Features

- 🔍 **Automated vulnerability scanning** - Runs `govulncheck -json` on your Go project
- 📝 **Smart annotations** - Creates GitHub annotations on:
  - Vulnerable module declarations in `go.mod` with detailed vulnerability information
  - Source code lines that call vulnerable functions with clear indication of what's vulnerable
- 🔧 **Suggested fixes** - When vulnerable code is actually called, provides specific version recommendations
- 📊 **Comprehensive reporting** - Generates:
  - Detailed workflow summary with vulnerability tables and links
  - Annotation counts and vulnerability statistics
  - Direct links to the Go vulnerability database
- 💡 **Rich context** - Each annotation includes:
  - Vulnerability ID and summary description
  - CVE numbers when available
  - Fixed version information
  - Links to detailed vulnerability information
- 🎯 **Zero configuration** - Works out of the box with sensible defaults

## Usage

Add this action to your workflow:

```yaml
name: Vulnerability Check
on: [pull_request]

jobs:
  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      
      - uses: imjasonh/govulncheck-action@v0.1
```

### Multiple Directories

To scan multiple directories, use comma-separated or space-delimited paths:

```yaml
- uses: imjasonh/govulncheck-action@v0.1
  with:
    working-directory: 'service1,service2,service3'
```

Or with spaces:

```yaml
- uses: imjasonh/govulncheck-action@v0.1
  with:
    working-directory: 'service1 service2 service3'
```

The action will:
- Run govulncheck in each directory
- Skip directories that don't exist (with a warning)
- Filter out duplicate vulnerabilities across directories
- Aggregate results from all directories

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `working-directory` | Directory or directories to run govulncheck in. Supports comma-separated or space-delimited paths (e.g., `"dir1,dir2"` or `"dir1 dir2"`). Duplicates are filtered, and non-existent directories are skipped with a warning. | `.` |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities-found` | Whether any vulnerabilities were found (`true`/`false`) |
| `vulnerability-count` | Number of vulnerabilities found |

## How It Works

1. The action installs the latest version of `govulncheck` (or skips if already installed)
2. Runs `govulncheck -json ./...` in your project
3. Parses the JSON output to identify genuine vulnerability findings
4. Creates GitHub annotations:
   - **Warning annotations in `go.mod`**: Highlights vulnerable module dependencies with:
     - Complete list of vulnerabilities sorted by ID
     - Summary descriptions and CVE numbers
     - Fixed version information
     - Links to the Go vulnerability database
   - **Warning annotations in source files**: Marks lines that call vulnerable code with:
     - Clear indication of which function is vulnerable (e.g., "This code calls html.Parse")
     - Vulnerability details and severity information
     - Direct links to learn more
   - **Notice annotations for fixes**: When vulnerable code is actively used:
     - Shows current vs recommended version
     - Lists which vulnerabilities would be fixed
     - Provides exact version to upgrade to
5. Generates a comprehensive workflow summary:
   - Overview statistics
   - Vulnerability details in formatted tables
   - Vulnerable code locations by file
   - Actionable recommendations
6. Sets output variables for use in subsequent workflow steps

## Example

The [`example/`](./example) directory contains a Go module with a known vulnerability to demonstrate the action:

- [`example/main.go`](./example/main.go) - Uses `html.Parse` from a vulnerable version of `golang.org/x/net`
- [`example/go.mod`](./example/go.mod) - Declares dependency on `golang.org/x/net v0.0.0-20220906165146-f3363e06e74c`

When the action runs on this example, it will:
1. Create warning annotations on the `go.mod` line with golang.org/x/net showing all vulnerabilities
2. Create a warning annotation on the line in `main.go` that calls `html.Parse`
3. Suggest updating to a fixed version since the vulnerable code is actually being called
4. Generate a detailed workflow summary with all findings

## Example Workflow

See [`.github/workflows/example.yml`](./.github/workflows/example.yml) for a complete example workflow that:
- Runs govulncheck on the example directory
- Reports the results
- Demonstrates how to fail a workflow when vulnerabilities are found

## The Action In Action

[example.yaml](https://github.com/imjasonh/govulncheck-action/actions/workflows/example.yml) demonstrates the action running on the vulnerable module in `./example`.

Here's an [example Pull Request showing the annotations](https://github.com/imjasonh/govulncheck-action/pull/1/files#diff-1c171c5d51ba71728458fc771ff98395bcd3f59481e736c18e059372723acaab)

## Annotation Examples

### go.mod Annotation
```
⚠️ Security vulnerabilities found in golang.org/x/net

• GO-2022-1144: Uncontrolled recursion in Unmarshal functions (CVE-2022-41723)
  🔗 https://pkg.go.dev/vuln/GO-2022-1144
  ✅ Fixed in: v0.4.0

• GO-2023-1495: Denial of service via crafted HTTP/2 stream (CVE-2023-39320)
  🔗 https://pkg.go.dev/vuln/GO-2023-1495
  ✅ Fixed in: v0.1.1-0.20221104162952-702349b0e862

💡 Recommended action: Update to v0.38.0 or later
```

### Source Code Annotation
```
🚨 Vulnerable code detected

This code calls html.Parse which has a known vulnerability.

Vulnerability: GO-2024-3333 - Non-linear parsing of case-insensitive content
CVE: CVE-2024-45338

Details: An attacker can craft an input that would be processed non-linearly...

🔗 More info: https://pkg.go.dev/vuln/GO-2024-3333

✅ Fix available: Update the dependency to v0.33.0 or later
```

### Suggested Fix Notice
```
🔧 Suggested fix: Update this dependency to fix vulnerabilities that are actually being called in your code.

Current: require golang.org/x/net v0.0.0-20220906165146-f3363e06e74c
Suggested: require golang.org/x/net v0.38.0

This fixes 9 vulnerabilities that have active call sites in your code:
• GO-2022-1144
• GO-2023-1495
• GO-2023-1571
...
```

## Development

The action is built with Node.js and uses the following structure:

```
.
├── index.js              # Main entry point
├── lib/
│   ├── govulncheck.js   # Handles govulncheck execution
│   ├── parser.js        # Parses JSON output
│   ├── annotator.js     # Creates GitHub annotations
│   └── summary.js       # Generates workflow summaries
├── test/                # Comprehensive test suite
├── example/             # Example vulnerable Go module
└── action.yml           # Action metadata
```

### Running Tests

```bash
npm install
npm test                # Run all tests
npm run test:coverage   # Run with coverage report
```

## License

Apache 2.0
