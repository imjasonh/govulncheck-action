# Go Vulnerability Check Action

A GitHub Action that runs `govulncheck` on your Go code and creates annotations for vulnerable dependencies and code paths directly in your pull requests.

## Features

- 🔍 **Automated vulnerability scanning** - Runs `govulncheck -json` on your Go project
- 📝 **Smart annotations** - Creates GitHub annotations on:
  - Vulnerable module declarations in `go.mod`
  - Source code lines that call vulnerable functions
- 📊 **Detailed output** - Reports the number of vulnerabilities found
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
      
      - uses: imjasonh/govulncheck-action@main
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `working-directory` | Directory to run govulncheck in | `.` |

## Outputs

| Output | Description |
|--------|-------------|
| `vulnerabilities-found` | Whether any vulnerabilities were found (`true`/`false`) |
| `vulnerability-count` | Number of vulnerabilities found |

## How It Works

1. The action installs the latest version of `govulncheck`
2. Runs `govulncheck -json ./...` in your project
3. Parses the JSON output to identify genuine vulnerability findings
4. Creates GitHub annotations:
   - **In `go.mod`**: Highlights vulnerable module dependencies
   - **In source files**: Marks lines that call vulnerable code paths
5. Sets output variables for use in subsequent workflow steps

## Example

The [`example/`](./example) directory contains a Go module with a known vulnerability to demonstrate the action:

- [`example/main.go`](./example/main.go) - Uses `html.Parse` from a vulnerable version of `golang.org/x/net`
- [`example/go.mod`](./example/go.mod) - Declares dependency on `golang.org/x/net v0.30.0` (vulnerable version)

## Example Workflow

See [`.github/workflows/example.yml`](./.github/workflows/example.yml) for a complete example workflow that:
- Runs govulncheck on the example directory
- Reports the results
- Demonstrates how to fail a workflow when vulnerabilities are found

## The Action In Action

[example.yaml](https://github.com/imjasonh/govulncheck-action/actions/.github/workflows/example.yaml) demonstrates the action running on the vulnerable module in `./example`.

## Development

The action is built with Node.js and uses the following structure:

```
.
├── index.js              # Main entry point
├── lib/
│   ├── govulncheck.js   # Handles govulncheck execution
│   ├── parser.js        # Parses JSON output
│   └── annotator.js     # Creates GitHub annotations
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
