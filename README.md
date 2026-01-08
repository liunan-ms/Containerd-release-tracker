# Containerd Release Tracker

A tool to track containerd releases, extract dependency information, and automate package upgrades in Azure Linux.

## Project Structure

```
.
├── main.go                          # CLI for release parsing
├── cmd/
│   └── upgrade/
│       └── main.go                  # CLI for package upgrades
├── pkg/
│   ├── parser/
│   │   └── parser.go                # Containerd release parsing logic
│   ├── agent/
│   │   └── agent.go                 # LLM abstraction layer
│   └── upgrade/
│       └── upgrade.go               # Azure Linux package upgrade logic
├── scripts/
│   └── parse_containerd_release.py  # Python parser (legacy)
└── containerd_release_analysis.json # Example output
```

## Features

### 1. Release Parser
- Fetch containerd releases from GitHub API
- Extract dependencies directly from source files:
  - `golang_minimum`: From `go.mod`
  - `golang_recommended`: From CI workflow YAML
  - `runc_version`, `libseccomp_version`: From GitHub
- Analyze release notes with GPT-4o LLM
- Generate JSON analysis

### 2. Package Upgrade Tool
- Automatically upgrade containerd and dependencies in Azure Linux
- Create dev branches in microsoft/azurelinux
- Use LLM to intelligently update RPM spec files
- Commit changes with proper changelog entries

## Quick Start

### Parse a Release

```bash
# Build
go build -o containerd-tracker main.go

# Run
export GITHUB_TOKEN='your_github_token'
./containerd-tracker --version 2.0.1

# Output: containerd_release_analysis.json
```

### Upgrade Packages

```bash
# Build
go build -o upgrade-packages cmd/upgrade/main.go

# Run (requires release analysis JSON)
./upgrade-packages --analysis containerd_release_analysis.json --token $GITHUB_TOKEN

# Creates branch: containerd-upgrade-2.0.1-YYYYMMDD-HHMMSS
# URL: https://github.com/microsoft/azurelinux/tree/[branch-name]
```

## CLI Reference

### containerd-tracker

Parse containerd releases and generate analysis.

```
Flags:
  --version, -v    Containerd version to parse (default: latest)
  --token, -t      GitHub personal access token (required)
  --output, -o     Output JSON file (default: containerd_release_analysis.json)
```

### upgrade-packages

Upgrade containerd and dependencies in Azure Linux.

```
Flags:
  --analysis, -a   Path to release analysis JSON (default: containerd_release_analysis.json)
  --token, -t      GitHub personal access token (required)
```

## Dependencies

- `github.com/google/go-github/v58` - GitHub API client
- `golang.org/x/oauth2` - OAuth2 authentication

## Development

```bash
# Install dependencies
go mod tidy

# Run directly
go run main.go --version 2.0.0

# Build
go build -o containerd-tracker main.go
```

## Package Usage

You can import the parser package in your own Go projects:

```go
import "github.com/liunan-ms/containerd-release-tracker/pkg/parser"

p := parser.NewParser("your-github-token")
result, err := p.ParseRelease(context.Background(), "2.0.0")
if err != nil {
    log.Fatal(err)
}
p.SaveToFile(result, "output.json")
```
