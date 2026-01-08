# Containerd Release Tracker (Go)

Go implementation of the containerd release tracker with GitHub Models LLM integration.

## Features

- Fetch latest or specific containerd releases from GitHub
- Analyze release notes using GPT-4o via GitHub Models
- Extract dependency information (Go, runc, libseccomp) from repository files
- Output results in JSON format
- Pretty-print results to console

## Prerequisites

- Go 1.22 or later
- GitHub Personal Access Token

## Installation

```bash
# Clone the repository
git clone https://github.com/liunan-ms/containerd-release-tracker.git
cd containerd-release-tracker

# Install dependencies
go mod download
go mod tidy

# Build
go build -o containerd-tracker main.go
```

## Usage

Set your GitHub token:
```bash
export GITHUB_TOKEN='your_token_here'
```

Run the tracker:

```bash
# Parse latest release
./containerd-tracker

# Parse specific version
./containerd-tracker --version 2.0.0
./containerd-tracker -v v1.7.13

# Save to custom file
./containerd-tracker --output my_analysis.json
./containerd-tracker -o my_analysis.json

# Provide token via flag
./containerd-tracker --token your_token_here
```

## Output

The tool generates a JSON file with:
- Release version, URL, and publish date
- Release note changes (breaking changes, security updates, etc.)
- Dependencies (Go version, runc version, libseccomp version)

Example output:
```json
{
  "version": "v2.2.1",
  "published_at": "2025-12-18T17:37:28Z",
  "url": "https://github.com/containerd/containerd/releases/tag/v2.2.1",
  "release_notes_length": 5432,
  "changes": {
    "breaking_changes": "...",
    "security_updates": "...",
    "notable_changes": "...",
    "upgrade_notes": "..."
  },
  "dependencies": {
    "golang_minimum": "1.22",
    "golang_recommended": "1.22.5, 1.23.1",
    "runc_version": "1.1.12",
    "libseccomp_version": "2.5.5"
  }
}
```

## Development

Run directly:
```bash
go run main.go --version 2.0.0
```

Run tests:
```bash
go test ./...
```

## License

MIT
