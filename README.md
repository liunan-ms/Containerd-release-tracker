# Containerd Release Tracker

A comprehensive tool to track containerd releases, extract dependency information, and automate package upgrades in Azure Linux using LLM-powered intelligent updates.

## Features

### 1. Release Analysis
- **Fetch containerd releases** from GitHub API (latest or specific versions)
- **Extract dependencies** directly from source files:
  - `golang_minimum`: From `go.mod`
  - `golang_recommended`: From CI workflow YAML
  - `runc_version`, `libseccomp_version`: From GitHub releases
- **Analyze release notes** using GPT-4o via GitHub Models API
- **Generate structured JSON** analysis with changes and dependencies

### 2. Package Upgrade Automation
- **Automatically upgrade** containerd and dependencies in Azure Linux
- **Create dev branches** in local git repository
- **Use LLM to intelligently update** RPM spec files:
  - Update Version and Release fields
  - Update commit hashes for commit-based sources
  - Add proper changelog entries
  - Update tarball sha256 signatures
- **Calculate** source tarball sha256 signatures
- **Commit changes** with descriptive messages
- **Push to remote** and provide PR creation links

### TODO
- **Automatically remove CVE patches included in the new versions during package upgrade**
- **Automatically upload source tarball**
- **Automatically trigger package build, image build and tests**

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

## Prerequisites

- **Go 1.22 or later**
- **GitHub Personal Access Token** with appropriate permissions
- **Azure Linux repository** cloned locally (for upgrades)

## Installation

```bash
# Clone the repository
git clone https://github.com/liunan-ms/containerd-release-tracker.git
cd containerd-release-tracker

# Install dependencies
go mod download
go mod tidy

# Build both tools
go build -o containerd-tracker main.go
go build -o upgrade-packages cmd/upgrade/main.go
```

## Quick Start

### 1. Parse a Containerd Release

Set your GitHub token:
```bash
export GITHUB_TOKEN='your_github_token'
```

Run the parser:
```bash
# Parse latest release
./containerd-tracker

# Parse specific version
./containerd-tracker --version 2.2.1
./containerd-tracker -v v2.0.0

# Save to custom file
./containerd-tracker --output my_analysis.json -v 2.2.1
```

**Example Output** (`containerd_release_analysis.json`):
```json
{
  "version": "v2.2.1",
  "published_at": "2025-12-18T17:37:28Z",
  "url": "https://github.com/containerd/containerd/releases/tag/v2.2.1",
  "release_notes_length": 5432,
  "changes": {
    "breaking_changes": "None",
    "security_updates": "Updated to address CVE-2024-XXXX",
    "notable_changes": "Improved performance for image pulls...",
    "upgrade_notes": "Recommended to upgrade runc to 1.1.12"
  },
  "dependencies": {
    "golang_minimum": "1.22",
    "golang_recommended": "1.22.5, 1.23.1",
    "runc_version": "1.1.12",
    "libseccomp_version": "2.5.5"
  }
}
```

### 2. Upgrade Azure Linux Packages

```bash
# Run upgrade tool (requires release analysis JSON)
./upgrade-packages \
  --analysis containerd_release_analysis.json \
  --token $GITHUB_TOKEN \
  --repo /path/to/azurelinux

# Default repo path is /workspace/azurelinux
./upgrade-packages --analysis containerd_release_analysis.json --token $GITHUB_TOKEN
```

**Example Output**:
```
🚀 Starting package upgrade process...

📊 Loaded analysis for containerd v2.2.1

📋 Found 4 packages to upgrade:
   • containerd2: 2.2.1
   • golang: 1.24.3
   • runc: 1.3.4
   • libseccomp: 2.5.6

📂 Using local repository: /workspace/azurelinux
🔄 Fetching latest changes from origin...
🌿 Creating new branch: containerd-upgrade-2.2.1-20260108-220643 from origin/3.0-dev
✅ Branch containerd-upgrade-2.2.1-20260108-220643 created successfully

================================================================================
📦 Upgrading containerd2 to version 2.2.1
================================================================================
📥 Reading spec file: /workspace/azurelinux/SPECS/containerd2/containerd2.spec
🔍 Looking up commit hash for containerd/containerd@v2.2.1...
✅ Found commit hash (via commits endpoint): dea7da592f5d1d2b7755e3a161be07f43fad8f75
🤖 Using LLM to update containerd2 spec file to version 2.2.1...
✅ Updated %define commit_hash to dea7da59
✅ Spec file updated
🔐 Downloading source tarball from https://github.com/containerd/containerd/archive/v2.2.1.tar.gz...
✅ SHA256: af5707a26891486332142cc0ade4f0c543f707d3954838f5cecee73b833cf9b4
📝 Updating signatures.json for containerd2...
✅ Updated signatures.json with version 2.2.1
💾 Writing updated spec file: /workspace/azurelinux/SPECS/containerd2/containerd2.spec
📤 Committing changes for containerd2...
✅ Committed containerd2 spec file

================================================================================
📦 Upgrading runc to version 1.3.4
================================================================================
📥 Reading spec file: /workspace/azurelinux/SPECS/runc/runc.spec
🔍 Looking up commit hash for opencontainers/runc@v1.3.4...
✅ Found commit hash (via commits endpoint): d6d73eb8c60246978da649ffe75ce5c8bca8f856
🤖 Using LLM to update runc spec file to version 1.3.4...
✅ Updated %define commit_hash to d6d73eb8
✅ Spec file updated
🔐 Downloading source tarball from https://github.com/opencontainers/runc/archive/v1.3.4.tar.gz...
✅ SHA256: a9f9646c4c8990239f6462b408b22d9aa40ba0473a9fc642b9d6576126495eee
📝 Updating signatures.json for runc...
✅ Updated signatures.json with version 1.3.4
💾 Writing updated spec file: /workspace/azurelinux/SPECS/runc/runc.spec
📤 Committing changes for runc...
✅ Committed runc spec file

================================================================================
📊 UPGRADE SUMMARY
================================================================================
✅ Successfully upgraded: 4 packages
❌ Failed: 0 packages
🌿 Branch: containerd-upgrade-2.2.1-20260108-220643
📂 Local repository: /workspace/azurelinux

💡 Next steps:
   1. Review the changes: cd /workspace/azurelinux && git diff origin/3.0-dev
   2. Push to remote: git push origin containerd-upgrade-2.2.1-20260108-220643
   3. Create PR at: https://github.com/microsoft/azurelinux/compare/3.0-dev...liunan-ms:containerd-upgrade-2.2.1-20260108-220643
```

The tool will:
- Create a timestamped branch (e.g., `containerd-upgrade-2.2.1-20260108-220643`)
- Update spec files for containerd2, golang, runc, and libseccomp
- Fetch commit hashes from GitHub for commit-based sources
- Download source tarballs and calculate sha256sums
- Update signature files with new checksums
- Commit all changes with descriptive messages
- Skip packages that are already up-to-date

## CLI Reference

### containerd-tracker

Parse containerd releases and generate dependency analysis.

**Usage:**
```bash
./containerd-tracker [flags]
```

**Flags:**
- `--version, -v`: Containerd version to parse (default: latest)
- `--token, -t`: GitHub personal access token (can also use `GITHUB_TOKEN` env var)
- `--output, -o`: Output JSON file (default: `containerd_release_analysis.json`)

**Examples:**
```bash
# Parse latest release
./containerd-tracker --token $GITHUB_TOKEN

# Parse specific version
./containerd-tracker -v 2.2.1 -t $GITHUB_TOKEN

# Custom output file
./containerd-tracker -v 2.0.0 -o my-analysis.json
```

### upgrade-packages

Upgrade containerd and dependencies in Azure Linux repository.

**Usage:**
```bash
./upgrade-packages [flags]
```

**Flags:**
- `--analysis, -a`: Path to release analysis JSON file (default: `containerd_release_analysis.json`)
- `--token, -t`: GitHub personal access token (required for API calls and LLM)
- `--repo, -r`: Path to local Azure Linux repository (default: `/workspace/azurelinux`)

**Examples:**
```bash
# Standard upgrade
./upgrade-packages --analysis containerd_release_analysis.json --token $GITHUB_TOKEN

# Custom repository path
./upgrade-packages -a my-analysis.json -t $GITHUB_TOKEN -r /path/to/azurelinux

# Short form
./upgrade-packages -a analysis.json -t $GITHUB_TOKEN
```

## How It Works

### Release Analysis Process

1. **Fetch Release**: Query GitHub API for containerd release information
2. **Extract Dependencies**: Parse source files to get exact dependency versions:
   - Read `go.mod` for minimum Go version
   - Parse `.github/workflows/*.yml` for recommended Go versions
   - Fetch runc and libseccomp versions from GitHub
3. **Analyze Release Notes**: Use GPT-4o LLM to categorize changes into:
   - Breaking changes
   - Security updates
   - Notable changes
   - Upgrade notes
4. **Generate JSON**: Output structured data for automation

### Package Upgrade Process

1. **Load Analysis**: Read the containerd release analysis JSON
2. **Extract Packages**: Identify packages to upgrade (containerd2, golang, runc, libseccomp)
3. **Create Branch**: Generate timestamped branch from `3.0-dev`
4. **For Each Package**:
   - Check if upgrade needed (version comparison)
   - Fetch commit hash from GitHub (for commit-based sources)
   - Use LLM to update spec file:
     - Update Version and Release fields
     - Update commit hash (if applicable)
     - Add changelog entry
     - Update Source0 URL
   - Download source tarball from GitHub
   - Calculate sha256sum
   - Update signatures.json file
   - Commit changes with descriptive message
5. **Summary**: Display upgrade results and next steps

## Package Usage

You can import the parser package in your own Go projects:

```go
import (
    "context"
    "log"
    "github.com/liunan-ms/containerd-release-tracker/pkg/parser"
)

func main() {
    p := parser.NewParser("your-github-token")
    result, err := p.ParseRelease(context.Background(), "2.2.1")
    if err != nil {
        log.Fatal(err)
    }
    p.SaveToFile(result, "output.json")
}
```

Import the upgrade package:

```go
import (
    "context"
    "github.com/liunan-ms/containerd-release-tracker/pkg/upgrade"
)

func main() {
    ctx := context.Background()
    manager := upgrade.NewUpgradeManager("github-token", "/path/to/azurelinux")
    err := manager.UpgradeAllPackages(ctx, "containerd_release_analysis.json")
    if err != nil {
        log.Fatal(err)
    }
}
```

## Dependencies

- **github.com/google/go-github/v58** - GitHub API client
- **golang.org/x/oauth2** - OAuth2 authentication for GitHub API

## Development

### Run Without Building

```bash
# Run parser
go run main.go --version 2.2.1

# Run upgrade tool
go run cmd/upgrade/main.go --analysis containerd_release_analysis.json --token $GITHUB_TOKEN
```

### Run Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Verbose output
go test -v ./...
```

### Code Structure

**pkg/parser**: Handles GitHub API interaction and dependency extraction
- `NewParser()`: Create parser with GitHub token
- `ParseRelease()`: Fetch and analyze a specific release
- `GetLatestRelease()`: Get the latest containerd release
- Direct file parsing for dependencies (no LLM for dependency extraction)

**pkg/agent**: LLM abstraction layer for GitHub Models API
- `CallLLM()`: Returns parsed JSON response
- `CallLLMRaw()`: Returns raw text response
- Uses GPT-4o model via `models.inference.ai.azure.com`

**pkg/upgrade**: Azure Linux package upgrade automation
- `NewUpgradeManager()`: Initialize with token and repo path
- `UpgradeAllPackages()`: Main workflow orchestration
- `UpdateSpecFile()`: LLM-powered spec file updates
- `GetSourceSha256FromGitHub()`: Download and hash tarballs
- `UpdateSignaturesJson()`: Update signature files

## Configuration

### GitHub Token

The GitHub token needs the following permissions:
- **`repo`**: Read repository data and releases
- **`read:packages`**: Read package data (if accessing private repos)

For microsoft/azurelinux with SAML SSO:
1. Generate token at https://github.com/settings/tokens
2. Authorize for `microsoft` organization with SAML SSO
3. Use token with the tool

### Environment Variables

```bash
# GitHub token (alternative to --token flag)
export GITHUB_TOKEN='your_github_token_here'

# Run without token flag
./containerd-tracker --version 2.2.1
./upgrade-packages --analysis containerd_release_analysis.json
```

## Troubleshooting

### Common Issues

**Issue**: "No signatures.json found for package"
- **Cause**: Package doesn't have a signatures file
- **Solution**: Tool automatically skips signature update for such packages

**Issue**: "Could not fetch commit hash"
- **Cause**: Version tag doesn't exist in GitHub
- **Solution**: Tool continues without commit hash update

**Issue**: "LLM returned invalid JSON"
- **Cause**: LLM response parsing error
- **Solution**: Check your GitHub token and retry

**Issue**: GitHub API rate limit
- **Cause**: Too many API calls without authentication
- **Solution**: Always provide GitHub token

### Debug Tips

```bash
# Check if Azure Linux repo exists
ls -la /workspace/azurelinux/SPECS/

# Verify GitHub token
curl -H "Authorization: token $GITHUB_TOKEN" https://api.github.com/user

# Test containerd release fetch
curl https://api.github.com/repos/containerd/containerd/releases/tags/v2.2.1

# Check branch creation
cd /workspace/azurelinux && git branch | grep containerd-upgrade
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License
