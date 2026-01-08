package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"
	"github.com/liunan-ms/containerd-release-tracker/pkg/agent"
	"golang.org/x/oauth2"
)

// ContainerdRelease represents a containerd release with extracted information
type ContainerdRelease struct {
	Version            string                 `json:"version"`
	PublishedAt        string                 `json:"published_at"`
	URL                string                 `json:"url"`
	ReleaseNotesLength int                    `json:"release_notes_length,omitempty"`
	Changes            map[string]interface{} `json:"changes,omitempty"`
	Dependencies       map[string]interface{} `json:"dependencies,omitempty"`
}

// Parser handles containerd release parsing
type Parser struct {
	client    *github.Client
	token     string
	llmClient *agent.LLMClient
}

// NewParser creates a new parser instance
func NewParser(token string) *Parser {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)

	return &Parser{
		client:    github.NewClient(tc),
		token:     token,
		llmClient: agent.NewLLMClient(token),
	}
}

// ParseRelease fetches and parses a containerd release
func (p *Parser) ParseRelease(ctx context.Context, version string) (*ContainerdRelease, error) {
	var release *github.RepositoryRelease
	var err error

	if version != "" {
		release, err = p.fetchSpecificRelease(ctx, version)
	} else {
		release, err = p.fetchLatestRelease(ctx)
	}

	if err != nil {
		return nil, err
	}

	result := &ContainerdRelease{
		Version:     release.GetTagName(),
		PublishedAt: release.GetPublishedAt().Format(time.RFC3339),
		URL:         release.GetHTMLURL(),
	}

	releaseNotes := release.GetBody()
	if releaseNotes == "" {
		fmt.Println("⚠️  No release notes found")
		return result, nil
	}

	result.ReleaseNotesLength = len(releaseNotes)

	changes, err := p.parseWithLLM(ctx, releaseNotes)
	if err != nil {
		return nil, err
	}
	result.Changes = changes

	dependencies, err := p.extractDependencies(ctx, result.Version)
	if err != nil {
		return nil, err
	}
	result.Dependencies = dependencies

	return result, nil
}

func (p *Parser) fetchLatestRelease(ctx context.Context) (*github.RepositoryRelease, error) {
	fmt.Println("🔍 Fetching latest containerd release...")
	release, _, err := p.client.Repositories.GetLatestRelease(ctx, "containerd", "containerd")
	if err != nil {
		return nil, err
	}
	fmt.Printf("✅ Found: %s\n\n", release.GetTagName())
	return release, nil
}

func (p *Parser) fetchSpecificRelease(ctx context.Context, version string) (*github.RepositoryRelease, error) {
	tag := version
	if !strings.HasPrefix(version, "v") {
		tag = "v" + version
	}
	fmt.Printf("🔍 Fetching containerd release %s...\n", tag)
	release, _, err := p.client.Repositories.GetReleaseByTag(ctx, "containerd", "containerd", tag)
	if err != nil {
		return nil, err
	}
	fmt.Printf("✅ Found: %s\n\n", release.GetTagName())
	return release, nil
}

func (p *Parser) parseWithLLM(ctx context.Context, releaseNotes string) (map[string]interface{}, error) {
	fmt.Println("🤖 Analyzing release notes...")
	truncated := releaseNotes
	if len(releaseNotes) > 50000 {
		truncated = releaseNotes[:50000]
	}

	prompt := fmt.Sprintf(`Analyze these containerd release notes.

Release Notes:
%s

Return ONLY valid JSON with these keys (use null if not found):
{
  "breaking_changes": "brief summary of breaking changes",
  "security_updates": "summary of security-related updates",
  "notable_changes": "other notable changes worth highlighting",
  "upgrade_notes": "important notes for dependency upgrading"
}`, truncated)

	parsed, err := p.llmClient.CallLLM(ctx, prompt)
	if err != nil {
		return nil, err
	}

	fmt.Println("✅ Analysis complete\n")
	return parsed, nil
}

func (p *Parser) extractDependencies(ctx context.Context, version string) (map[string]interface{}, error) {
	fmt.Printf("🤖 Extract dependency information from containerd repository...\n")
	fmt.Printf("📝 containerd version: %s\n\n", version)

	deps := make(map[string]interface{})

	// Fetch go.mod to get Go version
	golangMinimum := ""
	goModURL := fmt.Sprintf("https://raw.githubusercontent.com/containerd/containerd/%s/go.mod", version)
	if resp, err := http.Get(goModURL); err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "go ") && !strings.HasPrefix(line, "go:") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					golangMinimum = parts[1]
					fmt.Printf("✅ Found Go version from go.mod: %s\n", golangMinimum)
					break
				}
			}
		}
	} else if err != nil {
		fmt.Printf("⚠️  Failed to fetch go.mod: %v\n", err)
	}

	deps["golang_minimum"] = golangMinimum

	// Fetch recommended Go versions from CI workflow
	var golangRecommended []string
	ciYMLURL := fmt.Sprintf("https://raw.githubusercontent.com/containerd/containerd/%s/.github/workflows/ci.yml", version)
	if resp, err := http.Get(ciYMLURL); err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		content := string(body)

		// Look for go-version array in the YAML
		// Match patterns like: go-version: ["1.24.11", "1.25.5"]
		start := strings.Index(content, "go-version:")
		if start != -1 {
			remaining := content[start:]
			bracketStart := strings.Index(remaining, "[")
			bracketEnd := strings.Index(remaining, "]")
			if bracketStart != -1 && bracketEnd != -1 && bracketEnd > bracketStart {
				versionsStr := remaining[bracketStart+1 : bracketEnd]
				for _, part := range strings.Split(versionsStr, ",") {
					part = strings.TrimSpace(part)
					part = strings.Trim(part, `"'`)
					if part != "" {
						golangRecommended = append(golangRecommended, part)
					}
				}
				if len(golangRecommended) > 0 {
					fmt.Printf("✅ Found recommended Go versions from CI: %s\n", strings.Join(golangRecommended, ", "))
				}
			}
		}
	} else if err != nil {
		fmt.Printf("⚠️  Failed to fetch CI workflow: %v\n", err)
	}

	deps["golang_recommended"] = strings.Join(golangRecommended, ", ")

	// Fetch runc version from script/setup/runc-version
	runcVersion := ""
	runcURL := fmt.Sprintf("https://raw.githubusercontent.com/containerd/containerd/%s/script/setup/runc-version", version)
	if resp, err := http.Get(runcURL); err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		runcVersion = strings.TrimSpace(string(body))
		// Remove 'v' prefix if present
		runcVersion = strings.TrimPrefix(runcVersion, "v")
		fmt.Printf("✅ Found runc version from script: %s\n", runcVersion)
	} else if err != nil {
		fmt.Printf("⚠️  Failed to fetch runc version: %v\n", err)
	}

	deps["runc_version"] = runcVersion

	// Fetch libseccomp version from runc release assets
	libseccompVersion := ""
	if runcVersion != "" {
		runcRelease, _, err := p.client.Repositories.GetReleaseByTag(ctx, "opencontainers", "runc", "v"+runcVersion)
		if err == nil {
			// Look for libseccomp tarball in assets
			for _, asset := range runcRelease.Assets {
				assetName := asset.GetName()
				// Match pattern like: libseccomp-2.5.6.tar.gz
				if strings.HasPrefix(assetName, "libseccomp-") && strings.HasSuffix(assetName, ".tar.gz") {
					// Extract version between "libseccomp-" and ".tar.gz"
					libseccompVersion = strings.TrimSuffix(strings.TrimPrefix(assetName, "libseccomp-"), ".tar.gz")
					fmt.Printf("✅ Found libseccomp version from runc release: %s\n", libseccompVersion)
					break
				}
			}
		} else {
			fmt.Printf("⚠️  Failed to fetch runc release: %v\n", err)
		}
	}

	deps["libseccomp_version"] = libseccompVersion

	fmt.Println()
	return deps, nil
}

// SaveToFile saves the release data to a JSON file
func (p *Parser) SaveToFile(result *ContainerdRelease, filename string) error {
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return err
	}
	fmt.Printf("💾 Saved to: %s\n", filename)
	return nil
}
