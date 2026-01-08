package upgrade

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v58/github"
	"github.com/liunan-ms/containerd-release-tracker/pkg/agent"
	"golang.org/x/oauth2"
)

// ReleaseAnalysis represents the structure of containerd_release_analysis.json
type ReleaseAnalysis struct {
	Version      string                 `json:"version"`
	PublishedAt  string                 `json:"published_at"`
	URL          string                 `json:"url"`
	Dependencies map[string]interface{} `json:"dependencies,omitempty"`
	Changes      map[string]interface{} `json:"changes,omitempty"`
}

// PackageVersion represents a package to upgrade
type PackageVersion struct {
	Name    string
	Version string
}

// UpgradeManager handles package upgrades in Azure Linux repo
type UpgradeManager struct {
	client        *github.Client
	llmClient     *agent.LLMClient
	token         string
	localRepoPath string
}

// NewUpgradeManager creates a new upgrade manager instance
func NewUpgradeManager(token string, localRepoPath string) *UpgradeManager {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	if localRepoPath == "" {
		localRepoPath = "/workspace/azurelinux"
	}

	return &UpgradeManager{
		client:        client,
		llmClient:     agent.NewLLMClient(token),
		token:         token,
		localRepoPath: localRepoPath,
	}
}

// LoadReleaseAnalysis reads and parses the containerd_release_analysis.json file
func LoadReleaseAnalysis(filePath string) (*ReleaseAnalysis, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var analysis ReleaseAnalysis
	if err := json.Unmarshal(data, &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	return &analysis, nil
}

// ExtractPackageVersions extracts package names and versions from release analysis
func ExtractPackageVersions(analysis *ReleaseAnalysis) []PackageVersion {
	var packages []PackageVersion

	// Add containerd itself
	containerdVersion := strings.TrimPrefix(analysis.Version, "v")
	packages = append(packages, PackageVersion{
		Name:    "containerd2",
		Version: containerdVersion,
	})

	// Extract dependencies
	if analysis.Dependencies != nil {
		// Map dependency keys to package names
		packageMap := map[string]string{
			"golang_minimum":     "golang",
			"runc_version":       "runc",
			"libseccomp_version": "libseccomp",
		}

		for depKey, pkgName := range packageMap {
			if ver, ok := analysis.Dependencies[depKey]; ok {
				if verStr, ok := ver.(string); ok && verStr != "" {
					packages = append(packages, PackageVersion{
						Name:    pkgName,
						Version: verStr,
					})
				}
			}
		}
	}

	return packages
}

// extractVersionFromSpec extracts the Version field from a spec file
func extractVersionFromSpec(content string) string {
	re := regexp.MustCompile(`(?m)^Version:\s*(.+)$`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// extractCommitFromSpec extracts the %global commit field from a spec file
func extractCommitFromSpec(content string) string {
	re := regexp.MustCompile(`(?m)^%global\s+commit\s+([a-f0-9]{7,40})\s*$`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// getGitHubRepoFromSpec extracts GitHub repo URL from spec file
func getGitHubRepoFromSpec(content string) (owner, repo string) {
	// Try to extract from Source0 URL
	re := regexp.MustCompile(`(?:https?://)?github\.com/([^/]+)/([^/]+)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 2 {
		return matches[1], strings.TrimSuffix(matches[2], ".git")
	}
	return "", ""
}

// extractSourceFilenameFromSpec extracts the source filename from spec file
func extractSourceFilenameFromSpec(content string, version string) string {
	// Look for Source0 line
	re := regexp.MustCompile(`(?m)^Source0:\s*(.+)$`)
	matches := re.FindStringSubmatch(content)
	if len(matches) < 2 {
		return ""
	}

	sourceLine := strings.TrimSpace(matches[1])

	// Replace common macros
	sourceLine = strings.ReplaceAll(sourceLine, "%{version}", version)
	sourceLine = strings.ReplaceAll(sourceLine, "%{Version}", version)
	sourceLine = strings.ReplaceAll(sourceLine, "${version}", version)

	// Extract filename from URL if it's a URL
	if strings.Contains(sourceLine, "/") {
		parts := strings.Split(sourceLine, "/")
		return parts[len(parts)-1]
	}

	return sourceLine
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Remove 'v' prefix if present
	v1 = strings.TrimPrefix(v1, "v")
	v2 = strings.TrimPrefix(v2, "v")

	// Split by dots
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	// Compare each part
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int

		if i < len(parts1) {
			// Extract numeric part (ignore any suffix like -rc1)
			numPart := regexp.MustCompile(`^\d+`).FindString(parts1[i])
			if numPart != "" {
				n1, _ = strconv.Atoi(numPart)
			}
		}

		if i < len(parts2) {
			numPart := regexp.MustCompile(`^\d+`).FindString(parts2[i])
			if numPart != "" {
				n2, _ = strconv.Atoi(numPart)
			}
		}

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	return 0
}

// GetSourceSha256 downloads the source tarball and calculates its sha256sum
func (m *UpgradeManager) GetSourceSha256(ctx context.Context, packageName, version, sourceFilename string) (string, error) {
	if sourceFilename == "" {
		return "", fmt.Errorf("source filename is empty")
	}

	// Path where source files are stored
	sourcePath := fmt.Sprintf("%s/SPECS/%s/%s", m.localRepoPath, packageName, sourceFilename)

	fmt.Printf("🔐 Calculating sha256sum for %s...\n", sourceFilename)

	// Check if source file exists locally
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		// Try to download from spectool or source URL
		fmt.Printf("📥 Source file not found locally, attempting to fetch with spectool...\n")
		fetchCmd := fmt.Sprintf("cd %s/SPECS/%s && spectool -g -S %s.spec 2>&1 || true",
			m.localRepoPath, packageName, packageName)

		if err := m.runCommand(fetchCmd); err != nil {
			fmt.Printf("⚠️  Could not fetch source with spectool: %v\n", err)
		}

		// Check again if file exists after download attempt
		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			return "", fmt.Errorf("source file not found and could not be downloaded: %s", sourceFilename)
		}
	}

	// Calculate sha256sum
	sha256Cmd := fmt.Sprintf("sha256sum %s | awk '{print $1}'", sourcePath)
	sha256Exec := exec.Command("bash", "-c", sha256Cmd)
	output, err := sha256Exec.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to calculate sha256sum: %w: %s", err, string(output))
	}

	sha256 := strings.TrimSpace(string(output))
	if len(sha256) != 64 {
		return "", fmt.Errorf("invalid sha256sum length: %d (expected 64)", len(sha256))
	}

	fmt.Printf("✅ SHA256: %s\n", sha256)
	return sha256, nil
}

// GetCommitHashForVersion fetches the commit hash for a specific version tag from GitHub
func (m *UpgradeManager) GetCommitHashForVersion(ctx context.Context, owner, repo, version string) (string, error) {
	// Ensure version has 'v' prefix for tag lookup
	tagName := version
	if !strings.HasPrefix(version, "v") {
		tagName = "v" + version
	}

	fmt.Printf("🔍 Looking up commit hash for %s/%s@%s...\n", owner, repo, tagName)

	// Try to get the tag
	tag, resp, err := m.client.Git.GetRef(ctx, owner, repo, "tags/"+tagName)
	if err != nil {
		// If tag doesn't exist, try without 'v' prefix
		if resp != nil && resp.StatusCode == 404 && strings.HasPrefix(tagName, "v") {
			tagName = strings.TrimPrefix(tagName, "v")
			tag, _, err = m.client.Git.GetRef(ctx, owner, repo, "tags/"+tagName)
			if err != nil {
				return "", fmt.Errorf("failed to find tag %s: %w", tagName, err)
			}
		} else {
			return "", fmt.Errorf("failed to get tag: %w", err)
		}
	}

	if tag.Object == nil || tag.Object.SHA == nil {
		return "", fmt.Errorf("tag has no commit SHA")
	}

	commitSHA := *tag.Object.SHA
	fmt.Printf("✅ Found commit hash: %s\n", commitSHA[:8])
	return commitSHA, nil
}

// UpdateSignaturesJson updates the signatures.json file with new version and sha256
func (m *UpgradeManager) UpdateSignaturesJson(ctx context.Context, packageName, version, sha256sum string) error {
	signaturesPath := fmt.Sprintf("%s/SPECS/%s/signatures.json", m.localRepoPath, packageName)

	// Check if signatures.json exists
	if _, err := os.Stat(signaturesPath); os.IsNotExist(err) {
		fmt.Printf("ℹ️  No signatures.json found for %s, skipping signature update\n", packageName)
		return nil
	}

	fmt.Printf("📝 Updating signatures.json for %s...\n", packageName)

	// Read current signatures.json
	data, err := os.ReadFile(signaturesPath)
	if err != nil {
		return fmt.Errorf("failed to read signatures.json: %w", err)
	}

	// Parse JSON
	var signatures map[string]interface{}
	if err := json.Unmarshal(data, &signatures); err != nil {
		return fmt.Errorf("failed to parse signatures.json: %w", err)
	}

	// Update or add the signature for this version
	if signatures["Signatures"] == nil {
		signatures["Signatures"] = make(map[string]interface{})
	}

	sigMap, ok := signatures["Signatures"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid signatures.json format: Signatures is not a map")
	}

	// Add new signature entry
	sigMap[version] = map[string]string{
		"sha256": sha256sum,
	}

	// Write back to file with proper formatting
	updatedData, err := json.MarshalIndent(signatures, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal signatures.json: %w", err)
	}

	if err := os.WriteFile(signaturesPath, updatedData, 0644); err != nil {
		return fmt.Errorf("failed to write signatures.json: %w", err)
	}

	// Stage the signatures.json file
	addCmd := fmt.Sprintf("cd %s && git add SPECS/%s/signatures.json", m.localRepoPath, packageName)
	if err := m.runCommand(addCmd); err != nil {
		fmt.Printf("⚠️  Failed to stage signatures.json: %v\n", err)
	}

	fmt.Printf("✅ Updated signatures.json with version %s\n", version)
	return nil
}

// CreateDevBranch creates a new dev branch in local repository
func (m *UpgradeManager) CreateDevBranch(ctx context.Context, branchName string) error {
	baseBranch := "3.0-dev"

	fmt.Printf("📂 Using local repository: %s\n", m.localRepoPath)

	// Check if repo exists
	if _, err := os.Stat(m.localRepoPath); os.IsNotExist(err) {
		return fmt.Errorf("local repository not found at %s", m.localRepoPath)
	}

	// Fetch latest changes from origin
	fmt.Printf("🔄 Fetching latest changes from origin...\n")
	cmd := fmt.Sprintf("cd %s && git fetch origin %s", m.localRepoPath, baseBranch)
	if err := m.runCommand(cmd); err != nil {
		return fmt.Errorf("failed to fetch from origin: %w", err)
	}

	// Check if branch already exists
	fmt.Printf("🔍 Checking if branch %s already exists...\n", branchName)
	checkCmd := fmt.Sprintf("cd %s && git rev-parse --verify %s 2>/dev/null", m.localRepoPath, branchName)
	if m.runCommand(checkCmd) == nil {
		fmt.Printf("⚠️  Branch %s already exists, checking it out...\n", branchName)
		checkoutCmd := fmt.Sprintf("cd %s && git checkout %s", m.localRepoPath, branchName)
		if err := m.runCommand(checkoutCmd); err != nil {
			return fmt.Errorf("failed to checkout existing branch: %w", err)
		}
		return nil
	}

	// Create new branch from origin/base
	fmt.Printf("🌿 Creating new branch: %s from origin/%s\n", branchName, baseBranch)
	createCmd := fmt.Sprintf("cd %s && git checkout -b %s origin/%s", m.localRepoPath, branchName, baseBranch)
	if err := m.runCommand(createCmd); err != nil {
		return fmt.Errorf("failed to create branch: %w", err)
	}

	fmt.Printf("✅ Branch %s created successfully\n\n", branchName)
	return nil
}

// runCommand executes a shell command
func (m *UpgradeManager) runCommand(cmd string) error {
	cmdExec := exec.Command("bash", "-c", cmd)

	output, err := cmdExec.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(output))
	}
	return nil
}

// GetSpecFileContent fetches the spec file content from local repository
func (m *UpgradeManager) GetSpecFileContent(ctx context.Context, packageName, branch string) (string, string, error) {
	specPath := fmt.Sprintf("%s/SPECS/%s/%s.spec", m.localRepoPath, packageName, packageName)

	fmt.Printf("📥 Reading spec file: %s\n", specPath)

	// Read file content
	content, err := os.ReadFile(specPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read spec file: %w", err)
	}

	// Return empty SHA as it's not needed for local operations
	return string(content), "", nil
}

// UpdateSpecFile updates a spec file with the new version using LLM
func (m *UpgradeManager) UpdateSpecFile(ctx context.Context, packageName, currentContent, newVersion, commitHash string) (string, error) {
	fmt.Printf("🤖 Using LLM to update %s spec file to version %s...\n", packageName, newVersion)

	// If commit hash is provided, update it in the content before LLM processing
	contentToUpdate := currentContent
	if commitHash != "" {
		// Try to update %global commit line directly
		commitRe := regexp.MustCompile(`(?m)^(%global\s+commit\s+)[a-f0-9]{7,40}(\s*)$`)
		if commitRe.MatchString(contentToUpdate) {
			contentToUpdate = commitRe.ReplaceAllString(contentToUpdate, fmt.Sprintf("${1}%s${2}", commitHash))
			fmt.Printf("✅ Updated %%global commit to %s\n", commitHash[:8])
		}
	}

	commitInstruction := ""
	if commitHash != "" {
		commitInstruction = fmt.Sprintf("\n6. IMPORTANT: Verify the %%global commit line is set to: %s", commitHash)
	}

	prompt := fmt.Sprintf(`You are an expert in RPM spec file management for Azure Linux.

Task: Update the following spec file to version %s.

Current spec file content:
%s

Instructions:
1. Update the Version field to %s
2. Update the Release field to 1 (reset for new version)
3. Add a new changelog entry at the top of the %%changelog section with:
   - Current date in format: %%{_day} %%{_month} %%{_year}
   - Your name: Containerd Release Tracker <azurelinux@microsoft.com>
   - Version string: %s-1
   - Message: "Update to version %s for containerd compatibility"
4. Update Source0 URL if it contains version numbers
5. Keep all other sections unchanged%s

Return ONLY the complete updated spec file content, no explanations or markdown code blocks.`,
		newVersion, contentToUpdate, newVersion, newVersion, newVersion, commitInstruction)

	// For spec files, we need the raw text response, not JSON
	result, err := m.llmClient.CallLLMRaw(ctx, prompt)
	if err != nil {
		return "", fmt.Errorf("LLM call failed: %w", err)
	}

	// Post-process: Ensure commit hash is updated even if LLM didn't handle it
	if commitHash != "" {
		commitRe := regexp.MustCompile(`(?m)^(%global\s+commit\s+)[a-f0-9]{7,40}(\s*)$`)
		if commitRe.MatchString(result) {
			// Verify it's set to the correct hash
			currentCommit := extractCommitFromSpec(result)
			if currentCommit != commitHash {
				result = commitRe.ReplaceAllString(result, fmt.Sprintf("${1}%s${2}", commitHash))
				fmt.Printf("🔧 Force-updated %%global commit to %s (LLM didn't update it correctly)\n", commitHash[:8])
			}
		}
	}

	fmt.Printf("✅ Spec file updated\n")
	return result, nil
}

// CommitSpecFile commits the updated spec file to the forked repository
// CommitSpecFile writes the updated spec file and commits locally
func (m *UpgradeManager) CommitSpecFile(ctx context.Context, packageName, branch, content, sha, version string) error {
	specPath := fmt.Sprintf("%s/SPECS/%s/%s.spec", m.localRepoPath, packageName, packageName)

	// Write updated content to file
	fmt.Printf("💾 Writing updated spec file: %s\n", specPath)
	if err := os.WriteFile(specPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write spec file: %w", err)
	}

	// Stage the file
	fmt.Printf("📤 Committing changes for %s...\n", packageName)
	addCmd := fmt.Sprintf("cd %s && git add SPECS/%s/%s.spec", m.localRepoPath, packageName, packageName)
	if err := m.runGitCommand(addCmd); err != nil {
		return fmt.Errorf("failed to stage file: %w", err)
	}

	// Commit the change
	commitMessage := fmt.Sprintf("Update %s to version %s\n\nAutomatic update for containerd compatibility", packageName, version)
	commitCmd := fmt.Sprintf("cd %s && git commit -m %s", m.localRepoPath, shellescape(commitMessage))
	if err := m.runGitCommand(commitCmd); err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	fmt.Printf("✅ Committed %s spec file\n\n", packageName)
	return nil
}

// runGitCommand executes a git command in the local repo
func (m *UpgradeManager) runGitCommand(cmd string) error {
	return m.runCommand(cmd)
}

// shellescape escapes a string for safe use in shell commands
func shellescape(s string) string {
	return fmt.Sprintf("'%s'", strings.ReplaceAll(s, "'", "'\\''"))
}

// UpgradePackage upgrades a single package in the Azure Linux repository
func (m *UpgradeManager) UpgradePackage(ctx context.Context, pkg PackageVersion, branch string) error {
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("📦 Upgrading %s to version %s\n", pkg.Name, pkg.Version)
	fmt.Println(strings.Repeat("=", 80))

	// Get current spec file
	currentContent, sha, err := m.GetSpecFileContent(ctx, pkg.Name, branch)
	if err != nil {
		return err
	}

	// Check current version in spec file
	currentVersion := extractVersionFromSpec(currentContent)
	if currentVersion != "" && compareVersions(currentVersion, pkg.Version) >= 0 {
		fmt.Printf("⏭️  Skipping %s: current version %s is already >= target version %s\n\n", pkg.Name, currentVersion, pkg.Version)
		return nil
	}

	// Try to get commit hash for the version if spec uses commit-based sources
	commitHash := ""
	if extractCommitFromSpec(currentContent) != "" {
		owner, repo := getGitHubRepoFromSpec(currentContent)
		if owner != "" && repo != "" {
			hash, err := m.GetCommitHashForVersion(ctx, owner, repo, pkg.Version)
			if err != nil {
				fmt.Printf("⚠️  Could not fetch commit hash: %v (continuing without it)\n", err)
			} else {
				commitHash = hash
			}
		}
	}

	// Update spec file using LLM
	updatedContent, err := m.UpdateSpecFile(ctx, pkg.Name, currentContent, pkg.Version, commitHash)
	if err != nil {
		return err
	}

	// Get source filename and calculate sha256sum
	sourceFilename := extractSourceFilenameFromSpec(updatedContent, pkg.Version)
	if sourceFilename != "" {
		sha256sum, err := m.GetSourceSha256(ctx, pkg.Name, pkg.Version, sourceFilename)
		if err != nil {
			fmt.Printf("⚠️  Could not calculate sha256sum: %v (continuing without signature update)\n", err)
		} else {
			// Update signatures.json
			if err := m.UpdateSignaturesJson(ctx, pkg.Name, pkg.Version, sha256sum); err != nil {
				fmt.Printf("⚠️  Could not update signatures.json: %v\n", err)
			}
		}
	} else {
		fmt.Printf("ℹ️  Could not extract source filename from spec, skipping signature update\n")
	}

	// Commit the updated spec file
	if err := m.CommitSpecFile(ctx, pkg.Name, branch, updatedContent, sha, pkg.Version); err != nil {
		return err
	}

	return nil
}

// UpgradeAllPackages upgrades all packages from the release analysis
func (m *UpgradeManager) UpgradeAllPackages(ctx context.Context, analysisFile string) error {
	fmt.Println("🚀 Starting package upgrade process...\n")

	// Load release analysis
	analysis, err := LoadReleaseAnalysis(analysisFile)
	if err != nil {
		return fmt.Errorf("failed to load release analysis: %w", err)
	}

	fmt.Printf("📊 Loaded analysis for containerd %s\n\n", analysis.Version)

	// Extract package versions
	packages := ExtractPackageVersions(analysis)
	fmt.Printf("📋 Found %d packages to upgrade:\n", len(packages))
	for _, pkg := range packages {
		fmt.Printf("   • %s: %s\n", pkg.Name, pkg.Version)
	}
	fmt.Println()

	// Create dev branch
	timestamp := time.Now().Format("20060102-150405")
	branchName := fmt.Sprintf("containerd-upgrade-%s-%s", strings.TrimPrefix(analysis.Version, "v"), timestamp)

	if err := m.CreateDevBranch(ctx, branchName); err != nil {
		return err
	}

	// Upgrade each package
	successCount := 0
	failureCount := 0

	for _, pkg := range packages {
		if err := m.UpgradePackage(ctx, pkg, branchName); err != nil {
			fmt.Printf("❌ Failed to upgrade %s: %v\n\n", pkg.Name, err)
			failureCount++
			continue
		}
		successCount++
	}

	// Summary
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("📊 UPGRADE SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("✅ Successfully upgraded: %d packages\n", successCount)
	fmt.Printf("❌ Failed: %d packages\n", failureCount)
	fmt.Printf("🌿 Branch: %s\n", branchName)
	fmt.Printf("📂 Local repository: %s\n", m.localRepoPath)
	fmt.Println()

	if successCount > 0 {
		fmt.Println("💡 Next steps:")
		fmt.Println("   1. Review the changes: cd", m.localRepoPath, "&& git diff origin/3.0-dev")
		fmt.Println("   2. Push to remote: git push origin", branchName)
		fmt.Println("   3. Create PR at: https://github.com/microsoft/azurelinux/compare/3.0-dev...liunan-ms:" + branchName)
		fmt.Println()
	}

	if failureCount > 0 {
		return fmt.Errorf("some packages failed to upgrade")
	}

	return nil
}
