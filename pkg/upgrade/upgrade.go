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

// extractCommitFromSpec extracts the %define commit_hash field from a spec file
func extractCommitFromSpec(content string) string {
	// Try %define commit_hash format
	re := regexp.MustCompile(`(?m)^%define\s+commit_hash\s+([a-f0-9]{7,40})\s*$`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}

	return ""
}

// getGitHubRepoFromSpec extracts GitHub repo URL from spec file
func getGitHubRepoFromSpec(content string) (owner, repo string) {
	// Extract from any line containing github.com URL (URL, Source0, etc.)
	// Match github.com/owner/repo and capture owner and repo parts
	re := regexp.MustCompile(`github\.com/([^/\s]+)/([^/\s#]+)`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 2 {
		repo := strings.TrimSuffix(matches[2], ".git")
		// Remove any query parameters or anchors
		if idx := strings.IndexAny(repo, "?#"); idx >= 0 {
			repo = repo[:idx]
		}
		return matches[1], repo
	}
	return "", ""
}

// GetSourceSha256FromGitHub downloads the source tarball from GitHub, calculates sha256sum, and deletes it
func (m *UpgradeManager) GetSourceSha256FromGitHub(ctx context.Context, owner, repo, version string) (string, error) {
	// Ensure version has 'v' prefix for tarball URL
	tagName := version
	if !strings.HasPrefix(version, "v") {
		tagName = "v" + version
	}

	// Construct GitHub archive URL
	downloadURL := fmt.Sprintf("https://github.com/%s/%s/archive/%s.tar.gz", owner, repo, tagName)

	// Create temporary file
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("%s-%s-*.tar.gz", repo, version))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()

	// Ensure temp file is deleted on return
	defer os.Remove(tmpPath)

	fmt.Printf("🔐 Downloading source tarball from %s...\n", downloadURL)

	// Download the file using curl
	downloadCmd := fmt.Sprintf("curl -sSL -o %s %s", tmpPath, downloadURL)
	if err := m.runCommand(downloadCmd); err != nil {
		return "", fmt.Errorf("failed to download tarball: %w", err)
	}

	// Verify file was downloaded and has content
	fileInfo, err := os.Stat(tmpPath)
	if err != nil {
		return "", fmt.Errorf("failed to stat downloaded file: %w", err)
	}
	if fileInfo.Size() == 0 {
		return "", fmt.Errorf("downloaded file is empty")
	}

	// Calculate sha256sum
	sha256Cmd := fmt.Sprintf("sha256sum %s | awk '{print $1}'", tmpPath)
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

	// Method 1: Try commits endpoint (works for tags and branches)
	commit, _, err := m.client.Repositories.GetCommit(ctx, owner, repo, tagName, nil)
	if err == nil && commit != nil && commit.SHA != nil {
		commitSHA := *commit.SHA
		fmt.Printf("✅ Found commit hash (via commits endpoint): %s\n", commitSHA)
		return commitSHA, nil
	}

	fmt.Printf("❌ Not found commit hash\n")
	return "", nil
}

// UpdateSignaturesJson updates the signatures.json file with new version and sha256
func (m *UpgradeManager) UpdateSignaturesJson(ctx context.Context, packageName, version, sha256sum string) error {
	signaturesPath := fmt.Sprintf("%s/SPECS/%s/%s.signatures.json", m.localRepoPath, packageName, packageName)

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

	currentContent := string(data)

	// For LLM prompt, use "containerd" instead of "containerd2" for tarball naming
	tarballName := packageName
	if packageName == "containerd2" {
		tarballName = "containerd"
	}

	// Use LLM to update the signatures.json
	prompt := fmt.Sprintf(`You are an expert in JSON file management for Azure Linux package signatures.

Task: Update the signatures.json file to replace the existing package tarball signature with the new version.

Current signatures.json content:
%s

Instructions:
1. Find the entry in "Signatures" that matches the pattern "%s-*.tar.gz" (e.g., "%s-2.0.0.tar.gz", "%s-1.9.0.tar.gz", etc.)
2. Replace that entry's key with "%s-%s.tar.gz" and its value with "%s"
3. If no matching tarball entry exists, add a new entry with key "%s-%s.tar.gz" and value "%s"
4. Keep all other entries (like .service files, .toml files, etc.) unchanged
5. Maintain proper JSON formatting with 2-space indentation
6. Ensure the JSON structure is valid

Example:
- Original: "containerd-2.0.0.tar.gz": "old_hash"
- Updated:  "containerd-2.2.1.tar.gz": "new_hash"

Return ONLY the complete updated signatures.json content, no explanations or markdown code blocks.`,
		currentContent, tarballName, tarballName, tarballName, tarballName, version, sha256sum, tarballName, version, sha256sum)

	// Call LLM to get updated JSON content
	result, err := m.llmClient.CallLLMRaw(ctx, prompt)
	if err != nil {
		return fmt.Errorf("LLM call failed: %w", err)
	}

	// Validate the result is valid JSON
	var testJSON map[string]interface{}
	if err := json.Unmarshal([]byte(result), &testJSON); err != nil {
		return fmt.Errorf("LLM returned invalid JSON: %w", err)
	}

	// Write the updated content
	if err := os.WriteFile(signaturesPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("failed to write signatures.json: %w", err)
	}

	// Stage the signatures.json file - use original packageName for directory path
	addCmd := fmt.Sprintf("cd %s && git add SPECS/%s/%s.signatures.json", m.localRepoPath, packageName, packageName)
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
		} else {
			// Try %define commit_hash format
			commitRe = regexp.MustCompile(`(?m)^(%define\s+commit_hash\s+)[a-f0-9]{7,40}(\s*)$`)
			if commitRe.MatchString(contentToUpdate) {
				contentToUpdate = commitRe.ReplaceAllString(contentToUpdate, fmt.Sprintf("${1}%s${2}", commitHash))
				fmt.Printf("✅ Updated %%define commit_hash to %s\n", commitHash[:8])
			}
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
		currentCommit := extractCommitFromSpec(result)
		if currentCommit != commitHash {
			// Try %global commit format first
			commitRe := regexp.MustCompile(`(?m)^(%global\s+commit\s+)[a-f0-9]{7,40}(\s*)$`)
			if commitRe.MatchString(result) {
				result = commitRe.ReplaceAllString(result, fmt.Sprintf("${1}%s${2}", commitHash))
				fmt.Printf("🔧 Force-updated %%global commit to %s (LLM didn't update it correctly)\n", commitHash[:8])
			} else {
				// Try %define commit_hash format
				commitRe = regexp.MustCompile(`(?m)^(%define\s+commit_hash\s+)[a-f0-9]{7,40}(\s*)$`)
				if commitRe.MatchString(result) {
					result = commitRe.ReplaceAllString(result, fmt.Sprintf("${1}%s${2}", commitHash))
					fmt.Printf("🔧 Force-updated %%define commit_hash to %s (LLM didn't update it correctly)\n", commitHash[:8])
				}
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
	owner, repo := getGitHubRepoFromSpec(currentContent)

	// Try to get commit hash for the version if spec uses commit-based sources
	commitHash := ""
	if extractCommitFromSpec(currentContent) != "" {
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
	// Try to get sha256sum from GitHub source tarball if owner/repo are available
	var sha256sum string

	if owner != "" && repo != "" {
		sha256sum, err = m.GetSourceSha256FromGitHub(ctx, owner, repo, pkg.Version)
		if err != nil {
			fmt.Printf("⚠️  Could not calculate sha256sum from GitHub: %v\n", err)
		}
	} else {
		fmt.Printf("ℹ️  Could not extract source filename from spec, skipping signature update\n")
	}

	// Update signatures.json if we got a valid sha256sum
	if sha256sum != "" {
		if err := m.UpdateSignaturesJson(ctx, pkg.Name, pkg.Version, sha256sum); err != nil {
			fmt.Printf("⚠️  Could not update signatures.json: %v\n", err)
		}
	} // Commit the updated spec file
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
	// Check if local repository exists, clone if not
	if _, err := os.Stat(m.localRepoPath); os.IsNotExist(err) {
		fmt.Printf("📂 Local repository not found at %s\n", m.localRepoPath)
		fmt.Printf("🔄 Cloning Azure Linux repository...\n")

		cloneCmd := fmt.Sprintf("git clone https://github.com/microsoft/azurelinux.git %s", m.localRepoPath)
		if err := m.runCommand(cloneCmd); err != nil {
			return fmt.Errorf("failed to clone repository: %w", err)
		}

		fmt.Printf("✅ Repository cloned successfully\n\n")
	}

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
		fmt.Println()
		fmt.Println("🚀 Pushing branch to remote repository...")
		pushCmd := fmt.Sprintf("cd %s && git push origin %s", m.localRepoPath, branchName)
		if err := m.runCommand(pushCmd); err != nil {
			fmt.Printf("⚠️  Failed to push branch: %v\n", err)
			fmt.Println("   You can manually push with: git push origin", branchName)
		} else {
			fmt.Printf("✅ Branch pushed successfully\n")
		}
		fmt.Println()

		fmt.Println("💡 Next steps:")
		fmt.Println("   1. Review the changes: cd", m.localRepoPath, "&& git diff origin/3.0-dev")
		fmt.Println("   2. Create PR at: https://github.com/microsoft/azurelinux/compare/3.0-dev...liunan-ms:" + branchName)
	}

	if failureCount > 0 {
		return fmt.Errorf("some packages failed to upgrade")
	}

	return nil
}
