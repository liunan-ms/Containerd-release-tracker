package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/liunan-ms/containerd-release-tracker/pkg/upgrade"
)

func main() {
	analysisFile := flag.String("analysis", "containerd_release_analysis.json", "Path to release analysis JSON file")
	aShort := flag.String("a", "", "Short for --analysis")
	tokenFlag := flag.String("token", "", "GitHub token")
	tShort := flag.String("t", "", "Short for --token")
	repoPath := flag.String("repo", "/workspace/azurelinux", "Path to local azurelinux repository")
	rShort := flag.String("r", "", "Short for --repo")

	flag.Parse()

	if *aShort != "" {
		analysisFile = aShort
	}
	if *tShort != "" {
		tokenFlag = tShort
	}
	if *rShort != "" {
		repoPath = rShort
	}

	token := *tokenFlag
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	if token == "" {
		fmt.Println("❌ Error: GITHUB_TOKEN required")
		fmt.Println("\nSet it: export GITHUB_TOKEN='your_token'")
		os.Exit(1)
	}

	manager := upgrade.NewUpgradeManager(token, *repoPath)
	ctx := context.Background()

	if err := manager.UpgradeAllPackages(ctx, *analysisFile); err != nil {
		fmt.Printf("\n❌ Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ Upgrade process complete!")
}
