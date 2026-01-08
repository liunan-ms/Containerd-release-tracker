package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/liunan-ms/containerd-release-tracker/pkg/parser"
)

func main() {
	version := flag.String("version", "", "Specific containerd version")
	vShort := flag.String("v", "", "Short for --version")
	output := flag.String("output", "containerd_release_analysis.json", "Output file")
	oShort := flag.String("o", "", "Short for --output")
	tokenFlag := flag.String("token", "", "GitHub token")
	tShort := flag.String("t", "", "Short for --token")

	flag.Parse()

	if *vShort != "" {
		version = vShort
	}
	if *oShort != "" {
		output = oShort
	}
	if *tShort != "" {
		tokenFlag = tShort
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

	p := parser.NewParser(token)
	ctx := context.Background()

	result, err := p.ParseRelease(ctx, *version)
	if err != nil {
		fmt.Printf("\n❌ Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n" + "================================================================================")
	fmt.Printf("📦 Release: %s\n", result.Version)
	fmt.Printf("📅 Published: %s\n", result.PublishedAt)
	fmt.Printf("🔗 URL: %s\n\n", result.URL)

	if err := p.SaveToFile(result, *output); err != nil {
		fmt.Printf("❌ Save failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✅ Complete!")
}
