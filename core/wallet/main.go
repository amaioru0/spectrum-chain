// Main entry point for Spectrum Chain wallet CLI
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spectrum-chain/core/wallet"
)

// Version information
const (
	Version = "1.0.0"
)

func main() {
	log.SetPrefix("[Spectrum Wallet] ")
	log.SetFlags(log.LstdFlags)

	// Parse command line flags
	walletPath := flag.String("wallet", "./wallet.dat", "Path to wallet file")
	showVersion := flag.Bool("version", false, "Show version information")

	// Custom usage function
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Spectrum Chain Wallet CLI v%s\n\n", Version)
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags] [command]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nCommands:\n")
		fmt.Fprintf(os.Stderr, "  shell                   Start interactive shell\n")
		fmt.Fprintf(os.Stderr, "  create <name>           Create a new account\n")
		fmt.Fprintf(os.Stderr, "  list                    List all accounts\n")
		fmt.Fprintf(os.Stderr, "  use <name>              Set active account\n")
		fmt.Fprintf(os.Stderr, "  balance [name]          Get account balance\n")
		fmt.Fprintf(os.Stderr, "  send <from> <to> <amount> Send tokens\n")
		fmt.Fprintf(os.Stderr, "  import <name> <key>     Import account from private key\n")
		fmt.Fprintf(os.Stderr, "  export <name>           Export account private key\n")
	}

	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("Spectrum Chain Wallet v%s\n", Version)
		os.Exit(0)
	}

	// Create directory for wallet if it doesn't exist
	walletDir := filepath.Dir(*walletPath)
	if err := os.MkdirAll(walletDir, 0755); err != nil {
		log.Fatalf("Failed to create wallet directory: %v", err)
	}

	// Initialize wallet
	walletInstance, err := wallet.NewWallet(*walletPath)
	if err != nil {
		log.Fatalf("Failed to initialize wallet: %v", err)
	}

	// Create CLI
	cli := wallet.NewCLI(walletInstance)

	// Run CLI
	if err := cli.Run(); err != nil {
		log.Fatalf("Error: %v", err)
	}
}
