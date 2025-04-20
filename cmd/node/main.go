// Main entry point for Spectrum Chain node
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/amaioru0/spectrum-chain/core/blockchain"
	"github.com/amaioru0/spectrum-chain/core/consensus"
	"github.com/amaioru0/spectrum-chain/core/network"
	"github.com/amaioru0/spectrum-chain/core/node"
	"github.com/amaioru0/spectrum-chain/core/vm"
	"github.com/amaioru0/spectrum-chain/core/wallet"
)

// Version information
const (
	Version = "1.0.0"
)

func main() {
	log.SetPrefix("[Spectrum] ")
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// Parse command line flags
	dataDir := flag.String("datadir", "./data", "Directory for blockchain data")
	listenAddr := flag.String("addr", ":9000", "Listen address for P2P connections")
	apiAddr := flag.String("api", ":8000", "Address for HTTP API")
	bootstrapNodes := flag.String("bootstrap", "", "Comma separated list of bootstrap nodes")
	isBootstrap := flag.Bool("is-bootstrap", false, "Run as a bootstrap node")
	minerEnabled := flag.Bool("mine", false, "Enable mining")
	vmEnabled := flag.Bool("vm", false, "Enable global VM")
	sshEnabled := flag.Bool("ssh", false, "Enable SSH to global VM")
	sshPort := flag.Int("ssh-port", 2222, "Port for SSH connections to global VM")
	walletPath := flag.String("wallet", "", "Path to wallet file (default: datadir/wallet.dat)")
	logLevel := flag.String("log", "info", "Log level (debug, info, warn, error)")
	showVersion := flag.Bool("version", false, "Show version information")

	flag.Parse()

	// Show version and exit if requested
	if *showVersion {
		fmt.Printf("Spectrum Chain Node v%s\n", Version)
		os.Exit(0)
	}

	// Set log level
	setupLogging(*logLevel)

	// Set wallet path if not specified
	if *walletPath == "" {
		*walletPath = filepath.Join(*dataDir, "wallet.dat")
	}

	// Create data directory if it doesn't exist
	if err := os.MkdirAll(*dataDir, 0755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	// Parse bootstrap nodes
	var bootstrapAddrs []string
	if *bootstrapNodes != "" {
		bootstrapAddrs = strings.Split(*bootstrapNodes, ",")
	}

	// Initialize components
	log.Println("Initializing Spectrum Chain node...")

	// Initialize wallet
	walletInstance, err := wallet.NewWallet(*walletPath)
	if err != nil {
		log.Fatalf("Failed to initialize wallet: %v", err)
	}

	// Initialize blockchain
	chain, err := blockchain.NewBlockchain(filepath.Join(*dataDir, "blockchain"))
	if err != nil {
		log.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Initialize consensus
	consensusEngine := consensus.NewPoSConsensus(chain, walletInstance)

	// Initialize P2P network
	networkManager, err := network.NewNetworkManager(*listenAddr, bootstrapAddrs)
	if err != nil {
		log.Fatalf("Failed to initialize network: %v", err)
	}

	// Initialize VM if enabled
	var vmManager *vm.Manager
	if *vmEnabled {
		vmManager, err = vm.NewManager(filepath.Join(*dataDir, "vm"), networkManager)
		if err != nil {
			log.Fatalf("Failed to initialize VM manager: %v", err)
		}
	}

	// Create node
	nodeInstance := node.NewNode(
		chain,
		consensusEngine,
		networkManager,
		walletInstance,
		vmManager,
		&node.NodeConfig{
			DataDir:      *dataDir,
			APIAddr:      *apiAddr,
			MinerEnabled: *minerEnabled,
			SSHEnabled:   *sshEnabled,
			SSHPort:      *sshPort,
		},
	)

	// Start the node
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := nodeInstance.Start(ctx); err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}

	log.Printf("Spectrum Chain node v%s running", Version)
	log.Printf("P2P networking address: %s", *listenAddr)
	log.Printf("API server address: %s", *apiAddr)
	if *vmEnabled {
		log.Printf("Global VM enabled")
		if *sshEnabled {
			log.Printf("SSH access enabled on port %d", *sshPort)
		}
	}
	if *minerEnabled {
		log.Printf("Mining enabled")
	}

	// Handle graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := nodeInstance.Stop(shutdownCtx); err != nil {
		log.Fatalf("Error during shutdown: %v", err)
	}

	log.Println("Node stopped gracefully")
}

// setupLogging configures logging based on level
func setupLogging(level string) {
	switch strings.ToLower(level) {
	case "debug":
		log.SetFlags(log.LstdFlags | log.Lshortfile | log.Lmicroseconds)
		// In a real implementation, we would set up more sophisticated logging
	case "info":
		log.SetFlags(log.LstdFlags)
	case "warn":
		// Configure for warnings
	case "error":
		// Configure for errors only
	default:
		log.SetFlags(log.LstdFlags)
	}
}
