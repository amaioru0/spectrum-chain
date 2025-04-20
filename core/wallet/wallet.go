// Wallet and CLI implementation for Spectrum Chain
package wallet

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/amaioru0/spectrum-chain/core/blockchain"
	"github.com/amaioru0/spectrum-chain/core/network"
	"github.com/btcsuite/btcd/btcec"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
)

// Account represents a user account in the wallet
type Account struct {
	Address    string `json:"address"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Balance    uint64 `json:"balance"`
}

// Wallet manages user accounts and transactions
type Wallet struct {
	Accounts      map[string]Account `json:"accounts"`
	ActiveAccount string             `json:"active_account"`
	WalletPath    string             `json:"-"`
	blockchain    *blockchain.Blockchain
	network       *network.NetworkManager
}

// NewWallet creates a new wallet or loads an existing one
func NewWallet(walletPath string) (*Wallet, error) {
	wallet := &Wallet{
		Accounts:   make(map[string]Account),
		WalletPath: walletPath,
	}

	// Load existing wallet if available
	if _, err := os.Stat(walletPath); err == nil {
		data, err := os.ReadFile(walletPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read wallet file: %w", err)
		}

		if err := json.Unmarshal(data, wallet); err != nil {
			return nil, fmt.Errorf("failed to unmarshal wallet data: %w", err)
		}
	} else {
		// Create a new account if wallet doesn't exist
		if err := wallet.CreateAccount("default"); err != nil {
			return nil, fmt.Errorf("failed to create default account: %w", err)
		}

		wallet.ActiveAccount = "default"

		// Save the new wallet
		if err := wallet.Save(); err != nil {
			return nil, fmt.Errorf("failed to save new wallet: %w", err)
		}
	}

	return wallet, nil
}

// SetBlockchain sets the blockchain instance
func (w *Wallet) SetBlockchain(blockchain *blockchain.Blockchain) {
	w.blockchain = blockchain
}

// SetNetwork sets the network manager instance
func (w *Wallet) SetNetwork(network *network.NetworkManager) {
	w.network = network
}

// CreateAccount creates a new account in the wallet
func (w *Wallet) CreateAccount(name string) error {
	// Check if account already exists
	if _, exists := w.Accounts[name]; exists {
		return fmt.Errorf("account '%s' already exists", name)
	}

	// Generate a new private key
	privateKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get public key
	publicKey := privateKey.PublicKey

	// Generate address from public key
	address := crypto.PubkeyToAddress(publicKey).Hex()

	// Convert keys to hex strings
	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hex.EncodeToString(privateKeyBytes)

	publicKeyBytes := crypto.FromECDSAPub(&publicKey)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Create account
	account := Account{
		Address:    address,
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Balance:    0,
	}

	// Add account to wallet
	w.Accounts[name] = account

	// Save wallet
	return w.Save()
}

// GetActiveAccount returns the active account
func (w *Wallet) GetActiveAccount() (Account, error) {
	if w.ActiveAccount == "" {
		return Account{}, errors.New("no active account")
	}

	account, exists := w.Accounts[w.ActiveAccount]
	if !exists {
		return Account{}, fmt.Errorf("active account '%s' not found", w.ActiveAccount)
	}

	return account, nil
}

// SetActiveAccount sets the active account
func (w *Wallet) SetActiveAccount(name string) error {
	if _, exists := w.Accounts[name]; !exists {
		return fmt.Errorf("account '%s' not found", name)
	}

	w.ActiveAccount = name
	return w.Save()
}

// GetBalance returns the balance of an account
func (w *Wallet) GetBalance(accountName string) (uint64, error) {
	if w.blockchain == nil {
		return 0, errors.New("blockchain not set")
	}

	account, exists := w.Accounts[accountName]
	if !exists {
		return 0, fmt.Errorf("account '%s' not found", accountName)
	}

	// In a real implementation, we would query the blockchain for UTXOs
	// For simplicity, we'll just return the cached balance
	return account.Balance, nil
}

// UpdateBalances updates account balances from blockchain
func (w *Wallet) UpdateBalances() error {
	if w.blockchain == nil {
		return errors.New("blockchain not set")
	}

	// In a real implementation, we would scan the blockchain for UTXOs
	// For simplicity, this is just a placeholder

	// Save updated balances
	return w.Save()
}

// CreateTransaction creates a new transaction
func (w *Wallet) CreateTransaction(from string, to string, amount uint64) (*blockchain.Transaction, error) {
	if w.blockchain == nil {
		return nil, errors.New("blockchain not set")
	}

	fromAccount, exists := w.Accounts[from]
	if !exists {
		return nil, fmt.Errorf("sender account '%s' not found", from)
	}

	// Check balance
	if fromAccount.Balance < amount {
		return nil, fmt.Errorf("insufficient balance: have %d, need %d", fromAccount.Balance, amount)
	}

	// Create inputs
	// In a real implementation, we would select appropriate UTXOs
	var inputs []blockchain.TxInput

	// Create outputs
	var outputs []blockchain.TxOutput

	// Output for recipient
	recipientOutput := blockchain.TxOutput{
		Value:      amount,
		PubKeyHash: []byte(to), // In a real implementation, this would be properly hashed
	}
	outputs = append(outputs, recipientOutput)

	// Change output
	if fromAccount.Balance > amount {
		changeOutput := blockchain.TxOutput{
			Value:      fromAccount.Balance - amount,
			PubKeyHash: []byte(fromAccount.Address), // In a real implementation, this would be properly hashed
		}
		outputs = append(outputs, changeOutput)
	}

	// Create transaction
	tx := &blockchain.Transaction{
		Inputs:    inputs,
		Outputs:   outputs,
		Timestamp: time.Now().Unix(),
		PublicKey: []byte(fromAccount.PublicKey),
	}

	// Calculate transaction ID
	tx.ID = tx.Hash()

	// Sign transaction
	privateKeyBytes, err := hex.DecodeString(fromAccount.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	txData, err := json.Marshal(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transaction: %w", err)
	}

	hash := sha256.Sum256(txData)

	signature, err := crypto.Sign(hash[:], privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	tx.Signature = signature

	return tx, nil
}

// SendTransaction creates and broadcasts a transaction
func (w *Wallet) SendTransaction(from string, to string, amount uint64) error {
	if w.blockchain == nil || w.network == nil {
		return errors.New("blockchain or network not set")
	}

	// Create transaction
	tx, err := w.CreateTransaction(from, to, amount)
	if err != nil {
		return err
	}

	// Add to blockchain
	if err := w.blockchain.AddTransaction(tx); err != nil {
		return fmt.Errorf("failed to add transaction to blockchain: %w", err)
	}

	// Broadcast transaction
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	msg := network.Message{
		Type:      "transaction",
		Data:      txData,
		Timestamp: time.Now().Unix(),
	}

	if err := w.network.BroadcastMessage(&msg); err != nil {
		return fmt.Errorf("failed to broadcast transaction: %w", err)
	}

	// Update account balances
	fromAccount := w.Accounts[from]
	fromAccount.Balance -= amount
	w.Accounts[from] = fromAccount

	// Save wallet
	return w.Save()
}

// ImportAccount imports an account from a private key
func (w *Wallet) ImportAccount(name string, privateKeyHex string) error {
	// Check if account already exists
	if _, exists := w.Accounts[name]; exists {
		return fmt.Errorf("account '%s' already exists", name)
	}

	// Parse private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	// Get public key
	publicKey := privateKey.PublicKey

	// Generate address
	address := crypto.PubkeyToAddress(publicKey).Hex()

	// Convert public key to hex
	publicKeyBytes := crypto.FromECDSAPub(&publicKey)
	publicKeyHex := hex.EncodeToString(publicKeyBytes)

	// Create account
	account := Account{
		Address:    address,
		PrivateKey: privateKeyHex,
		PublicKey:  publicKeyHex,
		Balance:    0, // Will be updated when blockchain is set
	}

	// Add account to wallet
	w.Accounts[name] = account

	// Save wallet
	return w.Save()
}

// ExportAccount exports an account's private key
func (w *Wallet) ExportAccount(name string) (string, error) {
	account, exists := w.Accounts[name]
	if !exists {
		return "", fmt.Errorf("account '%s' not found", name)
	}

	return account.PrivateKey, nil
}

// ListAccounts returns a list of all accounts
func (w *Wallet) ListAccounts() []Account {
	accounts := make([]Account, 0, len(w.Accounts))
	for _, account := range w.Accounts {
		accounts = append(accounts, account)
	}
	return accounts
}

// Save saves the wallet to disk
func (w *Wallet) Save() error {
	data, err := json.MarshalIndent(w, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal wallet data: %w", err)
	}

	if err := os.WriteFile(w.WalletPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write wallet file: %w", err)
	}

	return nil
}

// CLI represents the command-line interface
type CLI struct {
	wallet  *Wallet
	rootCmd *cobra.Command
	reader  *bufio.Reader
}

// NewCLI creates a new CLI instance
func NewCLI(wallet *Wallet) *CLI {
	cli := &CLI{
		wallet: wallet,
		reader: bufio.NewReader(os.Stdin),
	}

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "spectrum-wallet",
		Short: "Spectrum Chain wallet CLI",
		Long:  "Command-line interface for Spectrum Chain wallet",
	}

	// Add commands
	rootCmd.AddCommand(cli.createAccountCmd())
	rootCmd.AddCommand(cli.listAccountsCmd())
	rootCmd.AddCommand(cli.setActiveAccountCmd())
	rootCmd.AddCommand(cli.getBalanceCmd())
	rootCmd.AddCommand(cli.sendCmd())
	rootCmd.AddCommand(cli.importAccountCmd())
	rootCmd.AddCommand(cli.exportAccountCmd())
	rootCmd.AddCommand(cli.interactiveCmd())

	cli.rootCmd = rootCmd

	return cli
}

// Run executes the CLI
func (cli *CLI) Run() error {
	return cli.rootCmd.Execute()
}

// createAccountCmd creates a new account
func (cli *CLI) createAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if err := cli.wallet.CreateAccount(name); err != nil {
				return err
			}

			fmt.Printf("Account '%s' created successfully\n", name)
			account := cli.wallet.Accounts[name]
			fmt.Printf("Address: %s\n", account.Address)

			return nil
		},
	}

	return cmd
}

// listAccountsCmd lists all accounts
func (cli *CLI) listAccountsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all accounts",
		RunE: func(cmd *cobra.Command, args []string) error {
			accounts := cli.wallet.ListAccounts()
			activeAccount := cli.wallet.ActiveAccount

			if len(accounts) == 0 {
				fmt.Println("No accounts found")
				return nil
			}

			fmt.Println("Accounts:")
			for _, account := range accounts {
				if activeAccount == account.Address {
					fmt.Printf("* %s: %s (Balance: %d SPECTRUM)\n", activeAccount, account.Address, account.Balance)
				} else {
					fmt.Printf("  %s: %s (Balance: %d SPECTRUM)\n", account.Address, account.Balance)
				}
			}

			return nil
		},
	}

	return cmd
}

// setActiveAccountCmd sets the active account
func (cli *CLI) setActiveAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use [name]",
		Short: "Set the active account",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if err := cli.wallet.SetActiveAccount(name); err != nil {
				return err
			}

			fmt.Printf("Active account set to '%s'\n", name)
			return nil
		},
	}

	return cmd
}

// getBalanceCmd gets the balance of an account
func (cli *CLI) getBalanceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "balance [name]",
		Short: "Get account balance",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var name string

			if len(args) == 0 {
				// Use active account
				activeAccount, err := cli.wallet.GetActiveAccount()
				if err != nil {
					return err
				}
				name = activeAccount.Address
			} else {
				name = args[0]
			}

			balance, err := cli.wallet.GetBalance(name)
			if err != nil {
				return err
			}

			fmt.Printf("Balance of '%s': %d SPECTRUM\n", name, balance)
			return nil
		},
	}

	return cmd
}

// sendCmd sends tokens to another address
func (cli *CLI) sendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "send [from] [to] [amount]",
		Short: "Send tokens to another address",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			from := args[0]
			to := args[1]

			amount, err := strconv.ParseUint(args[2], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid amount: %w", err)
			}

			if err := cli.wallet.SendTransaction(from, to, amount); err != nil {
				return err
			}

			fmt.Printf("Sent %d SPECTRUM from '%s' to '%s'\n", amount, from, to)
			return nil
		},
	}

	return cmd
}

// importAccountCmd imports an account from a private key
func (cli *CLI) importAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import [name] [private_key]",
		Short: "Import an account from a private key",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			privateKey := args[1]

			if err := cli.wallet.ImportAccount(name, privateKey); err != nil {
				return err
			}

			fmt.Printf("Account '%s' imported successfully\n", name)
			account := cli.wallet.Accounts[name]
			fmt.Printf("Address: %s\n", account.Address)

			return nil
		},
	}

	return cmd
}

// exportAccountCmd exports an account's private key
func (cli *CLI) exportAccountCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export [name]",
		Short: "Export an account's private key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			privateKey, err := cli.wallet.ExportAccount(name)
			if err != nil {
				return err
			}

			fmt.Printf("Private key for '%s': %s\n", name, privateKey)
			fmt.Println("KEEP THIS PRIVATE KEY SAFE! Anyone with this key can access your funds.")

			return nil
		},
	}

	return cmd
}

// interactiveCmd starts an interactive shell
func (cli *CLI) interactiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shell",
		Short: "Start interactive shell",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cli.startInteractiveShell()
		},
	}

	return cmd
}

// startInteractiveShell starts an interactive shell
func (cli *CLI) startInteractiveShell() error {
	fmt.Println("Spectrum Chain Wallet Interactive Shell")
	fmt.Println("Type 'help' for available commands")

	for {
		// Print prompt
		activeAccount, err := cli.wallet.GetActiveAccount()
		if err == nil {
			fmt.Printf("[%s] > ", activeAccount.Address[:8])
		} else {
			fmt.Print("> ")
		}

		// Read command
		line, err := cli.reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		// Process command
		if err := cli.processCommand(strings.TrimSpace(line)); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}
}

// processCommand processes an interactive command
func (cli *CLI) processCommand(command string) error {
	if command == "" {
		return nil
	}

	parts := strings.Split(command, " ")
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "help":
		cli.printHelp()
	case "exit", "quit":
		os.Exit(0)
	case "create":
		if len(args) != 1 {
			return errors.New("usage: create [name]")
		}
		return cli.createAccount(args[0])
	case "list":
		return cli.listAccounts()
	case "use":
		if len(args) != 1 {
			return errors.New("usage: use [name]")
		}
		return cli.setActiveAccount(args[0])
	case "balance":
		if len(args) > 1 {
			return errors.New("usage: balance [name]")
		}
		var name string
		if len(args) == 0 {
			account, err := cli.wallet.GetActiveAccount()
			if err != nil {
				return err
			}
			name = account.Address
		} else {
			name = args[0]
		}
		return cli.getBalance(name)
	case "send":
		if len(args) != 3 {
			return errors.New("usage: send [from] [to] [amount]")
		}
		amount, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid amount: %w", err)
		}
		return cli.sendTokens(args[0], args[1], amount)
	case "import":
		if len(args) != 2 {
			return errors.New("usage: import [name] [private_key]")
		}
		return cli.importAccount(args[0], args[1])
	case "export":
		if len(args) != 1 {
			return errors.New("usage: export [name]")
		}
		return cli.exportAccount(args[0])
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}

	return nil
}

// printHelp prints help information
func (cli *CLI) printHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  help                  - Show this help message")
	fmt.Println("  exit, quit            - Exit the shell")
	fmt.Println("  create [name]         - Create a new account")
	fmt.Println("  list                  - List all accounts")
	fmt.Println("  use [name]            - Set the active account")
	fmt.Println("  balance [name]        - Get account balance")
	fmt.Println("  send [from] [to] [amount] - Send tokens")
	fmt.Println("  import [name] [private_key] - Import an account")
	fmt.Println("  export [name]         - Export account private key")
}

// Helper functions for interactive mode
func (cli *CLI) createAccount(name string) error {
	if err := cli.wallet.CreateAccount(name); err != nil {
		return err
	}

	fmt.Printf("Account '%s' created successfully\n", name)
	account := cli.wallet.Accounts[name]
	fmt.Printf("Address: %s\n", account.Address)

	return nil
}

func (cli *CLI) listAccounts() error {
	accounts := cli.wallet.ListAccounts()
	activeAccount := cli.wallet.ActiveAccount

	if len(accounts) == 0 {
		fmt.Println("No accounts found")
		return nil
	}

	fmt.Println("Accounts:")
	for _, account := range accounts {
		if activeAccount == account.Address {
			fmt.Printf("* %s: %s (Balance: %d SPECTRUM)\n", activeAccount, account.Address, account.Balance)
		} else {
			fmt.Printf("  %s: %s (Balance: %d SPECTRUM)\n", account.Address, account.Balance)
		}
	}

	return nil
}

func (cli *CLI) setActiveAccount(name string) error {
	if err := cli.wallet.SetActiveAccount(name); err != nil {
		return err
	}

	fmt.Printf("Active account set to '%s'\n", name)
	return nil
}

func (cli *CLI) getBalance(name string) error {
	balance, err := cli.wallet.GetBalance(name)
	if err != nil {
		return err
	}

	fmt.Printf("Balance of '%s': %d SPECTRUM\n", name, balance)
	return nil
}

func (cli *CLI) sendTokens(from, to string, amount uint64) error {
	if err := cli.wallet.SendTransaction(from, to, amount); err != nil {
		return err
	}

	fmt.Printf("Sent %d SPECTRUM from '%s' to '%s'\n", amount, from, to)
	return nil
}

func (cli *CLI) importAccount(name, privateKey string) error {
	if err := cli.wallet.ImportAccount(name, privateKey); err != nil {
		return err
	}

	fmt.Printf("Account '%s' imported successfully\n", name)
	account := cli.wallet.Accounts[name]
	fmt.Printf("Address: %s\n", account.Address)

	return nil
}

func (cli *CLI) exportAccount(name string) error {
	privateKey, err := cli.wallet.ExportAccount(name)
	if err != nil {
		return err
	}

	fmt.Printf("Private key for '%s': %s\n", name, privateKey)
	fmt.Println("KEEP THIS PRIVATE KEY SAFE! Anyone with this key can access your funds.")

	return nil
}
