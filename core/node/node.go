// Node implementation for Spectrum Chain
package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/amaioru0/spectrum-chain/core/blockchain"
	"github.com/amaioru0/spectrum-chain/core/consensus"
	"github.com/amaioru0/spectrum-chain/core/network"
	"github.com/amaioru0/spectrum-chain/core/vm"
	"github.com/amaioru0/spectrum-chain/core/wallet"
	"github.com/gorilla/mux"
)

// NodeConfig holds configuration for a node
type NodeConfig struct {
	DataDir      string
	APIAddr      string
	MinerEnabled bool
	SSHEnabled   bool
	SSHPort      int
}

// Node represents a Spectrum Chain node
type Node struct {
	blockchain     *blockchain.Blockchain
	consensus      *consensus.PoSConsensus
	network        *network.NetworkManager
	wallet         *wallet.Wallet
	vmManager      *vm.Manager
	config         *NodeConfig
	apiServer      *http.Server
	pendingTxs     map[string]*blockchain.Transaction
	pendingTxsLock sync.RWMutex
	mempoolSize    int
	isRunning      bool
	stopChan       chan struct{}
}

// NewNode creates a new node
func NewNode(
	blockchain *blockchain.Blockchain,
	consensus *consensus.PoSConsensus,
	network *network.NetworkManager,
	wallet *wallet.Wallet,
	vmManager *vm.Manager,
	config *NodeConfig,
) *Node {
	return &Node{
		blockchain:  blockchain,
		consensus:   consensus,
		network:     network,
		wallet:      wallet,
		vmManager:   vmManager,
		config:      config,
		pendingTxs:  make(map[string]*blockchain.Transaction),
		mempoolSize: 10000, // Maximum number of transactions in mempool
		stopChan:    make(chan struct{}),
	}
}

// Start starts the node
func (n *Node) Start(ctx context.Context) error {
	if n.isRunning {
		return fmt.Errorf("node is already running")
	}

	log.Println("Starting Spectrum Chain node...")

	// Set blockchain on wallet
	n.wallet.SetBlockchain(n.blockchain)

	// Set network on wallet
	n.wallet.SetNetwork(n.network)

	// Start network
	if err := n.network.Start(); err != nil {
		return fmt.Errorf("failed to start network: %w", err)
	}

	// Register message handlers
	n.registerMessageHandlers()

	// Start consensus engine
	if err := n.consensus.Start(); err != nil {
		return fmt.Errorf("failed to start consensus engine: %w", err)
	}

	// Start VM manager if enabled
	if n.vmManager != nil {
		if err := n.vmManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start VM manager: %w", err)
		}
	}

	// Start mining if enabled
	if n.config.MinerEnabled {
		if err := n.consensus.StartMining(); err != nil {
			log.Printf("Warning: Failed to start mining: %v", err)
		}
	}

	// Start API server
	if err := n.startAPIServer(); err != nil {
		return fmt.Errorf("failed to start API server: %w", err)
	}

	// Start background tasks
	go n.runBlockCreationLoop(ctx)
	go n.runMemPoolCleanupLoop(ctx)

	n.isRunning = true
	log.Println("Spectrum Chain node started successfully")

	return nil
}

// Stop stops the node
func (n *Node) Stop(ctx context.Context) error {
	if !n.isRunning {
		return nil
	}

	log.Println("Stopping Spectrum Chain node...")

	// Signal all background tasks to stop
	close(n.stopChan)

	// Stop mining if running
	if n.consensus.IsMining() {
		if err := n.consensus.StopMining(); err != nil {
			log.Printf("Warning: Failed to stop mining: %v", err)
		}
	}

	// Stop API server
	if n.apiServer != nil {
		if err := n.apiServer.Shutdown(ctx); err != nil {
			log.Printf("Warning: Failed to stop API server gracefully: %v", err)
		}
	}

	// Stop VM manager if enabled
	if n.vmManager != nil {
		if err := n.vmManager.Stop(ctx); err != nil {
			log.Printf("Warning: Failed to stop VM manager: %v", err)
		}
	}

	// Stop consensus engine
	if err := n.consensus.Stop(); err != nil {
		log.Printf("Warning: Failed to stop consensus engine: %v", err)
	}

	// Stop network
	if err := n.network.Stop(); err != nil {
		log.Printf("Warning: Failed to stop network: %v", err)
	}

	// Close blockchain
	if err := n.blockchain.Close(); err != nil {
		log.Printf("Warning: Failed to close blockchain: %v", err)
	}

	n.isRunning = false
	log.Println("Spectrum Chain node stopped successfully")

	return nil
}

// registerMessageHandlers registers message handlers for network messages
func (n *Node) registerMessageHandlers() {
	// Register handler for new transactions
	n.network.RegisterMessageHandler("transaction", n.handleTransactionMessage)

	// Register handler for new blocks
	n.network.RegisterMessageHandler("block", n.handleBlockMessage)

	// Register handler for block requests
	n.network.RegisterMessageHandler("get_block", n.handleGetBlockMessage)

	// Register handler for transaction requests
	n.network.RegisterMessageHandler("get_transaction", n.handleGetTransactionMessage)
}

// handleTransactionMessage handles incoming transaction messages
func (n *Node) handleTransactionMessage(msg *network.Message) error {
	// Parse transaction
	var tx blockchain.Transaction
	if err := json.Unmarshal(msg.Data, &tx); err != nil {
		return fmt.Errorf("failed to unmarshal transaction: %w", err)
	}

	// Verify and add transaction to mempool
	if err := n.addTransaction(&tx); err != nil {
		return fmt.Errorf("failed to add transaction: %w", err)
	}

	return nil
}

// handleBlockMessage handles incoming block messages
func (n *Node) handleBlockMessage(msg *network.Message) error {
	// Parse block
	var block blockchain.Block
	if err := json.Unmarshal(msg.Data, &block); err != nil {
		return fmt.Errorf("failed to unmarshal block: %w", err)
	}

	// Verify block
	if err := n.consensus.VerifyBlock(&block); err != nil {
		return fmt.Errorf("invalid block: %w", err)
	}

	// Add block to blockchain
	// In a real implementation, this would handle chain reorganization
	// and would validate the entire chain

	// For simplicity, we'll just log the new block
	log.Printf("Received new block at height %d with %d transactions",
		block.Header.Height, len(block.Transactions))

	return nil
}

// handleGetBlockMessage handles requests for specific blocks
func (n *Node) handleGetBlockMessage(msg *network.Message) error {
	// Parse request
	var request struct {
		Height uint64 `json:"height"`
		Hash   []byte `json:"hash"`
	}

	if err := json.Unmarshal(msg.Data, &request); err != nil {
		return fmt.Errorf("failed to unmarshal block request: %w", err)
	}

	var block *blockchain.Block
	var err error

	// Get block by height or hash
	if request.Height > 0 {
		block, err = n.blockchain.GetBlockByHeight(request.Height)
	} else if len(request.Hash) > 0 {
		block, err = n.blockchain.GetBlockByHash(request.Hash)
	} else {
		return fmt.Errorf("missing block height or hash in request")
	}

	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	// Serialize block
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	// Create response message
	response := &network.Message{
		Type:      "block_response",
		Data:      blockData,
		Timestamp: time.Now().Unix(),
		Recipient: msg.Sender,
	}

	// Send response
	return n.network.SendMessage(response)
}

// handleGetTransactionMessage handles requests for specific transactions
func (n *Node) handleGetTransactionMessage(msg *network.Message) error {
	// Parse request
	var request struct {
		TxID []byte `json:"txid"`
	}

	if err := json.Unmarshal(msg.Data, &request); err != nil {
		return fmt.Errorf("failed to unmarshal transaction request: %w", err)
	}

	if len(request.TxID) == 0 {
		return fmt.Errorf("missing transaction ID in request")
	}

	// Check mempool first
	n.pendingTxsLock.RLock()
	txID := fmt.Sprintf("%x", request.TxID)
	tx, exists := n.pendingTxs[txID]
	n.pendingTxsLock.RUnlock()

	if !exists {
		// If not in mempool, check blockchain
		// In a real implementation, this would search for the transaction in the blockchain
		return fmt.Errorf("transaction not found")
	}

	// Serialize transaction
	txData, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("failed to marshal transaction: %w", err)
	}

	// Create response message
	response := &network.Message{
		Type:      "transaction_response",
		Data:      txData,
		Timestamp: time.Now().Unix(),
		Recipient: msg.Sender,
	}

	// Send response
	return n.network.SendMessage(response)
}

// addTransaction adds a transaction to the mempool
func (n *Node) addTransaction(tx *blockchain.Transaction) error {
	// Verify transaction
	if err := n.blockchain.VerifyTransaction(tx); err != nil {
		return fmt.Errorf("transaction verification failed: %w", err)
	}

	// Add to mempool
	n.pendingTxsLock.Lock()
	defer n.pendingTxsLock.Unlock()

	// Check if mempool is full
	if len(n.pendingTxs) >= n.mempoolSize {
		return fmt.Errorf("mempool is full")
	}

	txID := fmt.Sprintf("%x", tx.ID)
	n.pendingTxs[txID] = tx

	return nil
}

// getPendingTransactions gets transactions from the mempool
func (n *Node) getPendingTransactions(limit int) []blockchain.Transaction {
	n.pendingTxsLock.RLock()
	defer n.pendingTxsLock.RUnlock()

	transactions := make([]blockchain.Transaction, 0, limit)
	count := 0

	for _, tx := range n.pendingTxs {
		if count >= limit {
			break
		}

		transactions = append(transactions, *tx)
		count++
	}

	return transactions
}

// removePendingTransaction removes a transaction from the mempool
func (n *Node) removePendingTransaction(txID string) {
	n.pendingTxsLock.Lock()
	defer n.pendingTxsLock.Unlock()

	delete(n.pendingTxs, txID)
}

// runBlockCreationLoop periodically creates new blocks
func (n *Node) runBlockCreationLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-n.stopChan:
			return
		case <-ticker.C:
			// Skip if not mining
			if !n.consensus.IsMining() {
				continue
			}

			// Get pending transactions
			txs := n.getPendingTransactions(1000)

			if len(txs) == 0 {
				continue
			}

			// Create new block
			block, err := n.blockchain.AddBlock(txs)
			if err != nil {
				log.Printf("Failed to create new block: %v", err)
				continue
			}

			log.Printf("Created new block at height %d with %d transactions",
				block.Header.Height, len(block.Transactions))

			// Remove transactions from mempool
			for _, tx := range txs {
				txID := fmt.Sprintf("%x", tx.ID)
				n.removePendingTransaction(txID)
			}

			// Broadcast block
			blockData, err := json.Marshal(block)
			if err != nil {
				log.Printf("Failed to marshal block: %v", err)
				continue
			}

			msg := &network.Message{
				Type:      "block",
				Data:      blockData,
				Timestamp: time.Now().Unix(),
			}

			if err := n.network.BroadcastMessage(msg); err != nil {
				log.Printf("Failed to broadcast block: %v", err)
			}
		}
	}
}

// runMemPoolCleanupLoop periodically cleans up old transactions from the mempool
func (n *Node) runMemPoolCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-n.stopChan:
			return
		case <-ticker.C:
			n.cleanupMempool()
		}
	}
}

// cleanupMempool removes old transactions from the mempool
func (n *Node) cleanupMempool() {
	n.pendingTxsLock.Lock()
	defer n.pendingTxsLock.Unlock()

	now := time.Now().Unix()
	expireTime := int64(3600) // 1 hour

	for id, tx := range n.pendingTxs {
		if now-tx.Timestamp > expireTime {
			delete(n.pendingTxs, id)
		}
	}
}

// startAPIServer starts the HTTP API server
func (n *Node) startAPIServer() error {
	router := mux.NewRouter()

	// Register API routes
	router.HandleFunc("/api/status", n.handleAPIStatus).Methods("GET")
	router.HandleFunc("/api/blockchain/info", n.handleAPIBlockchainInfo).Methods("GET")
	router.HandleFunc("/api/blockchain/blocks", n.handleAPIGetBlocks).Methods("GET")
	router.HandleFunc("/api/blockchain/block/{hash}", n.handleAPIGetBlockByHash).Methods("GET")
	router.HandleFunc("/api/blockchain/block/height/{height}", n.handleAPIGetBlockByHeight).Methods("GET")
	router.HandleFunc("/api/transaction/submit", n.handleAPISubmitTransaction).Methods("POST")
	router.HandleFunc("/api/transaction/{txid}", n.handleAPIGetTransaction).Methods("GET")
	router.HandleFunc("/api/wallet/balance/{address}", n.handleAPIGetBalance).Methods("GET")
	router.HandleFunc("/api/wallet/create", n.handleAPICreateWallet).Methods("POST")
	router.HandleFunc("/api/peers", n.handleAPIGetPeers).Methods("GET")

	// VM-related routes
	if n.vmManager != nil {
		router.HandleFunc("/api/vm/status", n.handleAPIVMStatus).Methods("GET")
		router.HandleFunc("/api/vm/start", n.handleAPIStartVM).Methods("POST")
		router.HandleFunc("/api/vm/stop", n.handleAPIStopVM).Methods("POST")
		router.HandleFunc("/api/vm/allocate", n.handleAPIAllocateResources).Methods("POST")
	}

	// Create HTTP server
	n.apiServer = &http.Server{
		Addr:    n.config.APIAddr,
		Handler: router,
	}

	// Start server in background
	go func() {
		log.Printf("API server listening on %s", n.config.APIAddr)
		if err := n.apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error: %v", err)
		}
	}()

	return nil
}

// API handler functions

// handleAPIStatus handles the status API endpoint
func (n *Node) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := struct {
		NodeID           string `json:"node_id"`
		Version          string `json:"version"`
		BlockchainHeight uint64 `json:"blockchain_height"`
		PeerCount        int    `json:"peer_count"`
		Uptime           int64  `json:"uptime"`
		IsMining         bool   `json:"is_mining"`
		VMRunning        bool   `json:"vm_running"`
	}{
		NodeID:           "node-1", // In a real implementation, this would be the node's ID
		Version:          "1.0.0",
		BlockchainHeight: 0,
		PeerCount:        len(n.network.GetPeers()),
		Uptime:           0, // In a real implementation, this would be the node's uptime
		IsMining:         n.consensus.IsMining(),
		VMRunning:        n.vmManager != nil && n.vmManager.IsVMRunning(),
	}

	// Get blockchain height
	lastBlock, err := n.blockchain.GetLastBlock()
	if err == nil {
		status.BlockchainHeight = lastBlock.Header.Height
	}

	respondWithJSON(w, http.StatusOK, status)
}

// handleAPIBlockchainInfo handles the blockchain info API endpoint
func (n *Node) handleAPIBlockchainInfo(w http.ResponseWriter, r *http.Request) {
	lastBlock, err := n.blockchain.GetLastBlock()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get last block: %v", err))
		return
	}

	info := struct {
		Height        uint64 `json:"height"`
		LastBlockHash string `json:"last_block_hash"`
		Timestamp     int64  `json:"timestamp"`
		TxCount       int    `json:"tx_count"`
		Difficulty    uint32 `json:"difficulty"`
	}{
		Height:        lastBlock.Header.Height,
		LastBlockHash: fmt.Sprintf("%x", lastBlock.Header.PrevBlockHash),
		Timestamp:     lastBlock.Header.Timestamp,
		TxCount:       len(lastBlock.Transactions),
		Difficulty:    lastBlock.Header.Difficulty,
	}

	respondWithJSON(w, http.StatusOK, info)
}

// handleAPIGetBlocks handles the get blocks API endpoint
func (n *Node) handleAPIGetBlocks(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	limit := 10
	offset := 0

	if limitParam := r.URL.Query().Get("limit"); limitParam != "" {
		if parsedLimit, err := parseInt(limitParam); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	if offsetParam := r.URL.Query().Get("offset"); offsetParam != "" {
		if parsedOffset, err := parseInt(offsetParam); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	// In a real implementation, this would fetch blocks from the blockchain
	// For simplicity, we'll just return a placeholder response

	lastBlock, err := n.blockchain.GetLastBlock()
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get last block: %v", err))
		return
	}

	blocks := []struct {
		Height    uint64 `json:"height"`
		Hash      string `json:"hash"`
		Timestamp int64  `json:"timestamp"`
		TxCount   int    `json:"tx_count"`
	}{}

	// Add dummy blocks
	for i := 0; i < limit; i++ {
		height := lastBlock.Header.Height - uint64(offset+i)
		if height < 0 {
			break
		}

		blocks = append(blocks, struct {
			Height    uint64 `json:"height"`
			Hash      string `json:"hash"`
			Timestamp int64  `json:"timestamp"`
			TxCount   int    `json:"tx_count"`
		}{
			Height:    height,
			Hash:      fmt.Sprintf("%x", lastBlock.Header.PrevBlockHash), // This would be the actual block hash
			Timestamp: lastBlock.Header.Timestamp - int64(i*30),
			TxCount:   len(lastBlock.Transactions),
		})
	}

	respondWithJSON(w, http.StatusOK, blocks)
}

// handleAPIGetBlockByHash handles the get block by hash API endpoint
func (n *Node) handleAPIGetBlockByHash(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	hash := vars["hash"]

	if hash == "" {
		respondWithError(w, http.StatusBadRequest, "Missing block hash")
		return
	}

	// In a real implementation, this would fetch the block from the blockchain
	// For simplicity, we'll just return a placeholder response

	respondWithError(w, http.StatusNotFound, "Block not found")
}

// handleAPIGetBlockByHeight handles the get block by height API endpoint
func (n *Node) handleAPIGetBlockByHeight(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	heightStr := vars["height"]

	if heightStr == "" {
		respondWithError(w, http.StatusBadRequest, "Missing block height")
		return
	}

	height, err := parseUint64(heightStr)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid block height")
		return
	}

	// In a real implementation, this would fetch the block from the blockchain
	// For simplicity, we'll just return a placeholder response

	respondWithError(w, http.StatusNotFound, "Block not found")
}

// handleAPISubmitTransaction handles the submit transaction API endpoint
func (n *Node) handleAPISubmitTransaction(w http.ResponseWriter, r *http.Request) {
	var txReq struct {
		From   string `json:"from"`
		To     string `json:"to"`
		Amount uint64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&txReq); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Create and send transaction
	if err := n.wallet.SendTransaction(txReq.From, txReq.To, txReq.Amount); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to send transaction: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "Transaction submitted successfully"})
}

// handleAPIGetTransaction handles the get transaction API endpoint
func (n *Node) handleAPIGetTransaction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	txID := vars["txid"]

	if txID == "" {
		respondWithError(w, http.StatusBadRequest, "Missing transaction ID")
		return
	}

	// In a real implementation, this would fetch the transaction from the blockchain
	// For simplicity, we'll just return a placeholder response

	respondWithError(w, http.StatusNotFound, "Transaction not found")
}

// handleAPIGetBalance handles the get balance API endpoint
func (n *Node) handleAPIGetBalance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]

	if address == "" {
		respondWithError(w, http.StatusBadRequest, "Missing address")
		return
	}

	// In a real implementation, this would calculate the balance from UTXOs
	// For simplicity, we'll just return a placeholder response

	balance := struct {
		Address string `json:"address"`
		Balance uint64 `json:"balance"`
	}{
		Address: address,
		Balance: 1000, // Placeholder
	}

	respondWithJSON(w, http.StatusOK, balance)
}

// handleAPICreateWallet handles the create wallet API endpoint
func (n *Node) handleAPICreateWallet(w http.ResponseWriter, r *http.Request) {
	var walletReq struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&walletReq); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if walletReq.Name == "" {
		respondWithError(w, http.StatusBadRequest, "Missing wallet name")
		return
	}

	// Create wallet account
	if err := n.wallet.CreateAccount(walletReq.Name); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create wallet: %v", err))
		return
	}

	account := n.wallet.Accounts[walletReq.Name]

	wallet := struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	}{
		Name:    walletReq.Name,
		Address: account.Address,
	}

	respondWithJSON(w, http.StatusOK, wallet)
}

// handleAPIGetPeers handles the get peers API endpoint
func (n *Node) handleAPIGetPeers(w http.ResponseWriter, r *http.Request) {
	peers := n.network.GetPeers()
	respondWithJSON(w, http.StatusOK, peers)
}

// handleAPIVMStatus handles the VM status API endpoint
func (n *Node) handleAPIVMStatus(w http.ResponseWriter, r *http.Request) {
	if n.vmManager == nil {
		respondWithError(w, http.StatusNotFound, "VM manager not enabled")
		return
	}

	vmState := n.vmManager.GetVMState()
	respondWithJSON(w, http.StatusOK, vmState)
}

// handleAPIStartVM handles the start VM API endpoint
func (n *Node) handleAPIStartVM(w http.ResponseWriter, r *http.Request) {
	if n.vmManager == nil {
		respondWithError(w, http.StatusNotFound, "VM manager not enabled")
		return
	}

	if err := n.vmManager.StartVM(); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to start VM: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "VM started successfully"})
}

// handleAPIStopVM handles the stop VM API endpoint
func (n *Node) handleAPIStopVM(w http.ResponseWriter, r *http.Request) {
	if n.vmManager == nil {
		respondWithError(w, http.StatusNotFound, "VM manager not enabled")
		return
	}

	if err := n.vmManager.StopVM(); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to stop VM: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "VM stopped successfully"})
}

// handleAPIAllocateResources handles the allocate resources API endpoint
func (n *Node) handleAPIAllocateResources(w http.ResponseWriter, r *http.Request) {
	if n.vmManager == nil {
		respondWithError(w, http.StatusNotFound, "VM manager not enabled")
		return
	}

	var resourceReq struct {
		CPUCores    int `json:"cpu_cores"`
		MemoryMB    int `json:"memory_mb"`
		StorageGB   int `json:"storage_gb"`
		NetworkKbps int `json:"network_kbps"`
	}

	if err := json.NewDecoder(r.Body).Decode(&resourceReq); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	if err := n.vmManager.AllocateResources(
		resourceReq.CPUCores,
		resourceReq.MemoryMB,
		resourceReq.StorageGB,
		resourceReq.NetworkKbps,
	); err != nil {
		respondWithError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to allocate resources: %v", err))
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"status": "Resources allocated successfully"})
}

// Helper functions

// respondWithError sends an error response
func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

// respondWithJSON sends a JSON response
func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, err := json.Marshal(payload)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf(`{"error": "Failed to marshal JSON response: %v"}`, err)))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// parseInt parses a string to an integer
func parseInt(s string) (int, error) {
	// Implementation omitted for brevity
	return 0, nil
}

// parseUint64 parses a string to an uint64
func parseUint64(s string) (uint64, error) {
	// Implementation omitted for brevity
	return 0, nil
}
