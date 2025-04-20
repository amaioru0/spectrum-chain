
// Package consensus implements the consensus algorithm for Spectrum Chain
package consensus

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"

	"github.com/spectrum-chain/core/blockchain"
	"github.com/spectrum-chain/core/wallet"
)

const (
	// MinStake is the minimum amount of tokens required to stake
	MinStake = 1000

	// BlockReward is the reward for producing a block
	BlockReward = 10

	// MaxBlockSize is the maximum size of a block in bytes
	MaxBlockSize = 1024 * 1024 // 1MB

	// BlockInterval is the target time between blocks in seconds
	BlockInterval = 30

	// StakeMaturityPeriod is the number of blocks before staked tokens can be unstaked
	StakeMaturityPeriod = 1440 // ~12 hours with 30-second blocks
)

// StakeInfo represents staking information for an account
type StakeInfo struct {
	Address      string `json:"address"`
	Amount       uint64 `json:"amount"`
	Timestamp    int64  `json:"timestamp"`
	BlockHeight  uint64 `json:"block_height"`
	IsValidator  bool   `json:"is_validator"`
}

// PoSConsensus implements Proof of Stake consensus
type PoSConsensus struct {
	blockchain  *blockchain.Blockchain
	wallet      *wallet.Wallet
	stakes      map[string]*StakeInfo // Address -> StakeInfo
	stakesLock  sync.RWMutex
	validators  []string
	validLock   sync.RWMutex
	isMining    bool
	miningLock  sync.Mutex
	stopMining  chan struct{}
}

// NewPoSConsensus creates a new PoS consensus engine
func NewPoSConsensus(blockchain *blockchain.Blockchain, wallet *wallet.Wallet) *PoSConsensus {
	return &PoSConsensus{
		blockchain:  blockchain,
		wallet:      wallet,
		stakes:      make(map[string]*StakeInfo),
		stopMining:  make(chan struct{}),
	}
}

// Start starts the consensus engine
func (pos *PoSConsensus) Start() error {
	// Load stake information from the blockchain
	if err := pos.loadStakes(); err != nil {
		return fmt.Errorf("failed to load stakes: %w", err)
	}

	// Select validators
	pos.selectValidators()

	return nil
}

// Stop stops the consensus engine
func (pos *PoSConsensus) Stop() error {
	pos.miningLock.Lock()
	defer pos.miningLock.Unlock()

	if pos.isMining {
		close(pos.stopMining)
		pos.isMining = false
	}

	return nil
}

// Stake stakes tokens for consensus participation
func (pos *PoSConsensus) Stake(address string, amount uint64) error {
	// Check minimum stake
	if amount < MinStake {
		return fmt.Errorf("stake amount %d is below minimum %d", amount, MinStake)
	}

	// Check if account has enough balance
	// In a real implementation, this would deduct tokens from the account
	// and keep track of them in a separate stake account

	// Update stake information
	pos.stakesLock.Lock()
	defer pos.stakesLock.Unlock()

	lastBlock, err := pos.blockchain.GetLastBlock()
	if err != nil {
		return fmt.Errorf("failed to get last block: %w", err)
	}

	pos.stakes[address] = &StakeInfo{
		Address:     address,
		Amount:      amount,
		Timestamp:   time.Now().Unix(),
		BlockHeight: lastBlock.Header.Height,
		IsValidator: false,
	}

	// Update validators
	pos.selectValidators()

	// Broadcast stake information
	// In a real implementation, this would be handled by a transaction

	return nil
}

// Unstake removes tokens from staking
func (pos *PoSConsensus) Unstake(address string, amount uint64) error {
	pos.stakesLock.Lock()
	defer pos.stakesLock.Unlock()

	stake, exists := pos.stakes[address]
	if !exists {
		return fmt.Errorf("no stake found for address %s", address)
	}

	// Check if stake is mature
	lastBlock, err := pos.blockchain.GetLastBlock()
	if err != nil {
		return fmt.Errorf("failed to get last block: %w", err)
	}

	if lastBlock.Header.Height < stake.BlockHeight+StakeMaturityPeriod {
		return fmt.Errorf("stake is not mature yet, need to wait %d more blocks",
			stake.BlockHeight+StakeMaturityPeriod-lastBlock.Header.Height)
	}

	// Check amount
	if amount > stake.Amount {
		return fmt.Errorf("unstake amount %d exceeds staked amount %d", amount, stake.Amount)
	}

	// Update stake
	if amount == stake.Amount {
		// Remove stake completely
		delete(pos.stakes, address)
	} else {
		// Reduce stake amount
		stake.Amount -= amount
		pos.stakes[address] = stake
	}

	// Update validators
	pos.selectValidators()

	// Return tokens to account balance
	// In a real implementation, this would be handled by a transaction

	return nil
}

// StartMining starts the mining process
func (pos *PoSConsensus) StartMining() error {
	pos.miningLock.Lock()
	defer pos.miningLock.Unlock()

	if pos.isMining {
		return errors.New("mining is already in progress")
	}

	// Check if node is a validator
	activeAccount, err := pos.wallet.GetActiveAccount()
	if err != nil {
		return fmt.Errorf("failed to get active account: %w", err)
	}

	isValidator := false
	pos.validLock.RLock()
	for _, v := range pos.validators {
		if v == activeAccount.Address {
			isValidator = true
			break
		}
	}
	pos.validLock.RUnlock()

	if !isValidator {
		return fmt.Errorf("active account %s is not a validator", activeAccount.Address)
	}

	// Start mining in background
	pos.stopMining = make(chan struct{})
	pos.isMining = true

	go pos.miningLoop()

	log.Printf("Mining started with account %s", activeAccount.Address)

	return nil
}

// StopMining stops the mining process
func (pos *PoSConsensus) StopMining() error {
	pos.miningLock.Lock()
	defer pos.miningLock.Unlock()

	if !pos.isMining {
		return nil
	}

	close(pos.stopMining)
	pos.isMining = false

	log.Println("Mining stopped")

	return nil
}

// IsMining returns whether mining is in progress
func (pos *PoSConsensus) IsMining() bool {
	pos.miningLock.Lock()
	defer pos.miningLock.Unlock()

	return pos.isMining
}

// loadStakes loads stake information from the blockchain
func (pos *PoSConsensus) loadStakes() error {
	// In a real implementation, this would scan the blockchain for stake transactions
	// For simplicity, we'll use a placeholder implementation

	// Example: Load stakes from a database or blockchain
	// [...]

	return nil
}

// selectValidators selects validators based on stake
func (pos *PoSConsensus) selectValidators() {
	pos.stakesLock.RLock()
	defer pos.stakesLock.RUnlock()

	pos.validLock.Lock()
	defer pos.validLock.Unlock()

	// Sort stakes by amount (descending)
	// In a real implementation, this would be more complex
	// and would involve a selection algorithm based on stake amount and time

	// For simplicity, we'll just select all accounts with stakes as validators
	validators := make([]string, 0, len(pos.stakes))
	for addr, stake := range pos.stakes {
		validators = append(validators, addr)
		stake.IsValidator = true
	}

	pos.validators = validators
}

// miningLoop continuously mines new blocks
func (pos *PoSConsensus) miningLoop() {
	for {
		select {
		case <-pos.stopMining:
			return
		default:
			// Check if it's our turn to mine
			if pos.isValidatorTurn() {
				// Create new block
				if err := pos.createNewBlock(); err != nil {
					log.Printf("Error creating new block: %v", err)
				}
			}

			// Wait a short time before trying again
			time.Sleep(1 * time.Second)
		}
	}
}

// isValidatorTurn checks if it's this validator's turn to create a block
func (pos *PoSConsensus) isValidatorTurn() bool {
	// Get active account
	activeAccount, err := pos.wallet.GetActiveAccount()
	if err != nil {
		log.Printf("Failed to get active account: %v", err)
		return false
	}

	// Get last block
	lastBlock, err := pos.blockchain.GetLastBlock()
	if err != nil {
		log.Printf("Failed to get last block: %v", err)
		return false
	}

	// Check if enough time has passed since the last block
	now := time.Now().Unix()
	if now-lastBlock.Header.Timestamp < BlockInterval {
		return false
	}

	// Determine turn based on a combination of time and stake
	// This is a simplified implementation - a real one would be more sophisticated
	pos.validLock.RLock()
	validatorCount := len(pos.validators)
	pos.validLock.RUnlock()

	if validatorCount == 0 {
		return false
	}

	// Create a deterministic seed from the last block hash
	seed := binary.LittleEndian.Uint64(lastBlock.Header.PrevBlockHash[:8])
	seed ^= uint64(now / BlockInterval)

	// Select validator based on seed
	selectedIdx := seed % uint64(validatorCount)

	pos.validLock.RLock()
	defer pos.validLock.RUnlock()

	// Check if we're the selected validator
	return pos.validators[selectedIdx] == activeAccount.Address
}

// createNewBlock creates and adds a new block to the blockchain
func (pos *PoSConsensus) createNewBlock() error {
	// Get pending transactions from mempool
	// In a real implementation, this would retrieve transactions from the mempool
	var transactions []blockchain.Transaction

	// Add block to blockchain
	block, err := pos.blockchain.AddBlock(transactions)
	if err != nil {
		return fmt.Errorf("failed to add block: %w", err)
	}

	log.Printf("Created new block at height %d with %d transactions",
		block.Header.Height, len(block.Transactions))

	// Broadcast block to network
	// In a real implementation, this would broadcast the block to the network

	return nil
}

// VerifyBlock verifies a received block
func (pos *PoSConsensus) VerifyBlock(block *blockchain.Block) error {
	// Verify block header
	if err := pos.verifyBlockHeader(block); err != nil {
		return err
	}

	// Verify transactions
	for _, tx := range block.Transactions {
		if err := pos.blockchain.VerifyTransaction(&tx); err != nil {
			return fmt.Errorf("invalid transaction %x: %w", tx.ID, err)
		}
	}

	return nil
}

// verifyBlockHeader verifies a block header
func (pos *PoSConsensus) verifyBlockHeader(block *blockchain.Block) error {
	// Verify merkle root
	merkleRoot := blockchain.CalculateMerkleRoot(block.Transactions)
	if !bytes.Equal(merkleRoot, block.Header.MerkleRoot) {
		return errors.New("invalid merkle root")
	}

	// Verify timestamp
	if block.Header.Timestamp > time.Now().Unix()+300 {
		return errors.New("block timestamp is too far in the future")
	}

	// Verify difficulty
	lastBlock, err := pos.blockchain.GetLastBlock()
	if err != nil {
		return fmt.Errorf("failed to get last block: %w", err)
	}

	expectedDifficulty := pos.blockchain.CalculateDifficulty()
	if block.Header.Difficulty != expectedDifficulty {
		return fmt.Errorf("invalid difficulty: got %d, expected %d", block.Header.Difficulty, expectedDifficulty)
	}

	// Verify proof of work
	target := big.NewInt(1)
	target.Lsh(target, 256-uint(block.Header.Difficulty))

	blockHash := sha256.Sum256(pos.blockchain.SerializeHeader(block.Header))
	hashInt := new(big.Int).SetBytes(blockHash[:])

	if hashInt.Cmp(target) >= 0 {
		return errors.New("invalid proof of work")
	}