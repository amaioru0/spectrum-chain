// Core blockchain implementation for Spectrum Chain
package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v3"
)

// Constants for blockchain operation
const (
	BlockchainDBPath         = "blockchain"
	BlocksBucket             = "blocks"
	ChainstateBucket         = "chainstate"
	DefaultDifficulty        = 3
	DifficultyAdjustInterval = 100
	TargetBlockTime          = 30 // in seconds
	MaxTransactionsPerBlock  = 5000
	GenesisReward            = 100000000 // 100 SPECTRUM tokens
)

// Block represents a block in the blockchain
type Block struct {
	Header       BlockHeader   `json:"header"`
	Transactions []Transaction `json:"transactions"`
}

// BlockHeader contains metadata of a block
type BlockHeader struct {
	Version       uint32 `json:"version"`
	PrevBlockHash []byte `json:"prev_block_hash"`
	MerkleRoot    []byte `json:"merkle_root"`
	Timestamp     int64  `json:"timestamp"`
	Difficulty    uint32 `json:"difficulty"`
	Nonce         uint64 `json:"nonce"`
	Height        uint64 `json:"height"`
}

// Transaction represents a transaction in the blockchain
type Transaction struct {
	ID        []byte     `json:"id"`
	Inputs    []TxInput  `json:"inputs"`
	Outputs   []TxOutput `json:"outputs"`
	Timestamp int64      `json:"timestamp"`
	Signature []byte     `json:"signature"`
	PublicKey []byte     `json:"public_key"`
}

// TxInput represents a transaction input
type TxInput struct {
	TxID      []byte `json:"txid"`
	OutIndex  uint32 `json:"out_index"`
	PublicKey []byte `json:"public_key"`
}

// TxOutput represents a transaction output
type TxOutput struct {
	Value      uint64 `json:"value"`
	PubKeyHash []byte `json:"pubkey_hash"`
}

// Blockchain manages the chain of blocks
type Blockchain struct {
	db        *badger.DB
	tip       []byte
	lock      sync.RWMutex
	mempool   map[string]*Transaction
	mempoolMu sync.RWMutex
}

// NewBlockchain creates a new blockchain or loads an existing one
func NewBlockchain(dbPath string) (*Blockchain, error) {
	opts := badger.DefaultOptions(dbPath)
	opts.Logger = nil

	db, err := badger.Open(opts)
	if err != nil {
		return nil, err
	}

	bc := &Blockchain{
		db:      db,
		mempool: make(map[string]*Transaction),
	}

	// Check if blockchain exists
	var tip []byte
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("l"))
		if err == nil {
			return item.Value(func(val []byte) error {
				tip = make([]byte, len(val))
				copy(tip, val)
				return nil
			})
		}
		return err
	})

	// If blockchain doesn't exist, create genesis block
	if err == badger.ErrKeyNotFound {
		genesis := bc.createGenesisBlock()
		err = bc.addBlock(genesis)
		if err != nil {
			return nil, err
		}
		tip = genesis.Header.PrevBlockHash
	} else if err != nil {
		return nil, err
	}

	bc.tip = tip
	return bc, nil
}

// createGenesisBlock creates the genesis block
func (bc *Blockchain) createGenesisBlock() *Block {
	// Create a genesis transaction that sends coins to a predefined address
	coinbase := Transaction{
		ID:        []byte{},
		Inputs:    []TxInput{},
		Outputs:   []TxOutput{{Value: GenesisReward, PubKeyHash: []byte("genesis-address")}},
		Timestamp: time.Now().Unix(),
	}
	coinbase.ID = coinbase.Hash()

	// Create genesis block
	genesis := &Block{
		Header: BlockHeader{
			Version:       1,
			PrevBlockHash: []byte{},
			Timestamp:     time.Now().Unix(),
			Difficulty:    DefaultDifficulty,
			Height:        0,
		},
		Transactions: []Transaction{coinbase},
	}

	// Calculate merkle root
	genesis.Header.MerkleRoot = calculateMerkleRoot(genesis.Transactions)

	// Mine the genesis block
	bc.mineBlock(genesis)

	return genesis
}

// mineBlock performs proof-of-work to find a valid hash
func (bc *Blockchain) mineBlock(block *Block) {
	target := big.NewInt(1)
	target.Lsh(target, 256-uint(block.Header.Difficulty))

	var hashInt big.Int
	var hash [32]byte
	nonce := uint64(0)

	for {
		block.Header.Nonce = nonce
		hash = sha256.Sum256(bc.serializeHeader(block.Header))
		hashInt.SetBytes(hash[:])

		if hashInt.Cmp(target) == -1 {
			break
		}
		nonce++
	}
}

// AddBlock mines and adds a new block to the blockchain
func (bc *Blockchain) AddBlock(transactions []Transaction) (*Block, error) {
	bc.lock.Lock()
	defer bc.lock.Unlock()

	prevBlockHash := bc.tip

	// Get height of the previous block
	var prevHeight uint64
	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(prevBlockHash)
		if err != nil {
			return err
		}

		var prevBlock Block
		return item.Value(func(val []byte) error {
			if err := json.Unmarshal(val, &prevBlock); err != nil {
				return err
			}
			prevHeight = prevBlock.Header.Height
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Create new block
	block := &Block{
		Header: BlockHeader{
			Version:       1,
			PrevBlockHash: prevBlockHash,
			Timestamp:     time.Now().Unix(),
			Difficulty:    bc.calculateDifficulty(),
			Height:        prevHeight + 1,
		},
		Transactions: transactions,
	}

	// Add reward transaction
	rewardTx := bc.createRewardTransaction(block.Header.Height)
	block.Transactions = append([]Transaction{rewardTx}, block.Transactions...)

	// Calculate merkle root
	block.Header.MerkleRoot = calculateMerkleRoot(block.Transactions)

	// Mine the block
	bc.mineBlock(block)

	// Add the block to the chain
	if err := bc.addBlock(block); err != nil {
		return nil, err
	}

	return block, nil
}

// AddTransaction adds a transaction to the mempool
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	// Verify transaction
	if err := bc.VerifyTransaction(tx); err != nil {
		return err
	}

	bc.mempoolMu.Lock()
	defer bc.mempoolMu.Unlock()

	txID := fmt.Sprintf("%x", tx.ID)
	bc.mempool[txID] = tx

	return nil
}

// VerifyTransaction checks if a transaction is valid
func (bc *Blockchain) VerifyTransaction(tx *Transaction) error {
	// Implement transaction verification logic (signatures, double-spending, etc.)
	// This is simplified for brevity
	return nil
}

// calculateDifficulty adjusts the difficulty based on block times
func (bc *Blockchain) calculateDifficulty() uint32 {
	// Get current difficulty
	currentDifficulty := DefaultDifficulty

	// Get the last block
	lastBlock, err := bc.GetLastBlock()
	if err != nil {
		return currentDifficulty
	}

	// Only adjust difficulty at certain intervals
	if lastBlock.Header.Height%DifficultyAdjustInterval != 0 {
		return lastBlock.Header.Difficulty
	}

	// Get block at the beginning of the adjustment interval
	prevAdjustmentHeight := lastBlock.Header.Height - DifficultyAdjustInterval
	prevAdjustmentBlock, err := bc.GetBlockByHeight(prevAdjustmentHeight)
	if err != nil {
		return currentDifficulty
	}

	// Calculate time taken to mine blocks in the interval
	timeExpected := int64(TargetBlockTime * DifficultyAdjustInterval)
	timeActual := lastBlock.Header.Timestamp - prevAdjustmentBlock.Header.Timestamp

	// Adjust difficulty based on time difference
	if timeActual < timeExpected/2 {
		return lastBlock.Header.Difficulty + 1
	} else if timeActual > timeExpected*2 {
		if lastBlock.Header.Difficulty > 1 {
			return lastBlock.Header.Difficulty - 1
		}
	}

	return lastBlock.Header.Difficulty
}

// GetLastBlock returns the last block in the chain
func (bc *Blockchain) GetLastBlock() (*Block, error) {
	bc.lock.RLock()
	defer bc.lock.RUnlock()

	var lastBlock Block
	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(bc.tip)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &lastBlock)
		})
	})

	if err != nil {
		return nil, err
	}

	return &lastBlock, nil
}

// GetBlockByHeight returns a block by its height
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, error) {
	// Implementation omitted for brevity
	// This would scan through blocks to find one with matching height
	return nil, nil
}

// GetBlockByHash returns a block by its hash
func (bc *Blockchain) GetBlockByHash(hash []byte) (*Block, error) {
	var block Block

	err := bc.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(hash)
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &block)
		})
	})

	if err != nil {
		return nil, err
	}

	return &block, nil
}

// addBlock adds a block to the database
func (bc *Blockchain) addBlock(block *Block) error {
	err := bc.db.Update(func(txn *badger.Txn) error {
		blockData, err := json.Marshal(block)
		if err != nil {
			return err
		}

		blockHash := bc.hashBlock(block)

		if err := txn.Set(blockHash, blockData); err != nil {
			return err
		}

		// Update latest tip
		if err := txn.Set([]byte("l"), blockHash); err != nil {
			return err
		}

		bc.tip = blockHash

		return nil
	})

	return err
}

// createRewardTransaction creates a coinbase transaction with mining rewards
func (bc *Blockchain) createRewardTransaction(height uint64) Transaction {
	// Calculate reward based on block height (with halving)
	reward := calculateBlockReward(height)

	// Create coinbase transaction
	// In a real implementation, this would use the miner's address
	tx := Transaction{
		Inputs: []TxInput{},
		Outputs: []TxOutput{
			{
				Value:      reward,
				PubKeyHash: []byte("miner-address"), // Placeholder
			},
		},
		Timestamp: time.Now().Unix(),
	}

	tx.ID = tx.Hash()
	return tx
}

// calculateBlockReward determines the mining reward based on block height
func calculateBlockReward(height uint64) uint64 {
	// Implement halving logic (e.g., every 210,000 blocks)
	halvings := height / 210000

	if halvings >= 64 {
		return 0
	}

	// Initial reward is 50 SPECTRUM
	initialReward := uint64(5000000000)

	// Reduce by half for each halving
	return initialReward >> halvings
}

// hashBlock calculates the hash of a block
func (bc *Blockchain) hashBlock(block *Block) []byte {
	blockHeader := bc.serializeHeader(block.Header)
	hash := sha256.Sum256(blockHeader)
	return hash[:]
}

// serializeHeader converts a block header to bytes
func (bc *Blockchain) serializeHeader(header BlockHeader) []byte {
	var buf bytes.Buffer

	// Serialize header fields
	binary.Write(&buf, binary.LittleEndian, header.Version)
	buf.Write(header.PrevBlockHash)
	buf.Write(header.MerkleRoot)
	binary.Write(&buf, binary.LittleEndian, header.Timestamp)
	binary.Write(&buf, binary.LittleEndian, header.Difficulty)
	binary.Write(&buf, binary.LittleEndian, header.Nonce)
	binary.Write(&buf, binary.LittleEndian, header.Height)

	return buf.Bytes()
}

// calculateMerkleRoot calculates the Merkle root of transactions
func calculateMerkleRoot(transactions []Transaction) []byte {
	var hashes [][]byte

	// Get transaction hashes
	for _, tx := range transactions {
		hashes = append(hashes, tx.ID)
	}

	// If no transactions, return empty hash
	if len(hashes) == 0 {
		return []byte{}
	}

	// Build merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var level [][]byte
		for i := 0; i < len(hashes); i += 2 {
			hash := append(hashes[i], hashes[i+1]...)
			h := sha256.Sum256(hash)
			level = append(level, h[:])
		}

		hashes = level
	}

	return hashes[0]
}

// Hash calculates the hash of a transaction
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	// Create a copy of the transaction without the ID field
	txCopy := *tx
	txCopy.ID = []byte{}

	// Serialize and hash
	txData, _ := json.Marshal(txCopy)
	hash = sha256.Sum256(txData)

	return hash[:]
}

// Close closes the blockchain database
func (bc *Blockchain) Close() error {
	return bc.db.Close()
}
