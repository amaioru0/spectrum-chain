# Spectrum Chain

A distributed blockchain with a global virtual machine that allows nodes to contribute resources to a shared Ubuntu environment, with SSH access.

## Overview

Spectrum Chain is a bare-metal blockchain implementation in Go that features a distributed resource model where each node contributes CPU, memory, storage, and network bandwidth to power a global Ubuntu virtual machine.

Key features:
- **Proof of Stake (PoS) consensus mechanism**
- **Global distributed VM** that runs Ubuntu using resources from all nodes
- **Resource allocation system** that rewards participants with SPECTRUM tokens
- **CLI wallet** with comprehensive commands
- **SSH access** to the global VM through any node in the network

## Architecture

Spectrum Chain consists of the following core components:

1. **Blockchain Core**: Implements the blockchain, transactions, and blocks
2. **Consensus Engine**: Implements Proof of Stake (PoS) consensus
3. **Network Layer**: Handles peer-to-peer communication and message propagation
4. **Wallet Interface**: Manages accounts, keys, and transactions
5. **Virtual Machine (VM) Manager**: Orchestrates the global distributed VM
6. **API Server**: Provides HTTP endpoints for interacting with the node
7. **CLI Interface**: Command-line interface for node management and wallet operations

## Installation

### Prerequisites

- Go 1.18 or higher
- QEMU/KVM or libvirt
- Docker (optional, for VM functionality)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/spectrum-chain/core.git
cd core

# Build the node
go build -o spectrum-node cmd/node/main.go

# Build the wallet CLI
go build -o spectrum-wallet cmd/wallet/main.go
```

## Running a Node

```bash
# Run a regular node
./spectrum-node --datadir ./node-data --addr :9000 --api :8000

# Run a node with mining enabled
./spectrum-node --datadir ./node-data --addr :9000 --api :8000 --mine

# Run a node with VM functionality enabled
./spectrum-node --datadir ./node-data --addr :9000 --api :8000 --vm

# Run a node with SSH access to VM enabled
./spectrum-node --datadir ./node-data --addr :9000 --api :8000 --vm --ssh --ssh-port 2222

# Run a bootstrap node
./spectrum-node --datadir ./bootstrap-data --addr :9000 --api :8000 --is-bootstrap

# Connect to bootstrap nodes
./spectrum-node --datadir ./node-data --addr :9001 --api :8001 --bootstrap "127.0.0.1:9000"
```

## Using the Wallet CLI

The wallet CLI provides a comprehensive set of commands for managing your Spectrum Chain wallet.

### Interactive Shell

```bash
# Start the interactive shell
./spectrum-wallet shell
```

### Basic Commands

```bash
# Create a new account
./spectrum-wallet create myaccount

# List accounts
./spectrum-wallet list

# Set active account
./spectrum-wallet use myaccount

# Get account balance
./spectrum-wallet balance myaccount

# Send tokens
./spectrum-wallet send myaccount recipient-address 100

# Import an account from a private key
./spectrum-wallet import myaccount private-key-hex

# Export account private key
./spectrum-wallet export myaccount
```

## Accessing the Global VM

Once the VM is started and you have allocated resources, you can access it via SSH:

```bash
# Connect via SSH using any node's IP address
ssh -p 2222 spectrum@node-ip-address
# Default password: spectrum
```

## API Endpoints

The node provides a RESTful API for interacting with the blockchain and VM:

### Blockchain Endpoints

- `GET /api/status` - Get node status
- `GET /api/blockchain/info` - Get blockchain information
- `GET /api/blockchain/blocks` - Get list of blocks
- `GET /api/blockchain/block/{hash}` - Get block by hash
- `GET /api/blockchain/block/height/{height}` - Get block by height
- `POST /api/transaction/submit` - Submit a transaction
- `GET /api/transaction/{txid}` - Get transaction by ID
- `GET /api/wallet/balance/{address}` - Get wallet balance
- `POST /api/wallet/create` - Create a new wallet
- `GET /api/peers` - Get list of connected peers

### VM Endpoints

- `GET /api/vm/status` - Get VM status
- `POST /api/vm/start` - Start the VM
- `POST /api/vm/stop` - Stop the VM
- `POST /api/vm/allocate` - Allocate resources to the VM

## Allocating Resources to the VM

You can allocate resources to the global VM through the API:

```bash
# Allocate 2 CPU cores, 4GB memory, 20GB storage, and 100Mbps network
curl -X POST http://localhost:8000/api/vm/allocate -H "Content-Type: application/json" -d '{
  "cpu_cores": 2,
  "memory_mb": 4096,
  "storage_gb": 20,
  "network_kbps": 102400
}'
```

## Token Economics

The Spectrum Chain uses SPECTRUM tokens for:

1. **Staking**: Validators stake tokens to participate in consensus
2. **Resource Allocation**: Nodes earn tokens by contributing resources to the global VM
3. **Transaction Fees**: Transactions require a small fee paid in SPECTRUM
4. **Block Rewards**: Validators earn rewards for producing blocks

## Project Structure

```
spectrum-chain/
├── cmd/
│   ├── node/         # Node entry point
│   └── wallet/       # Wallet CLI entry point
├── core/
│   ├── blockchain/   # Blockchain implementation
│   ├── consensus/    # Consensus mechanism
│   ├── network/      # P2P networking
│   ├── node/         # Node implementation
│   ├── vm/           # Virtual machine manager
│   ├── wallet/       # Wallet implementation
│   └── utils/        # Utility functions
├── api/              # HTTP API implementation
├── scripts/          # Utility scripts
└── README.md         # This file
```

## Security Considerations

- **Private Keys**: Keep your private keys secure. Anyone with access to your private key can control your funds.
- **Node Security**: Secure your node with proper firewall rules and SSH key authentication for VM access.
- **Resource Allocation**: Be careful with resource allocation to avoid starving your host system.

## Development

### Setting Up Development Environment

```bash
# Install dependencies
go get -u github.com/spectrum-chain/core/...

# Run tests
go test ./...
```

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The Bitcoin and Ethereum projects for inspiration
- The Go community for excellent libraries and tools
- The libvirt and QEMU projects for VM functionality