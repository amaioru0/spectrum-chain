#!/bin/bash
set -e

# Default values
DATA_DIR=${DATA_DIR:-"/app/data"}
LISTEN_ADDR=${LISTEN_ADDR:-":9000"}
API_ADDR=${API_ADDR:-":8000"}
SSH_PORT=${SSH_PORT:-2222}
BOOTSTRAP_NODES=${BOOTSTRAP_NODES:-""}
IS_BOOTSTRAP=${IS_BOOTSTRAP:-false}
MINER_ENABLED=${MINER_ENABLED:-false}
VM_ENABLED=${VM_ENABLED:-false}
SSH_ENABLED=${SSH_ENABLED:-false}
LOG_LEVEL=${LOG_LEVEL:-"info"}

# Define command to run
if [ "$1" = "node" ]; then
    echo "Starting Spectrum Chain node..."
    
    # Build command with environment variables
    CMD="/app/spectrum-node"
    CMD+=" --datadir=${DATA_DIR}"
    CMD+=" --addr=${LISTEN_ADDR}"
    CMD+=" --api=${API_ADDR}"
    
    if [ ! -z "$BOOTSTRAP_NODES" ]; then
        CMD+=" --bootstrap=${BOOTSTRAP_NODES}"
    fi
    
    if [ "$IS_BOOTSTRAP" = "true" ]; then
        CMD+=" --is-bootstrap"
    fi
    
    if [ "$MINER_ENABLED" = "true" ]; then
        CMD+=" --mine"
    fi
    
    if [ "$VM_ENABLED" = "true" ]; then
        CMD+=" --vm"
    fi
    
    if [ "$SSH_ENABLED" = "true" ]; then
        CMD+=" --ssh"
        CMD+=" --ssh-port=${SSH_PORT}"
    fi
    
    CMD+=" --log=${LOG_LEVEL}"
    
    # Execute the command
    exec $CMD
    
elif [ "$1" = "wallet" ]; then
    echo "Starting Spectrum Chain wallet CLI..."
    
    # Set wallet path
    WALLET_PATH="${DATA_DIR}/wallet.dat"
    
    # Execute wallet in interactive mode
    exec /app/spectrum-wallet --wallet=${WALLET_PATH} shell
    
elif [ "$1" = "bash" ] || [ "$1" = "sh" ]; then
    exec "$@"
else
    echo "Unknown command: $1"
    echo "Available commands: node, wallet, bash, sh"
    exit 1
fi