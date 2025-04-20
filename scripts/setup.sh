#!/bin/bash
# Setup script for Spectrum Chain
set -e

# Default values
NODE_COUNT=3
DATA_DIR="./data"
USE_DOCKER=false

# Parse command-line options
while [[ $# -gt 0 ]]; do
  case $1 in
    --node-count)
      NODE_COUNT="$2"
      shift 2
      ;;
    --data-dir)
      DATA_DIR="$2"
      shift 2
      ;;
    --docker)
      USE_DOCKER=true
      shift
      ;;
    --help)
      echo "Spectrum Chain Setup Script"
      echo ""
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  --node-count <number>  Number of nodes to create (default: 3)"
      echo "  --data-dir <path>      Data directory (default: ./data)"
      echo "  --docker               Use Docker for deployment"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "Spectrum Chain Setup"
echo "===================="
echo "Node count: $NODE_COUNT"
echo "Data directory: $DATA_DIR"
echo "Use Docker: $USE_DOCKER"
echo ""

# Create data directory
mkdir -p "$DATA_DIR"

if [ "$USE_DOCKER" = true ]; then
  echo "Setting up Docker deployment..."
  
  # Check if Docker is installed
  if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker and try again."
    exit 1
  fi
  
  # Check if Docker Compose is installed
  if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
  fi
  
  # Generate docker-compose.yml based on node count
  cat > docker-compose.yml <<EOL
version: '3.8'

services:
  bootstrap-node:
    build: .
    container_name: spectrum-bootstrap
    environment:
      - DATA_DIR=/app/data
      - LISTEN_ADDR=:9000
      - API_ADDR=:8000
      - IS_BOOTSTRAP=true
      - MINER_ENABLED=true
      - LOG_LEVEL=info
    ports:
      - "9000:9000"
      - "8000:8000"
    volumes:
      - bootstrap-data:/app/data
    restart: unless-stopped
EOL

  # Add node services
  for i in $(seq 1 $NODE_COUNT); do
    API_PORT=$((8000 + $i))
    P2P_PORT=$((9000 + $i))
    SSH_PORT=$((2222 + $i - 1))
    
    cat >> docker-compose.yml <<EOL

  node$i:
    build: .
    container_name: spectrum-node$i
    depends_on:
      - bootstrap-node
    environment:
      - DATA_DIR=/app/data
      - LISTEN_ADDR=:9000
      - API_ADDR=:8000
      - BOOTSTRAP_NODES=bootstrap-node:9000
      - MINER_ENABLED=true
      - VM_ENABLED=true
      - SSH_ENABLED=true
      - SSH_PORT=2222
      - LOG_LEVEL=info
    ports:
      - "$P2P_PORT:9000"
      - "$API_PORT:8000"
      - "$SSH_PORT:2222"
    volumes:
      - node$i-data:/app/data
    restart: unless-stopped
EOL
  done

  # Add wallet service
  cat >> docker-compose.yml <<EOL

  wallet:
    build: .
    container_name: spectrum-wallet
    command: wallet
    environment:
      - DATA_DIR=/app/data
    volumes:
      - wallet-data:/app/data
    tty: true
    stdin_open: true

volumes:
  bootstrap-data:
EOL

  # Add volume definitions
  for i in $(seq 1 $NODE_COUNT); do
    cat >> docker-compose.yml <<EOL
  node$i-data:
EOL
  done

  cat >> docker-compose.yml <<EOL
  wallet-data:
EOL

  echo "Docker Compose configuration generated."
  echo "Starting containers..."
  
  # Build and start containers
  docker-compose up -d --build
  
  echo "Containers started!"
  echo ""
  echo "Access nodes with:"
  echo "  Bootstrap node API: http://localhost:8000"
  for i in $(seq 1 $NODE_COUNT); do
    API_PORT=$((8000 + $i))
    SSH_PORT=$((2222 + $i - 1))
    echo "  Node $i API: http://localhost:$API_PORT"
    echo "  Node $i SSH (to global VM): ssh -p $SSH_PORT spectrum@localhost"
  done
  
  echo ""
  echo "Use wallet with:"
  echo "  docker-compose exec -it wallet /app/spectrum-wallet --wallet=/app/data/wallet.dat shell"
  
else
  # Setup for local deployment
  echo "Setting up local deployment..."
  
  # Check if Go is installed
  if ! command -v go &> /dev/null; then
    echo "Go is not installed. Please install Go and try again."
    exit 1
  fi
  
  # Build binaries
  echo "Building Spectrum Chain binaries..."
  go build -o spectrum-node cmd/node/main.go
  go build -o spectrum-wallet cmd/wallet/main.go
  
  # Create bootstrap node directory
  BOOTSTRAP_DIR="$DATA_DIR/bootstrap"
  mkdir -p "$BOOTSTRAP_DIR"
  
  # Start bootstrap node
  echo "Starting bootstrap node..."
  ./spectrum-node --datadir="$BOOTSTRAP_DIR" --addr=:9000 --api=:8000 --is-bootstrap --mine > "$BOOTSTRAP_DIR/node.log" 2>&1 &
  BOOTSTRAP_PID=$!
  echo $BOOTSTRAP_PID > "$BOOTSTRAP_DIR/node.pid"
  echo "Bootstrap node started with PID $BOOTSTRAP_PID"
  
  # Wait for bootstrap node to start
  sleep 5
  
  # Start regular nodes
  for i in $(seq 1 $NODE_COUNT); do
    NODE_DIR="$DATA_DIR/node$i"
    mkdir -p "$NODE_DIR"
    
    API_PORT=$((8000 + $i))
    P2P_PORT=$((9000 + $i))
    SSH_PORT=$((2222 + $i - 1))
    
    echo "Starting node $i..."
    ./spectrum-node \
      --datadir="$NODE_DIR" \
      --addr=:$P2P_PORT \
      --api=:$API_PORT \
      --bootstrap=127.0.0.1:9000 \
      --mine \
      --vm \
      --ssh \
      --ssh-port=$SSH_PORT > "$NODE_DIR/node.log" 2>&1 &
    
    NODE_PID=$!
    echo $NODE_PID > "$NODE_DIR/node.pid"
    echo "Node $i started with PID $NODE_PID"
    
    # Wait for node to start
    sleep 2
  done
  
  echo ""
  echo "All nodes started!"
  echo ""
  echo "Access nodes with:"
  echo "  Bootstrap node API: http://localhost:8000"
  for i in $(seq 1 $NODE_COUNT); do
    API_PORT=$((8000 + $i))
    SSH_PORT=$((2222 + $i - 1))
    echo "  Node $i API: http://localhost:$API_PORT"
    echo "  Node $i SSH (to global VM): ssh -p $SSH_PORT spectrum@localhost"
  done
  
  echo ""
  echo "Use wallet with:"
  echo "  ./spectrum-wallet --wallet=$DATA_DIR/wallet.dat shell"
  
  # Create a stop script
  cat > stop.sh <<EOL
#!/bin/bash
# Stop all Spectrum Chain nodes

if [ -f "$BOOTSTRAP_DIR/node.pid" ]; then
  BOOTSTRAP_PID=\$(cat "$BOOTSTRAP_DIR/node.pid")
  echo "Stopping bootstrap node (PID \$BOOTSTRAP_PID)..."
  kill \$BOOTSTRAP_PID 2>/dev/null || true
  rm "$BOOTSTRAP_DIR/node.pid"
fi

for i in \$(seq 1 $NODE_COUNT); do
  NODE_DIR="$DATA_DIR/node\$i"
  if [ -f "\$NODE_DIR/node.pid" ]; then
    NODE_PID=\$(cat "\$NODE_DIR/node.pid")
    echo "Stopping node \$i (PID \$NODE_PID)..."
    kill \$NODE_PID 2>/dev/null || true
    rm "\$NODE_DIR/node.pid"
  fi
done

echo "All nodes stopped."
EOL
  
  chmod +x stop.sh
  echo ""
  echo "Created stop.sh script to stop all nodes."
fi

echo ""
echo "Setup complete!"