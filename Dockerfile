# Dockerfile for Spectrum Chain node
FROM golang:1.19-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache git build-base

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the node and wallet binaries
RUN go build -o spectrum-node cmd/node/main.go
RUN go build -o spectrum-wallet cmd/wallet/main.go

# Use a smaller base image for the final image
FROM alpine:3.16

WORKDIR /app

# Install runtime dependencies for VM functionality
RUN apk add --no-cache \
    qemu-img \
    qemu-system-x86_64 \
    libvirt-client \
    openssh-server \
    openssl \
    ca-certificates \
    bash \
    curl \
    jq

# Copy binaries from builder stage
COPY --from=builder /app/spectrum-node /app/spectrum-node
COPY --from=builder /app/spectrum-wallet /app/spectrum-wallet

# Create data directory
RUN mkdir -p /app/data

# Expose ports
# P2P networking
EXPOSE 9000
# HTTP API
EXPOSE 8000
# SSH access to VM
EXPOSE 2222

# Set up entry point script
COPY scripts/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node"]