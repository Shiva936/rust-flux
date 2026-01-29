#!/bin/bash

set -e

echo "=========================================="
echo "Rust-Flux Gateway - Build and Test"
echo "=========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo is not installed${NC}"
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

echo -e "${GREEN}✓${NC} Cargo found: $(cargo --version)"
echo ""

# Build the project
echo "Building rust-flux..."
if cargo build --release; then
    echo -e "${GREEN}✓${NC} Build successful"
else
    echo -e "${RED}✗${NC} Build failed"
    exit 1
fi
echo ""

# Run unit tests
echo "Running unit tests..."
if cargo test --lib -- --nocapture; then
    echo -e "${GREEN}✓${NC} Unit tests passed"
else
    echo -e "${RED}✗${NC} Unit tests failed"
    exit 1
fi
echo ""

# Run integration tests (these use an in-process mock upstream)
echo "Running integration tests..."
if cargo test --test integration_test -- --nocapture; then
    echo -e "${GREEN}✓${NC} Integration tests passed"
else
    echo -e "${RED}✗${NC} Integration tests failed"
    exit 1
fi
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}All tests completed successfully!${NC}"
echo "=========================================="
echo ""
echo "To run the gateway:"
echo "  1. Start Redis: redis-server"
echo "  2. Set environment variables:"
echo "     export REDIS_URL=redis://127.0.0.1:6379/"
echo "     export GATEWAY_CONFIG_PATH=config/config.yaml"
echo "     export JWT_SECRET=test-secret-key"
echo "     export RUST_LOG=info"
echo "  3. Run: ./target/release/rust-flux"
echo ""
echo "Or use Docker Compose:"
echo "  docker-compose up --build"
echo ""
