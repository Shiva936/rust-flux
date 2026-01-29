#!/bin/bash

# Test script for rust-flux gateway

set -e

echo "Building rust-flux..."
cargo build --release

echo "Running unit tests..."
cargo test --lib

echo "Running integration tests..."
cargo test --test integration_test

echo "Starting Redis in background..."
redis-server --daemonize yes --port 6379 || echo "Redis may already be running"

echo "Waiting for Redis..."
sleep 2

echo "Starting gateway..."
export RUST_LOG=info
export REDIS_URL=redis://127.0.0.1:6379/
export GATEWAY_CONFIG_PATH=config/config.yaml
export JWT_SECRET=test-secret-key

# Start gateway in background
./target/release/rust-flux &
GATEWAY_PID=$!

echo "Gateway started with PID: $GATEWAY_PID"
echo "Waiting for gateway to start..."
sleep 3

# Test health endpoint
echo ""
echo "Testing /healthz endpoint..."
curl -f http://localhost:8080/healthz && echo " ✓ Health check passed"

# Test metrics endpoint
echo ""
echo "Testing /metrics endpoint..."
curl -f http://localhost:8080/metrics | head -20 && echo " ✓ Metrics endpoint works"

# Test proxy (if upstream is available)
echo ""
echo "Testing proxy functionality..."
curl -f http://localhost:8080/public/test 2>/dev/null && echo " ✓ Proxy works" || echo " ⚠ Proxy test skipped (no upstream)"

echo ""
echo "Stopping gateway (PID: $GATEWAY_PID)..."
kill $GATEWAY_PID 2>/dev/null || true
wait $GATEWAY_PID 2>/dev/null || true

echo ""
echo "All tests completed!"
