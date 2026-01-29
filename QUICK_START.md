# Quick Start Guide

## Prerequisites

- Rust toolchain (install from https://rustup.rs/)
- Redis server (for rate limiting)

## Step 1: Install Dependencies

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Install Redis (macOS)
brew install redis

# Install Redis (Ubuntu/Debian)
sudo apt-get install redis-server
```

## Step 2: Start Redis

```bash
# Start Redis server
redis-server

# Or run in background
redis-server --daemonize yes
```

## Step 3: Build and Test

```bash
# Run the test script
./run_tests.sh

# Or manually:
cargo build --release
cargo test
```

## Step 4: Configure Environment

```bash
export REDIS_URL=redis://127.0.0.1:6379/
export GATEWAY_CONFIG_PATH=config/config.yaml
export JWT_SECRET=test-secret-key-change-in-production
export RUST_LOG=info
```

## Step 5: Run the Gateway

```bash
# Run the gateway
./target/release/rust-flux

# Or with cargo
cargo run --release
```

## Step 6: Test the Gateway

In another terminal:

```bash
# Health check
curl http://localhost:8080/healthz

# Metrics endpoint
curl http://localhost:8080/metrics

# Test proxy (requires upstream configured in config.yaml)
curl http://localhost:8080/api/v1/test
```

## Using Docker Compose

```bash
# Build and start all services
docker-compose up --build

# Test endpoints
curl http://localhost:8080/healthz
curl http://localhost:8080/metrics

# Stop services
docker-compose down
```

## Troubleshooting

### Redis Connection Error
- Make sure Redis is running: `redis-cli ping`
- Check REDIS_URL environment variable

### Config File Not Found
- Verify GATEWAY_CONFIG_PATH points to correct file
- Check that config/config.yaml exists

### Port Already in Use
- Change `listen_addr` in config.yaml
- Or stop the service using port 8080
