# rust-flux

High-Performance Async API Gateway in Rust

A production-grade async API Gateway built with Axum, featuring reverse proxying, JWT authentication, Redis-based rate limiting, comprehensive observability, and declarative configuration.

## Features

- **Reverse Proxy**: Route requests to multiple upstream services with path rewriting and method filtering
- **JWT Authentication**: Configurable JWT validation with HS256/RS256 support, issuer/audience checks, and scope validation
- **Rate Limiting**: Redis-backed distributed rate limiting with configurable policies per route/client
- **Observability**: Structured logging with tracing, Prometheus metrics endpoint, and distributed tracing support
- **Hot Reload**: Configuration hot-reload via file watching or SIGHUP
- **Graceful Shutdown**: Configurable graceful shutdown with drain timeout
- **Production Ready**: Docker support, health checks, and comprehensive error handling

## Quick Start

### Using Docker Compose

```bash
# Start all services (gateway, Redis, mock upstreams)
docker-compose up -d

# Check gateway health
curl http://localhost:8080/healthz

# View metrics
curl http://localhost:8080/metrics
```

### Configuration

The gateway uses a YAML configuration file (default: `config/config.yaml`). Example:

```yaml
server:
  listen_addr: "0.0.0.0:8080"
  shutdown_grace_period_secs: 30

metrics:
  path: "/metrics"

auth_policies:
  - name: "default"
    algorithm: "HS256"
    issuer: "gateway"
    audiences: []
    required_scopes: []
    key_id: null

upstreams:
  - name: "api-service"
    base_url: "http://api:8080"
    timeout_ms: 5000
    retry:
      attempts: 2
      backoff_ms: 100

routes:
  - id: "api-route"
    match_path:
      prefix: "/api"
    methods: ["GET", "POST"]
    upstream: "api-service"
    auth_policy: "default"
    rate_limit: "api-limit"

rate_limits:
  - name: "api-limit"
    limit_per_minute: 60
    burst: 10
    key:
      - "client_ip"
      - "route_path"
```

### Environment Variables

- `GATEWAY_CONFIG_PATH`: Path to config file (default: `config/config.yaml`)
- `REDIS_URL`: Redis connection URL (default: `redis://127.0.0.1:6379/`)
- `RUST_LOG`: Log level (default: `info`)
- `JWT_SECRET`: Default JWT secret for HS256 (or `JWT_KEY_{POLICY_NAME}` for per-policy keys)

## Building

```bash
# Build release binary
cargo build --release

# Run tests
cargo test

# Run integration tests
cargo test --test integration_test
```

## Running

### Prerequisites

- Rust toolchain (install from https://rustup.rs/)
- Redis server (for rate limiting)

### Quick Start

1. **Start Redis** (if not already running):
   ```bash
   redis-server
   ```

2. **Set environment variables**:
   ```bash
   export REDIS_URL=redis://127.0.0.1:6379/
   export GATEWAY_CONFIG_PATH=config/config.yaml
   export JWT_SECRET=your-secret-key-here
   export RUST_LOG=info
   ```

3. **Run the gateway**:
   ```bash
   cargo run --release
   ```

4. **Test the gateway**:
   ```bash
   # Health check
   curl http://localhost:8080/healthz

   # Metrics
   curl http://localhost:8080/metrics

   # Proxy request (requires upstream service)
   curl http://localhost:8080/api/v1/test
   ```

### Using Docker Compose

```bash
# Build and start all services
docker-compose up --build

# In another terminal, test the gateway
curl http://localhost:8080/healthz
```

## Architecture

The gateway follows a layered middleware architecture:

1. **Request ID / Tracing Layer**: Generates request IDs and trace spans
2. **Logging Layer**: Structured request/response logging
3. **Metrics Layer**: Prometheus metrics collection
4. **Routing Layer**: Resolves routes from configuration
5. **Auth Layer**: JWT validation (if required by route)
6. **Rate Limit Layer**: Redis-backed rate limiting
7. **Proxy Handler**: Forwards requests to upstream services

## Development

### Project Structure

```
src/
├── main.rs          # Entry point and server setup
├── config.rs        # Configuration loading and hot-reload
├── server.rs        # Router and endpoint setup
├── proxy.rs         # Reverse proxy logic
├── auth.rs          # JWT authentication
├── rate_limit.rs    # Rate limiting with Redis
└── observability.rs # Logging and metrics
```

### Testing

Unit tests are included in each module. Integration tests verify end-to-end proxy flows:

```bash
cargo test --test integration_test
```

## License

MIT
