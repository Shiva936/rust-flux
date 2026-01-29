# Build stage
FROM rust:1.75-slim as builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/rust-flux /usr/local/bin/rust-flux

# Create config directory
RUN mkdir -p /app/config

# Expose default port
EXPOSE 8080

# Set default config path
ENV GATEWAY_CONFIG_PATH=/app/config/config.yaml
ENV RUST_LOG=info

# Run the gateway
CMD ["rust-flux"]
