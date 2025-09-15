# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM rust:1.82-bookworm AS builder
ARG BIN_NAME=proxy-forwarder
WORKDIR /app

# System deps for building (OpenSSL, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates build-essential \
 && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main(){println!("cache");}' > src/main.rs
RUN cargo build --release --locked || true
RUN rm -rf src

# Copy source and build the actual binary
COPY . .
RUN cargo build --release --locked --bin "${BIN_NAME}"

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime
ARG BIN_NAME=proxy-forwarder
WORKDIR /app

# Runtime deps (OpenSSL and certs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*

# Non-root user
RUN useradd -m -u 10001 appuser

# Copy binary and set permissions
COPY --from=builder /app/target/release/${BIN_NAME} /usr/local/bin/app
COPY --from=builder /app/.env /usr/local/bin/.env
RUN chown appuser:appuser /usr/local/bin/app && chmod 0755 /usr/local/bin/app

USER appuser
ENV RUST_LOG=info
EXPOSE 8080

# If your binary listens on another port, update EXPOSE or remove it.
CMD ["/usr/local/bin/app"]
