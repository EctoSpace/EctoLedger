# ── Stage 1: Build ────────────────────────────────────────────────────
FROM rust:1.94-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Stub out the GUI crate so the workspace compiles without Node/Tauri deps.
COPY gui/src-tauri/Cargo.toml gui/src-tauri/Cargo.toml
RUN mkdir -p gui/src-tauri/src && echo "fn main(){}" > gui/src-tauri/src/main.rs

RUN cargo build --release -p ectoledger --no-default-features --features sandbox,evm \
    && strip target/release/ectoledger

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libssl3 curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ectoledger /usr/local/bin/ectoledger

# Default config — overridden by docker-compose environment.
ENV RUST_LOG=info \
    ECTO_BIND_HOST=0.0.0.0 \
    ECTO_BIND_PORT=3000 \
    ECTO_DEV_MODE=true \
    GUARD_REQUIRED=false

EXPOSE 3000

ENTRYPOINT ["ectoledger"]
CMD ["serve"]
