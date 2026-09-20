FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/

RUN cargo build --release -p fuin_controller

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --no-create-home --shell /usr/sbin/nologin fuin

COPY --from=builder /app/target/release/fuin_controller /usr/local/bin/fuin-controller
RUN chown fuin:fuin /usr/local/bin/fuin-controller

USER fuin
ENTRYPOINT ["/usr/local/bin/fuin-controller"]
