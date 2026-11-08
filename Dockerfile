# Build stage
FROM rust:slim AS builder

WORKDIR /app

# Copy the source code
COPY Cargo.toml Cargo.lock* ./
COPY src src
COPY static static

RUN set -x \
    && apt update \
    && DEBIAN_FRONTEND=noninteractive apt install -y build-essential ca-certificates pkg-config libssl-dev git --no-install-recommends \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/*

# Build the release binary
RUN cargo build --release

# Runtime stage
FROM ghcr.io/studyfranco/docker-baseimages-debian:testing

RUN set -x \
    && apt update \
    && apt dist-upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt install -y ca-certificates libsqlite3-0 curl --no-install-recommends \
    && apt autopurge -yy \
    && apt clean autoclean -y \
    && rm -rf /var/cache/* /var/lib/apt/lists/* /var/log/* /var/tmp/* /tmp/* \
    && mkdir -p /app

WORKDIR /app

# Copy the binary and static files
COPY --from=builder /app/target/release/simply_ip_vault /usr/local/bin/simply_ip_vault
COPY static /app/static

# Expose API/Frontend port
EXPOSE 3000

# Default environment configuration
ENV DATABASE_URL=sqlite://data/simply_ip_vault.db?mode=rwc
ENV RUST_LOG=info
ENV ALLOW_PRIVATE_WEBHOOKS=false

# Readiness, not liveness.
#
# Docker's HEALTHCHECK is what `depends_on: condition: service_healthy` waits on and what an
# orchestrator uses to take a container out of rotation, so the useful question is "can this instance
# serve a request?" rather than "is the process alive?". `/ready` proves the database answers and the
# Master identity is pinned; `/health` would answer 200 for a process that could do neither.
#
# `--start-period` covers migrations and the master pin on first boot, which run before the listener
# binds — during that window a probe failure is expected and must not count against the container.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -fsS http://127.0.0.1:3000/ready || exit 1

# Define command
CMD ["simply_ip_vault"]
