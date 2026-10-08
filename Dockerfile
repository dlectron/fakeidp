# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
# Builder and runtime deliberately share the same Debian release. The binary
# links the distribution's glibc and OpenSSL dynamically, so a builder from a
# different distro (or a CI convenience image) produces something that only
# fails once the container starts.
FROM rust:1.98-trixie AS cargo-build

WORKDIR /usr/src/fakeidp

# Compile the dependency graph on its own layer, against a stub main.rs, so that
# editing sources does not rebuild every crate. Cargo builds everything in
# [dependencies] here regardless of what the stub actually uses.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --locked

# The real sources. Cargo decides by mtime and COPY preserves the context's, so
# touch the entrypoint to be sure the stub's artifact is not reused.
COPY . .
RUN touch src/main.rs && cargo build --release --locked

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM debian:trixie-slim

# `ldd` on the built binary shows only libc/libm/libgcc: reqwest resolves to
# rustls and nothing in the source touches the openssl crate, so no OpenSSL
# runtime is required. ca-certificates is kept as the one cheap insurance
# against a future outbound TLS call failing in a confusing way.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 1000 runtme \
    && useradd --system --uid 1001 --gid runtme --shell /usr/sbin/nologin --no-create-home runtme

# Everything the service reads stays owned by root and is only readable to the
# account that runs it, so a compromised process cannot rewrite its own binary,
# its signing key or the pages it serves.
COPY --from=cargo-build --chown=root:root --chmod=755 /usr/src/fakeidp/target/release/fakeidp /usr/local/bin/fakeidp

COPY --from=cargo-build --chown=root:runtme --chmod=440 /usr/src/fakeidp/keys/private_key.der /usr/local/etc/private_key.der

# No --chmod here: it would apply to the directory as well as the files, and a
# static dir without its execute bit cannot be traversed, so nothing under
# /static would be servable.
COPY --from=cargo-build --chown=root:root /usr/src/fakeidp/static/ /usr/local/fakeidp/static/

# CircleCI passes both of these on every publish; without the ARGs they were
# accepted and silently discarded, so the published images carried no provenance.
ARG VERSION="dev"
ARG COMMITID="unknown"

LABEL org.opencontainers.image.title="fakeidp" \
      org.opencontainers.image.description="OIDC compatible fake IdP for testing: issues any token it is asked for" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMITID}" \
      org.opencontainers.image.source="https://github.com/dlectron/fakeidp" \
      org.opencontainers.image.licenses="Apache-2.0"

USER runtme

EXPOSE 8080

ENV BIND="0.0.0.0"

ENV PORT="8080"

ENV EXPOSED_HOST="http://localhost:8080"

# Optional: a JSON file, or a folder of *.json files, with the users to offer on
# the login screen. The binary reads USERS itself, so CMD needs no flag for it;
# empty means the manual login form. See examples/docker-compose.yml.
ENV USERS=""

# exec so the service replaces the shell and becomes PID 1: without it SIGTERM
# stops at /bin/sh and every `docker stop` waits out the full timeout.
CMD ["sh", "-c", "exec fakeidp /usr/local/etc/private_key.der -p ${PORT} -b ${BIND} -e ${EXPOSED_HOST} -f /usr/local/fakeidp/static"]
