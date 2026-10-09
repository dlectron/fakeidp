# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
# Builder and runtime deliberately share the same Debian release. The binary
# links the distribution's glibc dynamically, so a builder from a different
# distro (or a CI convenience image) produces something that only fails once
# the container starts. The Debian cross toolchains below link against that
# same release's glibc, so this holds for cross builds too.
#
# The builder always runs on the build host's own platform and cross-compiles
# for the target. Compiling arm64 under QEMU emulation took close to an hour
# and ran the multi-arch publish into CircleCI's job time limit.
FROM --platform=$BUILDPLATFORM rust:1.98-trixie AS cargo-build

ARG BUILDPLATFORM
ARG TARGETPLATFORM

# Pick the Rust target and, when it differs from the host, install its C cross
# toolchain (ring and zstd-sys need one) and tell cargo which compiler and
# linker to use. Debian names the package gcc-x86-64-linux-gnu but the tool it
# installs x86_64-linux-gnu-gcc, hence the separate pkg and gcc names.
RUN case "$TARGETPLATFORM" in \
      linux/amd64) triple=x86_64-unknown-linux-gnu;  pkg=x86-64;  gcc=x86_64-linux-gnu-gcc;  arch=amd64 ;; \
      linux/arm64) triple=aarch64-unknown-linux-gnu; pkg=aarch64; gcc=aarch64-linux-gnu-gcc; arch=arm64 ;; \
      *) echo "unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac \
    && echo "$triple" > /rust-target \
    && touch /cargo-env \
    && if [ "$TARGETPLATFORM" != "$BUILDPLATFORM" ]; then \
         apt-get update \
         && apt-get install -y --no-install-recommends gcc-${pkg}-linux-gnu libc6-dev-${arch}-cross \
         && rm -rf /var/lib/apt/lists/* \
         && rustup target add "$triple" \
         && printf 'export CARGO_TARGET_%s_LINKER=%s\nexport CC_%s=%s\n' \
              "$(echo "$triple" | tr a-z- A-Z_)" "$gcc" "$(echo "$triple" | tr - _)" "$gcc" > /cargo-env; \
       fi

WORKDIR /usr/src/fakeidp

# Compile the dependency graph on its own layer, against a stub main.rs, so that
# editing sources does not rebuild every crate. Cargo builds everything in
# [dependencies] here regardless of what the stub actually uses.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN . /cargo-env && cargo build --release --locked --target "$(cat /rust-target)"

# The real sources. Cargo decides by mtime and COPY preserves the context's, so
# touch the entrypoint to be sure the stub's artifact is not reused. The binary
# is copied to a fixed path so the final stage need not know the target triple.
COPY . .
RUN touch src/main.rs \
    && . /cargo-env \
    && cargo build --release --locked --target "$(cat /rust-target)" \
    && cp "target/$(cat /rust-target)/release/fakeidp" /usr/local/bin/fakeidp

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM debian:trixie-slim

# `ldd` on the built binary shows only libc/libm/libgcc: reqwest resolves to
# rustls and the unused openssl crate is no longer a dependency, so no OpenSSL
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
COPY --from=cargo-build --chown=root:root --chmod=755 /usr/local/bin/fakeidp /usr/local/bin/fakeidp

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

# Optional: a folder with custom.css, logo.<ext> and/or background.<ext> to
# restyle the login screen, served under /styling. Read by the binary itself,
# like USERS; empty means the built-in look.
ENV STYLING=""

# exec so the service replaces the shell and becomes PID 1: without it SIGTERM
# stops at /bin/sh and every `docker stop` waits out the full timeout.
CMD ["sh", "-c", "exec fakeidp /usr/local/etc/private_key.der -p ${PORT} -b ${BIND} -e ${EXPOSED_HOST} -f /usr/local/fakeidp/static"]
