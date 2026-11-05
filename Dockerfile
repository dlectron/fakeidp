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
#
# The slim variant has the C toolchain the native dependencies (ring, aws-lc-sys,
# zstd-sys) need and little else, which keeps the builder's vulnerability
# count a fraction of the full image's. Nothing from this stage ships.
FROM --platform=$BUILDPLATFORM rust:1.98-slim-trixie AS cargo-build

ARG BUILDPLATFORM
ARG TARGETPLATFORM

# Pick the Rust target and, when it differs from the host, install its C cross
# toolchain and tell cargo which compiler and linker to use. Debian names the
# package gcc-x86-64-linux-gnu but the tool it installs x86_64-linux-gnu-gcc,
# hence the separate pkg and gcc names.
#
# The upgrade picks up the Debian security fixes published since the rust image
# was last rebuilt; scanners otherwise report those against this stage.
RUN case "$TARGETPLATFORM" in \
      linux/amd64) triple=x86_64-unknown-linux-gnu;  pkg=x86-64;  gcc=x86_64-linux-gnu-gcc;  arch=amd64 ;; \
      linux/arm64) triple=aarch64-unknown-linux-gnu; pkg=aarch64; gcc=aarch64-linux-gnu-gcc; arch=arm64 ;; \
      *) echo "unsupported TARGETPLATFORM: $TARGETPLATFORM" >&2; exit 1 ;; \
    esac \
    && echo "$triple" > /rust-target \
    && touch /cargo-env \
    && apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && if [ "$TARGETPLATFORM" != "$BUILDPLATFORM" ]; then \
         apt-get install -y --no-install-recommends gcc-${pkg}-linux-gnu libc6-dev-${arch}-cross \
         && rustup target add "$triple" \
         && printf 'export CARGO_TARGET_%s_LINKER=%s\nexport CC_%s=%s\n' \
              "$(echo "$triple" | tr a-z- A-Z_)" "$gcc" "$(echo "$triple" | tr - _)" "$gcc" > /cargo-env; \
       fi \
    && rm -rf /var/lib/apt/lists/*

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

# The key's directory is laid out here, with the modes it must end up with,
# because the runtime image has no shell to fix them up in and `COPY --chmod`
# would apply the key's 0440 to any parent directory it has to create as well.
# A directory without its execute bit cannot be entered, so the service would
# fail to open the key. Debian happened to ship /usr/local/etc; distroless
# does not.
RUN install -d -m 755 /out/etc \
    && install -m 440 keys/private_key.der /out/etc/private_key.der

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

# Distroless: Debian 13's glibc, libgcc, ca-certificates and tzdata, and nothing
# else. No shell, no package manager, no apt database for a scanner to report
# against, which is what takes the image's vulnerability count to zero. The
# same Debian release as the builder, so the dynamically linked glibc matches.
#
# `ldd` on the built binary shows only libc/libm/libgcc: reqwest resolves to
# rustls and the unused openssl crate is no longer a dependency, so no OpenSSL
# runtime is required and the `cc` flavour (rather than `base`) is enough.
#
# The image ships the `nonroot` account (uid and gid 65532) ready-made, in
# place of the `runtme` user the Debian image used to create.
FROM gcr.io/distroless/cc-debian13:nonroot

# Everything the service reads stays owned by root and is only readable to the
# account that runs it, so a compromised process cannot rewrite its own binary,
# its signing key or the pages it serves.
COPY --from=cargo-build --chown=root:root --chmod=755 /usr/local/bin/fakeidp /usr/local/bin/fakeidp

# Copied as a directory, so the 0755 on it and the 0440 on the key both come
# from the builder's layout above; --chown resolves `nonroot` against this
# image's /etc/group.
COPY --from=cargo-build --chown=root:nonroot /out/etc/ /usr/local/etc/

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

USER nonroot

EXPOSE 8080

# The binary reads these three itself (clap `env`), so CMD needs no shell to
# turn them into flags. Explicit flags on the command line still win. The
# prefix keeps a PORT or BIND set by the environment from being picked up.
ENV FAKE_BIND="0.0.0.0"

ENV FAKE_PORT="8080"

ENV EXPOSED_HOST="http://localhost:8080"

# Optional: a JSON file, or a folder of *.json files, with the users to offer on
# the login screen. The binary reads USERS itself, so CMD needs no flag for it;
# empty means the manual login form. See examples/docker-compose.yml.
ENV USERS=""

# Optional: a folder with custom.css, logo.<ext> and/or background.<ext> to
# restyle the login screen, served under /styling. Read by the binary itself,
# like USERS; empty means the built-in look.
ENV STYLING=""

# Optional: a JSON file, or a folder of *.json files, with the clients of the
# client credentials and token exchange grants: their claims, allowed flows and
# allowed resources. Read by the binary itself, like USERS; empty means every
# client is allowed everything with default claims.
ENV CLIENTS=""

# Exec form, and there is no shell in the image anyway: the service is PID 1 and
# gets SIGTERM directly, so `docker stop` returns at once instead of waiting
# out the timeout behind a /bin/sh.
CMD ["fakeidp", "/usr/local/etc/private_key.der", "-f", "/usr/local/fakeidp/static"]
