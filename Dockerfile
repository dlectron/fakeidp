# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

FROM rust:1.89-bookworm as cargo-build

RUN apt-get update

WORKDIR /usr/src/fakeidp

COPY Cargo.toml Cargo.toml

RUN mkdir src/

RUN echo "fn main() {println!(\"if you see this, the build broke\")}" > src/main.rs

COPY . .

RUN cargo build --release

# RUN cargo install --path .

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM debian:bookworm-slim

RUN apt-get update && rm -rf /var/lib/apt/lists/*

RUN addgroup --system -gid 1000 runtme

RUN adduser --system --disabled-login --shell /bin/sh -uid 1001 --ingroup runtme runtme

COPY --from=cargo-build /usr/src/fakeidp/target/release/fakeidp /usr/local/bin/fakeidp

COPY --from=cargo-build /usr/src/fakeidp/keys/private_key.der /usr/local/etc/private_key.der

RUN mkdir -p "/usr/local/fakeidp/static"

COPY --from=cargo-build /usr/src/fakeidp/static/* /usr/local/fakeidp/static/

RUN chown runtme:runtme /usr/local/bin/fakeidp

USER runtme

ENV BIND="0.0.0.0"

ENV PORT="8080"

ENV EXPOSED_HOST="http://localhost:8080"

CMD ["sh", "-c", "fakeidp /usr/local/etc/private_key.der -p ${PORT} -b ${BIND} -e ${EXPOSED_HOST} -f /usr/local/fakeidp/static"]
