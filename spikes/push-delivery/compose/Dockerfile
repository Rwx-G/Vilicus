# Runtime image of the E13 test network: the sender and collector (`core`) and the simulated
# phones. Both stages are pinned by digest; run.sh prints the Debian package versions it uses.

# rust:1.99-trixie, rustc 1.99.1, the same toolchain as the cargo gates.
FROM rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bin push-delivery \
    && mkdir /out \
    && cp target/release/push-delivery /out/

# debian:trixie-slim (Debian 13), the product's server platform. curl is there for the access
# checks run.sh makes against the push servers.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates
COPY --from=build /out/push-delivery /usr/local/bin/push-delivery
COPY compose/sim.conf /etc/push-delivery/sim.conf
