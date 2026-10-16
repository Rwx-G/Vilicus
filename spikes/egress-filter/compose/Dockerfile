# One runtime image for every service of the E14 test network: the proxy, the scripted resolver,
# the fake upstreams (nginx), the client and the systemd sandbox. Both stages are pinned by
# digest; Debian package versions are printed by run.sh at each run.

# rust:1.99-trixie, rustc 1.99.1, the same toolchain as the cargo gates. The test-network feature
# lets the proxy treat the documentation ranges of the simulated internet as public.
FROM rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked --bins --features test-network \
    && mkdir /out \
    && cp target/release/egress-proxy target/release/egress-resolver target/release/egress-probe /out/

# debian:trixie-slim (Debian 13), the product's server platform.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       systemd systemd-sysv dbus curl ca-certificates socat iproute2 openssl python3 nginx-light \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 1000 --user-group --no-create-home egress \
    && for entry in core:2000 plugin-a:2001 plugin-b:2002 backup:2003 misconfigured:2004; do \
         useradd --uid "${entry#*:}" --user-group --no-create-home "${entry%:*}"; \
       done
COPY --from=build /out/ /usr/local/bin/
COPY compose/certs.sh /usr/local/lib/egress-test/certs.sh
RUN sh /usr/local/lib/egress-test/certs.sh /etc/egress-test
COPY compose/proxy.conf compose/zone.txt compose/nginx-allowed.conf compose/nginx-forbidden.conf \
     compose/nginx-internal.conf compose/ws_backend.py /etc/egress-test/
COPY compose/entrypoint.sh /usr/local/bin/entrypoint.sh
ENTRYPOINT ["sh", "/usr/local/bin/entrypoint.sh"]
