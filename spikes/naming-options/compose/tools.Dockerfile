# Runtime image of the E24 spike: the test instances (the spike binary, which links libssl), the
# DNS servers (dnsmasq), the certificate authorities (openssl) and the DNS checks (dig).
# debian:trixie-slim pinned by digest.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
 && apt-get install --yes --no-install-recommends bind9-dnsutils ca-certificates dnsmasq-base libssl3t64 openssl \
 && apt-get clean \
 && find /var/lib/apt/lists -type f -delete
