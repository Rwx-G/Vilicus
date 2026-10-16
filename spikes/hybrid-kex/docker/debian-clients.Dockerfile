# curl and the OpenSSL command line from a Debian release's own packages. BASE is a Debian image
# pinned by digest in compose.yaml; the package versions are printed by each run, not pinned here.
ARG BASE
FROM ${BASE}
RUN apt-get update \
    && apt-get install --yes --no-install-recommends curl openssl ca-certificates \
    && apt-get clean \
    && find /var/lib/apt/lists -mindepth 1 -delete
