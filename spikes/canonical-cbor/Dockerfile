# Build and test image for the E19 spike: Debian 13 (trixie), the spine's Rust line, and a
# pinned Node whose ICU carries the same Unicode version as the Rust NFC tables (see run.sh).
# node:22.23.2-trixie-slim and rust:1.99-trixie, pinned by digest.
FROM node@sha256:c5849ff9c9ebcd66615412f0b548ca5b8ecaef84003dc9ac2e077ebe46aaa3f6 AS node
FROM rust@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && rustup component add clippy rustfmt
