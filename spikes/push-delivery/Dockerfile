# Build and test image for the E13 spike's cargo gates: Debian 13 (trixie) and the spine's Rust
# line. Pinned by digest so a moved tag cannot change the toolchain under a recorded result
# (rust:1.99-trixie, rustc 1.99.1).
FROM rust:1.99-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a
RUN rustup component add clippy rustfmt
