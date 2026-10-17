# Host container for the Debian 13 e2e VM: QEMU with KVM boots the pinned Debian cloud image
# (IMAGE.lock) on a copy-on-write overlay. The base is debian:trixie-slim as pulled on
# 2026-10-16, pinned by digest (the digest spikes/sandbox-profile uses); the packages come from
# the trixie archive on the day of the build and `vm.sh info` prints their versions.
#
# A local test harness, not a service: it runs as root because the /dev/kvm node passed in with
# --device carries the engine's group, which differs between Docker Desktop and Linux hosts.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
LABEL org.opencontainers.image.title="vilicus-vm-host" \
      org.opencontainers.image.description="QEMU host for the Vilicus Debian 13 e2e VM" \
      org.opencontainers.image.source="https://github.com/Rwx-G/Vilicus" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      ca-certificates cloud-image-utils curl openssh-client qemu-system-x86 qemu-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /vm
COPY IMAGE.lock entrypoint.sh /vm/
ENTRYPOINT ["/bin/bash", "/vm/entrypoint.sh"]
