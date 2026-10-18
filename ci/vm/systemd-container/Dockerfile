# Privileged systemd container of the CI VM harness (ci/vm/README.md): Debian 13 (trixie) with
# systemd as PID 1, booted inside the Debian 13 guest the way the E10 and E14 spikes boot theirs.
# The base is debian:trixie-slim as pulled on 2026-10-16, pinned by digest (the digest
# spikes/sandbox-profile and e2e/vm use); the packages come from the trixie archive on the day of
# the build.
#
# systemd-sysctl.service is masked, and ci/test_vm_harness.py fails any Dockerfile under ci/vm/
# whose container boots an init without that mask: the container is privileged, so /proc/sys is the
# guest's, and Debian's 10-coredump-debian.conf would replace the guest's systemd-coredump pipe
# in kernel.core_pattern with "core" until the next boot (Story 1.6, "Debian 13 VM run"; gates
# E10-4 and E16-4). The harness also compares core_pattern before and after the run.
#
# It runs as root by necessity: systemd as PID 1. It is a disposable test fixture inside a
# disposable VM, never a service image.
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
LABEL org.opencontainers.image.title="vilicus-ci-systemd" \
      org.opencontainers.image.description="Privileged systemd container of the Vilicus CI VM harness" \
      org.opencontainers.image.source="https://github.com/Rwx-G/Vilicus" \
      org.opencontainers.image.licenses="Apache-2.0"
# DL3008: the trixie archive keeps only the current version of a package, so a pinned version
# stops installing at the next point release; the digest pins the base, as in e2e/vm.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get install --yes --no-install-recommends systemd systemd-sysv \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && systemctl mask systemd-sysctl.service
ENV container=docker
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/sbin/init"]
