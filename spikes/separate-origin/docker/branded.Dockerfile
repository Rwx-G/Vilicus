# Mozilla's own Firefox builds (not Playwright's patched Firefox) for the passive-fixture rerun of
# E26, driven by geckodriver over WebDriver. Same pins as the E24 spike (spikes/naming-options):
# Firefox 158.0 (the current release on 2026-10-16) and 157.0.1 (the previous release) from
# Mozilla's archive, whose SHA256SUMS list the same hashes, and geckodriver 0.37.1. The base
# image is the Playwright image already used here, for Node and the system libraries only.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:7852dc5a7d72f5fe458a597d690f6c42fbc8e9e26ddfa95f8e6ef552558d9bbf

RUN apt-get update \
 && apt-get install --yes --no-install-recommends libnss3-tools xz-utils \
 && apt-get clean \
 && find /var/lib/apt/lists -type f -delete

ADD --checksum=sha256:9549b054ec4cf85f50f6a19d8c6fb79580312e71ebc4ec2cb217ec9af09dc12a \
    https://archive.mozilla.org/pub/firefox/releases/158.0/linux-x86_64/en-US/firefox-158.0.tar.xz /tmp/firefox-158.tar.xz
ADD --checksum=sha256:0d92bf39cdd174f5f361008509310bdefbce72a57ca10523a43b32d62dc699b6 \
    https://archive.mozilla.org/pub/firefox/releases/157.0.1/linux-x86_64/en-US/firefox-157.0.1.tar.xz /tmp/firefox-157.tar.xz
ADD --checksum=sha256:e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e \
    https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-linux64.tar.gz /tmp/geckodriver.tar.gz

RUN set -e; cd /opt \
 && for v in 158 157; do mkdir -p firefox-$v && tar -xJf /tmp/firefox-$v.tar.xz -C firefox-$v; done \
 && tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin geckodriver \
 && find /tmp -maxdepth 1 -type f -name '*.tar.*' -delete
WORKDIR /app
