# Browser image of the E24 spike. Base: the official Playwright image v1.64.1-noble, pinned by
# digest, for the system libraries and the Playwright npm package that drives Chrome over CDP.
# The browsers under test are not Playwright's own builds (its Chromium 156 is ahead of Chrome
# stable, and its Firefox carries Playwright's patches); they are the vendors' builds, each
# pinned by SHA-256:
# - Chrome for Testing 155.0.8059.84 (the Chrome stable version on 2026-10-16) and
#   154.0.8037.97 (the previous stable), from Google's Chrome for Testing bucket;
# - Firefox 158.0 (the current release on 2026-10-16) and 157.0.1 (the previous release), from
#   Mozilla's archive, whose SHA256SUMS list the same hashes;
# - geckodriver 0.37.1, which drives Firefox over WebDriver.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:7852dc5a7d72f5fe458a597d690f6c42fbc8e9e26ddfa95f8e6ef552558d9bbf

RUN apt-get update \
 && apt-get install --yes --no-install-recommends libnss3-tools unzip xz-utils \
 && apt-get clean \
 && find /var/lib/apt/lists -type f -delete

ADD --checksum=sha256:cf0f049892dea22e6a6db26d47ed0d7776b7158edcbec4634086633df8bafcbc \
    https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.84/linux64/chrome-linux64.zip /tmp/chrome-155.zip
ADD --checksum=sha256:487c3b0e89f786d9257a6265a29bacf18b893e90f29c0ef6f7be9706ecc8c7a2 \
    https://storage.googleapis.com/chrome-for-testing-public/154.0.8037.97/linux64/chrome-linux64.zip /tmp/chrome-154.zip
ADD --checksum=sha256:9549b054ec4cf85f50f6a19d8c6fb79580312e71ebc4ec2cb217ec9af09dc12a \
    https://archive.mozilla.org/pub/firefox/releases/158.0/linux-x86_64/en-US/firefox-158.0.tar.xz /tmp/firefox-158.tar.xz
ADD --checksum=sha256:0d92bf39cdd174f5f361008509310bdefbce72a57ca10523a43b32d62dc699b6 \
    https://archive.mozilla.org/pub/firefox/releases/157.0.1/linux-x86_64/en-US/firefox-157.0.1.tar.xz /tmp/firefox-157.tar.xz
ADD --checksum=sha256:e815130ea95983e162ae91843b48d3a3ce991735635fce83a647afde21e09f7e \
    https://github.com/mozilla/geckodriver/releases/download/v0.37.1/geckodriver-v0.37.1-linux64.tar.gz /tmp/geckodriver.tar.gz

RUN set -e; cd /opt \
 && for v in 155 154; do mkdir -p chrome-$v && unzip -q /tmp/chrome-$v.zip -d chrome-$v; done \
 && for v in 158 157; do mkdir -p firefox-$v && tar -xJf /tmp/firefox-$v.tar.xz -C firefox-$v; done \
 && tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin geckodriver \
 && find /tmp -maxdepth 1 -type f \( -name '*.zip' -o -name '*.tar.*' \) -delete

WORKDIR /app
RUN npm init --yes >/dev/null && npm install --no-fund --no-audit playwright@1.64.1
