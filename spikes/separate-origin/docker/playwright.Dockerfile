# The official Playwright image ships the browsers but not the npm package; install the package
# version that matches the image tag, so the browsers it drives are the ones in the image. NSS
# tools install the test CAs as trust anchors (the browsers never skip certificate checks).
ARG BASE
FROM ${BASE}
ARG PLAYWRIGHT_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends libnss3-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN npm init --yes >/dev/null && npm install --no-fund --no-audit "playwright@${PLAYWRIGHT_VERSION}"
