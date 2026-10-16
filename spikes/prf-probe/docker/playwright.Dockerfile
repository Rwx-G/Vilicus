# The official Playwright image ships the browsers but not the npm package; install the package
# version that matches the image tag, so the browsers it drives are the ones in the image.
ARG BASE
FROM ${BASE}
ARG PLAYWRIGHT_VERSION
WORKDIR /app
RUN npm init --yes >/dev/null && npm install --no-fund --no-audit "playwright@${PLAYWRIGHT_VERSION}"
