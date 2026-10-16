# Browser driver image: an official Playwright image (browsers included), NSS tools to trust the
# run's test CA, and the Playwright npm package at the image's version, installed from a lockfile.
ARG BASE
FROM ${BASE}
ARG LOCK_DIR
RUN apt-get update \
  && apt-get install --yes --no-install-recommends libnss3-tools \
  && apt-get clean
WORKDIR /app
COPY ${LOCK_DIR}/package.json ${LOCK_DIR}/package-lock.json ./
RUN npm ci --no-fund --no-audit --ignore-scripts
COPY driver.mjs ./
ENTRYPOINT ["node", "/app/driver.mjs"]
