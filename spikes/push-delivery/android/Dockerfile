# Android emulator for the E13 emulator run (story 1.13): the Android emulator, platform-tools
# and an Android 15 x86_64 Google APIs system image, headless, KVM accelerated, plus the ntfy
# Android app APK, the observer and the scenario driver. Every download is pinned by SHA-256 in
# android.lock; the base is debian:trixie-slim as pulled on 2026-10-16, pinned by digest (the
# digest the other spikes use). Debian packages come from the trixie archive on the day of the
# build; run.sh prints the versions that matter.
#
# Building this image downloads the Android SDK packages, which are licensed under the Android
# Software Development Kit License Agreement (android.lock, SDK_LICENSE_ID); building or running
# it means accepting that agreement.
#
# A local test harness, not a service: it runs as root because the /dev/kvm node passed in with
# --device carries the engine's group, which differs between Docker Desktop and Linux hosts.

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS download
RUN apt-get update \
 && apt-get install --yes --no-install-recommends ca-certificates curl unzip
COPY android.lock /lock/android.lock
WORKDIR /download
# fetch NAME URL SHA256: downloads into /download/NAME and refuses a checksum mismatch.
RUN set -eu; . /lock/android.lock; \
    fetch() { curl --fail --silent --show-error --location --output "$1" "$2"; \
              echo "$3  $1" | sha256sum --check --strict; }; \
    fetch platform-tools.zip "$SDK_REPOSITORY/$PLATFORM_TOOLS_FILE" "$PLATFORM_TOOLS_SHA256"; \
    fetch emulator.zip "$SDK_REPOSITORY/$EMULATOR_FILE" "$EMULATOR_SHA256"; \
    fetch system-image.zip "$SDK_REPOSITORY/$SYSTEM_IMAGE_FILE" "$SYSTEM_IMAGE_SHA256"; \
    fetch ntfy.apk "$NTFY_APP_URL" "$NTFY_APP_SHA256"; \
    sdk=/out/android-sdk; \
    mkdir -p "$sdk/system-images/android-$SYSTEM_IMAGE_API/$SYSTEM_IMAGE_TAG" "$sdk/licenses" "$sdk/platforms" /out/e13; \
    unzip -q platform-tools.zip -d "$sdk"; \
    unzip -q emulator.zip -d "$sdk"; \
    unzip -q system-image.zip -d "$sdk/system-images/android-$SYSTEM_IMAGE_API/$SYSTEM_IMAGE_TAG"; \
    printf '\n%s' "$SDK_LICENSE_SHA1" > "$sdk/licenses/$SDK_LICENSE_ID"; \
    cp ntfy.apk /out/e13/ntfy.apk; \
    cp /lock/android.lock /out/e13/android.lock

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
LABEL org.opencontainers.image.title="vilicus-spike-push-delivery-android" \
      org.opencontainers.image.description="Headless Android emulator for the E13 emulator run" \
      org.opencontainers.image.source="https://github.com/Rwx-G/Vilicus" \
      org.opencontainers.image.licenses="Apache-2.0"
# The emulator ships its own Qt and graphics libraries; these are the system libraries it still
# loads when headless with SwiftShader. python3 runs the observer and the scenario driver.
RUN apt-get update \
 && apt-get install --yes --no-install-recommends \
      ca-certificates libasound2t64 libbsd0 libdbus-1-3 libdrm2 libegl1 libexpat1 libfontconfig1 \
      libgbm1 libgl1 libnss3 libpulse0 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 \
      libxdamage1 libxext6 libxfixes3 libxi6 libxkbcommon0 libxkbfile1 libxrandr2 libxrender1 \
      libxtst6 procps python3 zlib1g \
 && apt-get clean
COPY --from=download /out/android-sdk /opt/android-sdk
COPY --from=download /out/e13 /opt/e13
ENV ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_USER_HOME=/var/lib/e13/android \
    ANDROID_AVD_HOME=/var/lib/e13/avd \
    PATH=/opt/android-sdk/platform-tools:/opt/android-sdk/emulator:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
COPY avd /opt/e13/avd
COPY observer.py scenario.py analyse.py emulator.sh /opt/e13/
ENTRYPOINT ["/bin/bash", "/opt/e13/emulator.sh"]
