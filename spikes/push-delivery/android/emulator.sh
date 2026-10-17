#!/usr/bin/env bash
# Entrypoint of the emulator container: a fresh AVD on every start (no snapshot, no state kept
# between runs), the adb server, then the emulator in the foreground. Headless, KVM accelerated,
# SwiftShader rendering, 4 cores and 4 GiB. The container has no route to the internet; the
# guest reaches only the test network.
set -euo pipefail

if [ ! -c /dev/kvm ]; then
  echo "error: /dev/kvm is missing; start the container with --device /dev/kvm" >&2
  exit 1
fi

mkdir -p "$ANDROID_AVD_HOME" "$ANDROID_USER_HOME"
cp /opt/e13/avd/e13.ini "$ANDROID_AVD_HOME/e13.ini"
cp -r /opt/e13/avd/e13.avd "$ANDROID_AVD_HOME/"

adb start-server >/dev/null

exec emulator -avd e13 \
  -no-window -no-audio -no-boot-anim -no-snapshot -no-metrics \
  -gpu swiftshader_indirect -accel on -cores 4 -memory 4096 \
  -port 5554
