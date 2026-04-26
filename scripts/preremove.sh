#!/bin/sh
# preremove hook for the .deb / .rpm packages.
set -e

if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet adblocker.service; then
    systemctl stop adblocker.service || true
  fi
  if systemctl is-enabled --quiet adblocker.service; then
    systemctl disable adblocker.service || true
  fi
fi

# Detach pinned maps so the next install starts clean.
if [ -d /sys/fs/bpf/adblocker ]; then
  rm -rf /sys/fs/bpf/adblocker || true
fi

exit 0
