#!/bin/sh
# postinstall hook for the .deb / .rpm packages.
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  if [ "${1:-}" = "configure" ] || [ "${1:-1}" -ge 1 ] 2>/dev/null; then
    if ! systemctl is-enabled --quiet adblocker.service; then
      cat <<'EOF'

adblocker installed. The systemd unit is NOT enabled by default.
Enable it with:

  sudo systemctl enable --now adblocker

Edit /etc/adblocker/adblocker.yaml to point at your interfaces and
upstream feeds.

EOF
    fi
  fi
fi

# Ensure /sys/fs/bpf is mountable on the user's kernel.
if [ ! -d /sys/fs/bpf ]; then
  echo "warning: /sys/fs/bpf is not mounted; the daemon will fail to pin maps."
  echo "         add 'bpf  /sys/fs/bpf  bpf  rw,nosuid,nodev,noexec,relatime  0 0' to /etc/fstab"
fi

exit 0
