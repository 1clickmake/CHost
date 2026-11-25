#!/usr/bin/env bash
set -euo pipefail

echo "=== CHost Installer ==="

if [ "$(id -u)" -ne 0 ]; then
  echo "Error: Please run as root (sudo bash)."
  exit 1
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET_TAG="linux-x64" ;;
  aarch64) ASSET_TAG="linux-arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

INSTALL_DIR="/opt/chost"
DATA_DIR="/var/lib/chost"
mkdir -p "$INSTALL_DIR" "$DATA_DIR" /www/wwwroot

DOWNLOAD_URL=$(curl -sSL "https://api.github.com/repos/1clickmake/CHost/releases/latest" \
  | grep "browser_download_url" \
  | grep "$ASSET_TAG" \
  | head -n 1 \
  | cut -d '"' -f 4 || true)

if [ -n "$DOWNLOAD_URL" ]; then
  echo "Downloading CHost binary ($ASSET_TAG)..."
  curl -sSL "$DOWNLOAD_URL" -o /tmp/chost.tar.gz
  tar -xzf /tmp/chost.tar.gz -C "$INSTALL_DIR"
  rm -f /tmp/chost.tar.gz
else
  echo "No prebuilt release found. Please build from source with cargo build --release --bin chost."
  exit 1
fi

chmod +x "$INSTALL_DIR/chost"

cat >/etc/systemd/system/chost.service <<'EOF'
[Unit]
Description=CHost Web Server Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/chost
ExecStart=/opt/chost/chost
Restart=always
RestartSec=3
Environment=CHOST_PORT=8800
Environment=CHOST_DATA_DIR=/var/lib/chost

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable chost
systemctl restart chost

IP=$(curl -sSL https://api.ipify.org || hostname -I | awk '{print $1}')
echo "=== CHost Installed Successfully ==="
echo "URL: http://${IP}:8800"
echo "Default Password: Check /var/lib/chost/init_password.txt"
