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

# 접속 포트: 기존 설치면 유지, 새 설치면 사용 중이 아닌 랜덤 포트(20000-39999)
FRESH=0
[ -f "$DATA_DIR/chost.db" ] || FRESH=1
PORT=""
if [ -f /etc/systemd/system/chost.service ]; then
  PORT=$(grep -o 'CHOST_PORT=[0-9]*' /etc/systemd/system/chost.service | cut -d= -f2 || true)
fi
if [ -z "$PORT" ]; then
  for _i in $(seq 1 50); do
    P=$(shuf -i 20000-39999 -n 1)
    if ! ss -ltn 2>/dev/null | grep -q ":$P "; then PORT=$P; break; fi
  done
  PORT=${PORT:-8800}
fi

cat >/etc/systemd/system/chost.service <<EOF
[Unit]
Description=CHost Web Server Panel
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/chost
ExecStart=/opt/chost/chost
Restart=always
RestartSec=3
Environment=CHOST_PORT=${PORT}
Environment=CHOST_DATA_DIR=/var/lib/chost

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable chost
systemctl restart chost

# 방화벽(UFW)이 켜져 있으면 패널 포트 허용
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
fi

# 새 설치는 보안 접속 경로를 자동 생성 (기존 설치는 유지)
sleep 2
if [ "$FRESH" = "1" ]; then
  ENTRY=$(CHOST_DATA_DIR="$DATA_DIR" "$INSTALL_DIR/chost" --set-entry random 2>/dev/null || echo "/")
else
  ENTRY=$(CHOST_DATA_DIR="$DATA_DIR" "$INSTALL_DIR/chost" --show-entry 2>/dev/null || echo "/")
fi

IP=$(curl -sSL https://api.ipify.org || hostname -I | awk '{print $1}')
echo "=== CHost Installed Successfully ==="
echo "URL: http://${IP}:${PORT}${ENTRY}"
echo "Default Password: Check /var/lib/chost/init_password.txt"
echo "Forgot the URL?  sudo CHOST_DATA_DIR=/var/lib/chost /opt/chost/chost --show-entry"
