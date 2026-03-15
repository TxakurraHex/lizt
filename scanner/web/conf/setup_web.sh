#!/usr/bin/env bash
# Must run as sudo

# Stop on failure
set -euo pipefail

BINARY="target/debug/lizt_web"
BIN_DIR="/usr/bin"
CONF_DIR="/etc/lizt"
LOG_DIR="/var/log/lizt"
SSL_DIR="/etc/nginx/ssl"
NGINX_CONF="/etc/nginx/sites-available/lizt"
SERVICE_FILE="/etc/systemd/system/lizt_web.service"

if [[ $EUID -ne 0 ]]; then
	echo "ERROR: Must run as root." >&2
	exit 1
fi

if [[ ! -f "$BINARY" ]]; then
	echo "ERROR: $BINARY not found. Run 'cargo build --release -p web' first" >&2
	exit 1
fi

# Create lizt user if necessary
if ! id lizt &>/dev/null; then
	useradd --system --no-create-home --shell /usr/sbin/nologin lizt
	echo "Created system user: lizt"
fi

install -Dm755 "$BINARY" "$BIN_DIR/lizt_web"
echo "Installed: $BIN_DIR/lizt_web"

mkdir -p "$CONF_DIR"
if [[ ! -f "$CONF_DIR/env" ]]; then
	cat >"$CONF_DIR/env" <<'EOF'
DATABASE_URL=postgresql://user:password@localhost/lizt
LIZT_WEB_PORT=8080
# NVD_API_KEY=your-key-here
EOF
	chmod 600 "$CONF_DIR/env"
	echo "Created $CONF_DIR/env, edit it to verify DATABASE_URL and add NVD API key"
else
	grep -q LIZT_WEB_PORT "$CONF_DIR/env" || echo "LIZT_WEB_PORT=8080" >>"$CONF_DIR/env"
	echo "Using existing $CONF_DIR/env"
fi

mkdir -p "$LOG_DIR"
chown lizt:lizt "$LOG_DIR"

# Self-signed TLS cert
mkdir -p "$SSL_DIR"
if [[ ! -f "$SSL_DIR/lizt.crt" ]]; then
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
		-keyout "$SSL_DIR/lizt.key" \
		-out "$SSL_DIR/lizt.crt" \
		-subj "/CN=lizt-dashboard" \
		2>/dev/null
	echo "Generated self-signed TLS cert: $SSL_DIR/lizt.crt"
else
	echo "TLS cert already exists, skipping generation"
fi

# htpasswd file
if [[ ! -f /etc/nginx/.lizt_htpasswd ]]; then
	if ! command -v htpasswd &>/dev/null; then
		apt-get install -y apache2-utils -q
	fi
	echo ""
	echo "Create a dashboard login (username + password):"
	read -rp "  Username: " LIZT_USER
	htpasswd -c /etc/nginx/.lizt_htpasswd "$LIZT_USER"
	echo "Created /etc/nginx/.lizt_htpasswd"
else
	echo "htpasswd file already exists, skipping"
fi

# nginx config
install -Dm644 scanner/web/conf/lizt_nginx.conf "$NGINX_CONF"
ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/lizt
rm -f /etc/nginx/sites-enabled/default
nginx -t
echo "nginx config installed and validated"

# systemd unit file
install -Dm644 scanner/web/conf/lizt_web.service "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now lizt_web
systemctl reload nginx

# log4rs
install -Dm644 scanner/web/conf/lizt_web_log4rs.yaml "$CONF_DIR/"

# Migrations
cp -r migrations /etc/lizt/migrations

echo ""
echo "Done. lizt_web is running."
echo ""
echo "  Dashboard: https://$(curl -s ifconfig.me 2>/dev/null || echo '<ec2-public-ip>')"
echo ""
echo "EC2 security group: open inbound TCP 443 from your IP."
echo "Your browser will warn about the self-signed cert — that's expected."
