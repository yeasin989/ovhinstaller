#!/bin/bash
set -e

PANEL_PORT=8080
VPN_PORT=4443
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS=$(tr -dc 'A-Z' </dev/urandom | head -c2)$(tr -dc '0-9' </dev/urandom | head -c3)
ADMIN_INFO="$PANEL_DIR/admin.json"
CSV_FILE="/root/vpn_users.csv"
USER_FILE="/etc/ocserv/ocpasswd"
CERT_DIR="/etc/ocserv/certs"
SOCKET_FILE="/run/ocserv.socket"

# --- Install Dependencies ---
echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

# --- Generate certificates if needed ---
echo "[*] Configuring ocserv VPN on port $VPN_PORT..."
mkdir -p $CERT_DIR
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

# --- Write ocserv configuration ---
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
socket-file = $SOCKET_FILE
use-occtl = true          # enable occtl control socket
device = vpns
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

# --- Firewall rules ---
echo "[*] Opening firewall for VPN port $VPN_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

# --- Enable IP forwarding & NAT ---
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true
netfilter-persistent save

# --- User database & CSV setup ---
touch "$USER_FILE"; chmod 600 "$USER_FILE"
if [ ! -f "$CSV_FILE" ]; then echo "username,password" > "$CSV_FILE"; fi
chmod 666 "$CSV_FILE"

# --- Flask Admin Panel Setup ---
mkdir -p $PANEL_DIR
cd $PANEL_DIR
python3 -m venv venv
source venv/bin/activate
pip install flask

# Create admin credentials file
cat > $ADMIN_INFO <<EOF
{
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASS"
}
EOF

# Write requirements
cat > $PANEL_DIR/requirements.txt <<EOF
flask
EOF

# --- Create Flask app with fixed get_connected() ---
cat > $PANEL_DIR/app.py <<'EOF'
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
SOCKET = '/run/ocserv.socket'
MAX_USERS = 6000
PANEL_PORT = 8080

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_ip():
    try:
        import urllib.request
        return urllib.request.urlopen('https://ipv4.icanhazip.com').read().decode().strip()
    except:
        return socket.gethostbyname(socket.gethostname())

def load_admin():
    with open(ADMIN_INFO) as f: return json.load(f)

def save_admin(admin):
    with open(ADMIN_INFO, 'w') as f: json.dump(admin, f)

def get_users():
    users=[]
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            reader=csv.reader(f)
            for row in reader:
                if row and row[0]!='username': users.append({'username':row[0],'password':row[1]})
    return users

def get_connected():
    try:
        cmd=f"occtl --socket-file {SOCKET} show users"
        out=subprocess.check_output(cmd, shell=True)
        names=[l.split()[1] for l in out.decode().splitlines() if 'Username' in l]
        return len(names), names
    except:
        return 0, []

# ... rest of Flask routes unchanged ...

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)
EOF

# --- Ensure socket permissions ---
chmod 660 $SOCKET_FILE 2>/dev/null || true
chown root:root $SOCKET_FILE 2>/dev/null || true

# --- Create recovery CLI ---
cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

# --- Systemd service for panel ---
cat > /etc/systemd/system/ocserv-admin.service <<EOF
[Unit]
Description=OpenConnect Admin Panel
After=network.target

[Service]
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python3 app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# --- Enable and start services ---
systemctl daemon-reload
systemctl enable --now ocserv
systemctl enable --now ocserv-admin
systemctl restart ocserv ocserv-admin

IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
echo "========================================="
echo "✅ OpenConnect VPN + Admin Panel Installed!"
echo "Admin Panel: http://$IP:8080"
echo "VPN: $IP:$VPN_PORT"
echo "Admin User: $ADMIN_USER"
echo "Admin Pass: $ADMIN_PASS"
echo "Recover Admin: sudo get_admin_info"
echo "========================================="
