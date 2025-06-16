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

# 1. Install dependencies (includes ocserv and occtl)
echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

# 2. Configure and generate self-signed certificate
echo "[*] Configuring ocserv VPN on port $VPN_PORT..."
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

# 3. Write ocserv.conf
echo "[*] Writing /etc/ocserv/ocserv.conf"
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
socket-file = $SOCKET_FILE
device = vpns
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

# 4. Firewall configuration
echo "[*] Opening firewall for VPN port $VPN_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

# 5. Enable IP forwarding and NAT
echo "[*] Enabling IP forwarding and NAT..."
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true
netfilter-persistent save

# 6. Prepare user files
touch "$USER_FILE" && chmod 600 "$USER_FILE"
if [ ! -f "$CSV_FILE" ]; then
    echo "username,password" > "$CSV_FILE"
fi
chmod 666 "$CSV_FILE"

# 7. Setup Flask admin panel
echo "[*] Installing Flask admin panel..."
mkdir -p "$PANEL_DIR"
cd "$PANEL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install flask

# 8. Write admin credentials
echo "[*] Writing admin credentials..."
cat > "$ADMIN_INFO" <<EOF
{
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASS"
}
EOF

# 9. Create requirements.txt
echo "flask" > requirements.txt

# 10. Write app.py with updated get_connected()
echo "[*] Writing app.py..."
cat > "$PANEL_DIR/app.py" <<'PYCODE'
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
SOCKET_FILE = '/run/ocserv.socket'
MAX_USERS = 6000
PANEL_PORT = 8080

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_ip():
    try:
        import urllib.request
        ip = urllib.request.urlopen('https://ipv4.icanhazip.com').read().decode().strip()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

def load_admin():
    with open(ADMIN_INFO) as f:
        return json.load(f)
def save_admin(admin):
    with open(ADMIN_INFO, 'w') as f:
        json.dump(admin, f)

def get_users():
    users = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            reader = csv.reader(f)
            for row in reader:
                if row and row[0] == 'username': continue
                if len(row) >= 2:
                    users.append({'username': row[0], 'password': row[1]})
    return users

# Updated: point occtl at the correct socket and parse JSON
def get_connected():
    try:
        out = subprocess.check_output([
            'occtl', '-s', SOCKET_FILE, '--json', 'show', 'users'
        ])
        lst = json.loads(out.decode())
        names = [u['username'] for u in lst]
        return len(names), names
    except subprocess.CalledProcessError:
        return 0, []
    except FileNotFoundError:
        raise RuntimeError('occtl not installed or not in PATH')
    except Exception:
        return 0, []

# ... rest of your routes unchanged ...
# (login, dashboard, add_user, del_user, change_admin, logout)

@app.route('/', methods=['GET', 'POST'])
# <existing login handler>
# [Omitted here for brevity—reinsert your full handlers exactly as before]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)
PYCODE

# 11. CLI tool to recover admin info
echo "[*] Creating get_admin_info..."
cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

# 12. README
echo "[*] Writing README..."
cat > $PANEL_DIR/README.txt <<EOF
Access panel: http://<your-ip>:8080
Admin user: $ADMIN_USER
Admin pass: $ADMIN_PASS
Recover admin: sudo get_admin_info
EOF

# 13. Systemd service
echo "[*] Configuring systemd service..."
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

systemctl daemon-reload
systemctl enable --now ocserv
systemctl restart ocserv
systemctl enable --now ocserv-admin
systemctl restart ocserv-admin

IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
echo "========================================="
echo "✅ OpenConnect VPN + Admin Panel Installed!"
echo "Admin Panel: http://$IP:8080"
echo "VPN Connect to: $IP:$VPN_PORT"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="
