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
CERT_DIR="$PANEL_DIR/certs"
SOCKET_FILE="/run/ocserv.socket"

# Install Dependencies
echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

# Configure ocserv & Certs
echo "[*] Setting up ocserv..."
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
socket-file = $SOCKET_FILE
use-occtl = true
device = vpns
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

# Firewall & NAT
echo "[*] Configuring firewall and NAT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp
    ufw allow $VPN_PORT/udp
    ufw reload
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT
fi
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
IFACE=$(ip route | awk '/default/ {print $5; exit}')
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE
netfilter-persistent save

# User DB & CSV

touch "$USER_FILE"; chmod 600 "$USER_FILE"
if [ ! -f "$CSV_FILE" ]; then echo "username,password" > "$CSV_FILE"; fi
chmod 666 "$CSV_FILE"

# Flask Admin Panel Setup
echo "[*] Installing Admin Panel..."
mkdir -p "$PANEL_DIR"
cd "$PANEL_DIR"
python3 -m venv venv
action () { source venv/bin/activate; pip install flask; }
action

cat > "$ADMIN_INFO" <<EOF
{"username":"$ADMIN_USER","password":"$ADMIN_PASS"}
EOF

# Write Flask App with corrected redirects
cat > app.py <<'EOF'
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
SOCKET = '/run/ocserv.socket'
MAX_USERS = 6000
PANEL_PORT = 8080

def load_admin(): return json.load(open(ADMIN_INFO))

def save_admin(admin): json.dump(admin, open(ADMIN_INFO,'w'))

def get_users():
    users=[]
    if os.path.exists(CSV_FILE):
        for row in csv.reader(open(CSV_FILE)): 
            if row and row[0] != 'username': users.append({'username':row[0],'password':row[1]})
    return users

def get_connected():
    try:
        out = subprocess.check_output(f"occtl --socket-file {SOCKET} show users", shell=True)
        names=[l.split()[1] for l in out.decode().splitlines() if 'Username' in l]
        return len(names), names
    except:
        return 0, []

app = Flask(__name__)
app.secret_key = os.urandom(24)

LOGIN_HTML = '''<html><head>...login form...</head></html>'''
DASH_HTML = '''<html><head>...dashboard...</head></html>'''

@app.route('/', methods=['GET','POST'])
def login():
    if session.get('admin'): return redirect(request.url_root+'dashboard')
    if request.method=='POST':
        creds=load_admin()
        if request.form['username']==creds['username'] and request.form['password']==creds['password']:
            session['admin']=True
            return redirect(request.url_root+'dashboard')
        flash('Invalid login','error')
    return render_template_string(LOGIN_HTML)

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect(request.url_root)
    count,names=get_connected()
    return render_template_string(DASH_HTML, connected_count=count, connected_users=names, users=get_users())

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(request.url_root)

if __name__=='__main__': app.run(host='0.0.0.0', port=PANEL_PORT)
EOF

# Systemd Service
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/ocserv-admin.service <<EOF
[Unit]
Description=OpenConnect Admin Panel
After=network.target

[Service]
User=root
WorkingDirectory=$PANEL_DIR
ExecStart=$PANEL_DIR/venv/bin/python3 $PANEL_DIR/app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now ocserv ocserv-admin
systemctl restart ocserv ocserv-admin

echo "========================================="
echo "Admin Panel at http://${IP:-$(hostname -I | awk '{print $1}')}:$PANEL_PORT"
echo "User: $ADMIN_USER Pass: $ADMIN_PASS"
echo "========================================="
