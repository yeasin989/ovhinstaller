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

# --- Configure Certificates and ocserv ---
echo "[*] Configuring ocserv VPN on port $VPN_PORT..."
mkdir -p $CERT_DIR
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

# Write ocserv.conf
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
echo "[*] Setting up firewall and NAT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true
netfilter-persistent save

# User database
touch "$USER_FILE"; chmod 600 "$USER_FILE"
if [ ! -f "$CSV_FILE" ]; then echo "username,password" > "$CSV_FILE"; fi
chmod 666 "$CSV_FILE"

# Flask Admin Panel
mkdir -p $PANEL_DIR
cd $PANEL_DIR
python3 -m venv venv
source venv/bin/activate
pip install flask

# Admin credentials
cat > $ADMIN_INFO <<EOF
{
  "username": "$ADMIN_USER",
  "password": "$ADMIN_PASS"
}
EOF

# Requirements
cat > requirements.txt <<EOF
flask
EOF

# Flask app with relative redirects and fixed socket
cat > app.py <<'EOF'
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
SOCKET = '/run/ocserv.socket'
MAX_USERS = 6000
PANEL_PORT = 8080

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Templates
LOGIN_TEMPLATE = '''
<html>...</html>'''  # keep your existing HTML here
DASH_TEMPLATE = '''
<html>...</html>'''

# Helpers
def load_admin():
    with open(ADMIN_INFO) as f: return json.load(f)

def save_admin(admin):
    with open(ADMIN_INFO, 'w') as f: json.dump(admin, f)

def get_users():
    users=[]
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            for row in csv.reader(f):
                if row and row[0] != 'username': users.append({'username':row[0],'password':row[1]})
    return users

def get_connected():
    try:
        out = subprocess.check_output(f"occtl --socket-file {SOCKET} show users", shell=True)
        names = [l.split()[1] for l in out.decode().splitlines() if 'Username' in l]
        return len(names), names
    except:
        return 0, []

# Routes
@app.route('/', methods=['GET','POST'])
def login():
    if session.get('admin'): return redirect('/dashboard')
    if request.method == 'POST':
        creds = load_admin()
        if request.form['username']==creds['username'] and request.form['password']==creds['password']:
            session['admin']=True
            return redirect('/dashboard')
        flash('Login failed.','error')
    return render_template_string(LOGIN_TEMPLATE)

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect('/')
    users = get_users()
    count, names = get_connected()
    return render_template_string(DASH_TEMPLATE, connected_count=count, connected_users=names, users=users)

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('admin'): return redirect('/')
    subprocess.call(f"echo '{request.form['password']}\n\n' | ocpasswd -g default {request.form['username']}", shell=True)
    # add to CSV...
    return redirect('/dashboard')

@app.route('/del_user', methods=['POST'])
def del_user():
    if not session.get('admin'): return redirect('/')
    subprocess.call(f"ocpasswd -d {request.form['username']}", shell=True)
    return redirect('/dashboard')

@app.route('/change_admin', methods=['POST'])
def change_admin():
    if not session.get('admin'): return redirect('/')
    # change logic...
    return redirect('/dashboard')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect('/')

if __name__=='__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)
EOF

# Permissions & service
chmod 660 $SOCKET_FILE 2>/dev/null || true
chown root:root $SOCKET_FILE 2>/dev/null || true

# Recovery CLI
cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

# Systemd unit
cat >/etc/systemd/system/ocserv-admin.service <<EOF
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
systemctl enable --now ocserv ocserv-admin
systemctl restart ocserv ocserv-admin
echo "✅ Updated and fixed redirects!"
