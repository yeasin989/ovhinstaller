#!/bin/bash
set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────────────
PANEL_PORT=8080
VPN_PORT=4443
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS="$(tr -dc 'A-Z' </dev/urandom | head -c2)$(tr -dc '0-9' </dev/urandom | head -c3)"
ADMIN_FILE="$PANEL_DIR/admin.json"
CSV_FILE="/root/vpn_users.csv"
USER_FILE="/etc/ocserv/ocpasswd"
CERT_DIR="/etc/ocserv/certs"
SOCKET_FILE="/run/ocserv.socket"
# ────────────────────────────────────────────────────────────────────────────────

echo "==> Installing system packages..."
apt update -qq
apt install -y python3 python3-venv ocserv curl openssl iproute2 iptables-persistent

echo "==> Configuring ocserv..."
mkdir -p "$CERT_DIR"
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" \
    -out    "$CERT_DIR/server.crt" \
    -subj "/CN=$(curl -s ipv4.icanhazip.com)"
fi

cat >/etc/ocserv/ocserv.conf <<EOF
auth                        = "plain[/etc/ocserv/ocpasswd]"
tcp-port                    = $VPN_PORT
udp-port                    = $VPN_PORT
server-cert                 = $CERT_DIR/server.crt
server-key                  = $CERT_DIR/server.key
socket-file                 = $SOCKET_FILE
use-occtl                   = true
device                      = vpns
max-clients                 = 6000
max-same-clients            = 1
default-domain              = vpn
ipv4-network                = 192.168.150.0/24
dns                         = 8.8.8.8
dns                         = 1.1.1.1
EOF

echo "==> Enabling IP forwarding & NAT..."
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" >/etc/sysctl.d/99-ocserv-forward.conf
IFACE="$(ip route | awk '/default/ {print $5; exit}')"
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE
netfilter-persistent save

echo "==> Opening firewall ports..."
iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT

echo "==> Preparing user DB..."
touch "$USER_FILE" && chmod 600 "$USER_FILE"
if [ ! -f "$CSV_FILE" ]; then
  echo "username,password" >"$CSV_FILE"
fi
chmod 660 "$CSV_FILE"

echo "==> Setting up Flask admin panel..."
mkdir -p "$PANEL_DIR"
cd "$PANEL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --no-cache-dir flask

# Write admin credentials
cat > "$ADMIN_FILE" <<EOF
{"username":"$ADMIN_USER","password":"$ADMIN_PASS"}
EOF
chmod 600 "$ADMIN_FILE"

# Write the Flask app
cat > app.py <<'EOF'
import os, json, subprocess, csv
from flask import Flask, render_template_string, request, session, redirect, flash

ADMIN_FILE = '/opt/ocserv-admin/admin.json'
CSV_FILE   = '/root/vpn_users.csv'
SOCKET     = '/run/ocserv.socket'
PORT       = 8080

app = Flask(__name__)
app.secret_key = os.urandom(16)

LOGIN_HTML = """
<!doctype html>
<title>VPN Admin Login</title>
<h2>Login</h2>
<form method=post>
  <input name=username placeholder="Username" required autofocus>
  <input name=password type=password placeholder="Password" required>
  <button>Sign In</button>
  {% with msgs = get_flashed_messages() %}
    {% for msg in msgs %}<p style="color:red">{{msg}}</p>{% endfor %}
  {% endwith %}
</form>
"""

DASH_HTML = """
<!doctype html>
<title>VPN Admin Panel</title>
<form method=post action="/logout"><button>Logout</button></form>
<h2>Connected Users ({{count}})</h2>
<ul>{% for u in users %}<li>{{u}}</li>{% endfor %}</ul>
<h2>All VPN Accounts</h2>
<ul>{% for a in accounts %}<li>{{a.username}} / {{a.password}}</li>{% endfor %}</ul>
"""

def load_admin():
    return json.load(open(ADMIN_FILE))

def get_connected():
    try:
        out = subprocess.check_output(
            f"occtl --socket-file {SOCKET} show users", shell=True
        ).decode().splitlines()
        users = [l.split()[1] for l in out if 'Username' in l]
        return len(users), users
    except:
        return 0, []

def get_accounts():
    acc = []
    with open(CSV_FILE) as f:
        for user,pw in csv.reader(f):
            if user!='username':
                acc.append({'username':user,'password':pw})
    return acc

@app.route('/', methods=['GET','POST'])
def login():
    if session.get('admin'): return redirect('/dashboard')
    if request.method=='POST':
        creds = load_admin()
        if (request.form['username'], request.form['password']) == (creds['username'], creds['password']):
            session['admin']=True
            return redirect('/dashboard')
        flash('Invalid credentials')
    return render_template_string(LOGIN_HTML)

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect('/')
    count, users = get_connected()
    accounts = get_accounts()
    return render_template_string(DASH_HTML, count=count, users=users, accounts=accounts)

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT)
EOF

# Create systemd service
cat >/etc/systemd/system/ocserv-admin.service <<EOF
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

echo "==> Enabling services..."
systemctl daemon-reload
systemctl enable --now ocserv
systemctl enable --now ocserv-admin

PUBLIC_IP="$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
echo
echo "✅ Installation complete!"
echo "Admin panel: http://$PUBLIC_IP:$PANEL_PORT"
echo "VPN port: $PUBLIC_IP:$VPN_PORT"
echo "Login → $ADMIN_USER / $ADMIN_PASS"
echo "Get admin JSON: sudo cat $ADMIN_FILE"
echo

