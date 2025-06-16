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
source venv/bin/activate
pip install flask

# Admin credentials
cat > "$ADMIN_INFO" <<EOF
{"username":"$ADMIN_USER","password":"$ADMIN_PASS"}
EOF

# Write Flask app with full login/dashboard templates\ ncat > app.py << 'EOF'
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

LOGIN_HTML = '''
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Admin Login</title>
<style>
body{background:#191f2a;font-family:sans-serif;}
.login{max-width:350px;margin:80px auto;background:#fff;border-radius:14px;padding:32px;box-shadow:0 6px 24px #0002;}
h2{margin-top:0;color:#1e2b48;}
input{margin-bottom:12px;width:100%;padding:12px;border-radius:6px;border:1px solid #c4c4c4;}
button{width:100%;padding:12px;border:0;border-radius:6px;background:#1e89e7;color:#fff;font-weight:bold;font-size:1.1em;}
.toast{color:red;margin-top:10px;text-align:center;}
@media(max-width:600px){.login{padding:18px;}}
</style>
</head><body>
  <form class="login" method=post>
    <h2>VPN Admin Login</h2>
    <input name=username placeholder="admin" required>
    <input name=password type=password placeholder="password" required>
    <button>Login</button>
    <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
  </form>
</body></html>
'''

DASH_HTML = '''
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Admin Panel</title>
<style>
body{background:#f6f8fa;font-family:sans-serif;margin:0;}
.card{background:#fff;padding:24px;border-radius:18px;box-shadow:0 4px 32px #0002;max-width:540px;margin:30px auto;}
.row{display:flex;gap:22px;flex-wrap:wrap;}
h2{color:#1e2b48;margin-bottom:12px;}
input,select{padding:8px;border-radius:6px;border:1px solid #ccd;}
button{background:#1e89e7;color:#fff;border:0;padding:8px 20px;border-radius:6px;font-weight:bold;}
.logout{position:absolute;top:16px;right:24px;}
table{width:100%;border-collapse:collapse;}
th,td{padding:9px;text-align:left;}
tr:nth-child(even){background:#f4f6fa;}
th{background:#e7e9f0;}
.toast{padding:10px;text-align:center;border-radius:8px;font-size:1.08em;}
.success{background:#b0faad;color:#20621d;}
.error{background:#ffd3d3;color:#b93333;}
@media(max-width:650px){.card{padding:10px;}.row{flex-direction:column;}}
</style>
</head><body>
  <form method="post" action="/logout"><button class="logout">Logout</button></form>
  <div class="card">
    <h2>OpenConnect VPN Admin Panel</h2>
    <div style="margin-bottom:12px;"><b>Connected users:</b> {{connected_count}}/{{MAX_USERS}}</div>
    <div class="row"><b>Now connected:</b> {% for u in connected_users %}<code>{{u}}</code>{% endfor %}</div>
    <h3>Add VPN User</h3>
    <form method="post" action="/add_user" class="row">
      <input name="username" required placeholder="username" minlength=2>
      <input name="password" required placeholder="password" minlength=3>
      <button>Add</button>
    </form>
    <h3>All Users</h3>
    <table>
      <tr><th>Username</th><th>Password</th><th>Action</th></tr>
      {% for u in users %}<tr><td>{{u.username}}</td><td>{{u.password}}</td><td><form method="post" action="/del_user"><input type="hidden" name="username" value="{{u.username}}"><button>Delete</button></form></td></tr>{% endfor %}
    </table>
  </div>
</body></html>
'''

@app.route('/', methods=['GET','POST'])
def login():
    if session.get('admin'): return redirect(request.url_root+'dashboard')
    if request.method=='POST':
        creds= load_admin()
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

systemctl daemon-reload
systemctl enable --now ocserv ocserv-admin
systemctl restart ocserv ocserv-admin

echo "========================================="
echo "Admin Panel at http://${IP:-$(hostname -I | awk '{print $1}')}:$PANEL_PORT"
echo "User: $ADMIN_USER Pass: $ADMIN_PASS"
echo "========================================="
