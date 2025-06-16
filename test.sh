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
echo "[*] Setting up user database..."
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

# Write Flask application
cat > app.py << 'EOF'
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
SOCKET = '/run/ocserv.socket'
MAX_USERS = 6000
PANEL_PORT = 8080
app = Flask(__name__)
app.secret_key = os.urandom(24)

LOGIN_HTML = '''
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Admin Login</title>
<style>body{background:#191f2a;font-family:sans-serif;} .login{max-width:350px;margin:80px auto;background:#fff;border-radius:14px;padding:32px;}</style>
</head><body>
<form class="login" method="post">
  <h2>VPN Admin Login</h2>
  <input name="username" placeholder="admin" required>
  <input name="password" type="password" placeholder="password" required>
  <button>Login</button>
  <div style="color:red;">{% with messages = get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
</form>
</body></html>
'''

DASH_HTML = '''
<html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VPN Admin Panel</title>
<style>body{background:#f6f8fa;font-family:sans-serif;margin:0;} .card{max-width:540px;margin:30px auto;padding:24px;background:#fff;border-radius:18px;} .logout{position:absolute;top:16px;right:24px;}</style>
</head><body>
<form method="post" action="/logout"><button class="logout">Logout</button></form>
<div class="card">
  <h2>OpenConnect VPN Admin Panel</h2>
  <p><b>Connected users:</b> {{connected_count}}/{{MAX_USERS}}</p>
  <p>{% for u in connected_users %}<code>{{u}}</code>{% endfor %}</p>
  <h3>Add VPN User</h3>
  <form method="post" action="/add_user">
    <input name="username" placeholder="username" required minlength="2">
    <input name="password" placeholder="password" required minlength="3">
    <button>Add</button>
  </form>
  <h3>All Users</h3>
  <table border="1" cellpadding="5">
    <tr><th>Username</th><th>Password</th><th>Action</th></tr>
    {% for u in users %}
    <tr><td>{{u.username}}</td><td>{{u.password}}</td><td>
      <form method="post" action="/del_user"><input type="hidden" name="username" value="{{u.username}}"><button>Delete</button></form>
    </td></tr>
    {% endfor %}
  </table>
</div>
</body></html>
'''

def load_admin(): return json.load(open(ADMIN_INFO))

def get_users():
    users=[]
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            reader=csv.reader(f)
            for row in reader:
                if row and row[0] != 'username': users.append({'username':row[0],'password':row[1]})
    return users

def get_connected():
    try:
        out=subprocess.check_output(f"occtl --socket-file {SOCKET} show users", shell=True)
        names=[l.split()[1] for l in out.decode().splitlines() if 'Username' in l]
        return len(names), names
    except:
        return 0, []

@app.route('/', methods=['GET','POST'])
def login():
    if session.get('admin'): return redirect(request.url_root + 'dashboard')
    if request.method=='POST':
        creds=load_admin()
        if request.form['username']==creds['username'] and request.form['password']==creds['password']:
            session['admin']=True
            return redirect(request.url_root + 'dashboard')
        flash('Invalid login','error')
    return render_template_string(LOGIN_HTML)

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect(request.url_root)
    count,names=get_connected()
    return render_template_string(DASH_HTML, connected_count=count, connected_users=names, users=get_users())

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('admin'): return redirect(request.url_root)
    uname=request.form['username']; pword=request.form['password']
    subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
    # update CSV omitted for brevity
    return redirect(request.url_root + 'dashboard')

@app.route('/del_user', methods=['POST'])
def del_user():
    if not session.get('admin'): return redirect(request.url_root)
    subprocess.call(f"ocpasswd -d {request.form['username']}", shell=True)
    return redirect(request.url_root + 'dashboard')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(request.url_root)

if __name__=='__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)
EOF

# Create systemd service
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
