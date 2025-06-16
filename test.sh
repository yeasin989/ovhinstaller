#!/bin/bash
set -e

PANEL_PORT=8080
VPN_PORT=4443
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS=$(tr -dc 'A-Z' </dev/urandom | head -c2)$(tr -dc '0-9' </dev/urandom | head -c3)
ADMIN_INFO="$PANEL_DIR/admin.json"
USER_FILE="/etc/ocserv/ocpasswd"
CERT_DIR="/etc/ocserv/certs"
SOCKET_FILE="/run/ocserv.socket"

apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

mkdir -p $CERT_DIR
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[$USER_FILE]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
socket-file = $SOCKET_FILE
device = vpns
max-clients = 6000
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
log-level = info
log-file = /var/log/ocserv.log
EOF

iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT
iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o $(ip route | grep default | awk '{print $5}' | head -n1) -j MASQUERADE
netfilter-persistent save

sysctl -w net.ipv4.ip_forward=1

mkdir -p $PANEL_DIR
python3 -m venv $PANEL_DIR/venv
source $PANEL_DIR/venv/bin/activate
pip install flask

cat >$ADMIN_INFO <<EOF
{"username":"$ADMIN_USER","password":"$ADMIN_PASS"}
EOF

cat >$PANEL_DIR/app.py <<"EOF"
from flask import Flask, render_template_string, request, redirect, session, flash
import subprocess, json

app = Flask(__name__)
app.secret_key = 'secret!'
ADMIN_INFO = '/opt/ocserv-admin/admin.json'

@app.route('/', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        with open(ADMIN_INFO) as f:
            creds = json.load(f)
        if request.form['username']==creds['username'] and request.form['password']==creds['password']:
            session['admin']=True
            return redirect('/dashboard')
        flash('Invalid credentials')
    return render_template_string('''
    <form method="post">
      <input name="username" placeholder="Username">
      <input name="password" type="password" placeholder="Password">
      <button>Login</button>
      {{get_flashed_messages()}}
    </form>
    ''')

@app.route('/dashboard')
def dashboard():
    if not session.get('admin'): return redirect('/')
    output = subprocess.check_output("occtl -s /run/ocserv.socket show users", shell=True).decode()
    connected = [line.split(':')[1].strip() for line in output.splitlines() if 'Username:' in line]
    return render_template_string('''
    <html>
    <head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body { font-family: Arial; padding: 10px; }
      .user-list { list-style: none; padding: 0; }
      .user-list li { padding: 5px; background: #f2f2f2; margin-bottom: 5px; border-radius: 5px; }
      @media(max-width:600px){ body{font-size:14px;} }
    </style>
    </head>
    <body>
      <h2>Connected Users ({{connected|length}})</h2>
      <ul class="user-list">
        {% for u in connected %}<li>{{u}}</li>{% else %}<li>No users connected</li>{% endfor %}
      </ul>
    </body>
    </html>
    ''', connected=connected)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

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

IP=$(curl -s ipv4.icanhazip.com)
echo "Admin Panel: http://$IP:8080"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
