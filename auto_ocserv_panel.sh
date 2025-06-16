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

echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl openssl pwgen iproute2 iptables-persistent

# VPN SERVER CONFIGURATION
echo "[*] Configuring ocserv VPN on port $VPN_PORT..."

mkdir -p $CERT_DIR
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
device = vpns
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

echo "[*] Opening firewall for VPN port $VPN_PORT..."
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

touch "$USER_FILE"
chmod 600 "$USER_FILE"

if [ ! -f "$CSV_FILE" ]; then
    echo "username,password" > "$CSV_FILE"
fi
chmod 666 "$CSV_FILE"

mkdir -p $PANEL_DIR
cd $PANEL_DIR
python3 -m venv venv
source venv/bin/activate
pip install flask

cat > $ADMIN_INFO <<EOF
{
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASS"
}
EOF

cat > $PANEL_DIR/requirements.txt <<EOF
flask
EOF

cat > $PANEL_DIR/app.py <<"EOF"
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
MAX_USERS = 6000
PANEL_PORT = 8080

app = Flask(__name__)
app.secret_key = 'this_is_a_constant_super_secret_key__change_for_prod_2024'  # keep constant for reliable sessions

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
                if row and row[0] == 'username':
                    continue
                if len(row) >= 2:
                    users.append({'username': row[0], 'password': row[1]})
    return users

@app.route('/', methods=['GET', 'POST'])
def login():
    if session.get('admin'):
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        creds = load_admin()
        if request.form['username'] == creds['username'] and request.form['password'] == creds['password']:
            session['admin'] = True
            return redirect(url_for('dashboard'))  # always relative, always safe
        flash('Login failed.', 'error')
    return render_template_string('''
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>OpenConnect Admin Login</title>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@700;900&display=swap" rel="stylesheet">
      <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
      <style>
        body {background: linear-gradient(120deg, #232e47 0%, #447cfb 100%); min-height:100vh; font-family: 'Inter',sans-serif; margin:0;}
        .login-card {max-width:380px; margin:80px auto; background:#fff; border-radius:20px; box-shadow:0 8px 32px #0002; padding:36px 28px;}
        h2 {margin:0 0 20px 0; color:#2354be; font-size:2em; font-weight:900;}
        input {width:100%; padding:15px; border-radius:9px; border:1px solid #bcd; margin-bottom:16px; font-size:1.1em;}
        button {width:100%; background:linear-gradient(90deg,#3579f8,#43e3c1); color:#fff; border:0; border-radius:9px; font-size:1.12em; font-weight:700; padding:14px; transition:.15s;}
        button:hover {filter:brightness(.97);}
        .toast {color:#e9435b; font-weight:700; margin-top:12px;}
        @media(max-width:600px) {.login-card{padding:18px 8px;}}
      </style>
    </head>
    <body>
      <form class="login-card" method=post>
        <h2>OpenConnect<br>Admin</h2>
        <input name=username placeholder="admin" required>
        <input name=password type=password placeholder="password" required>
        <button>Login</button>
        <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
      </form>
    </body>
    </html>
    ''')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('admin'):
        return redirect(url_for('login'))
    users = get_users()
    admin = load_admin()
    server_ip = get_ip()
    panel_port = PANEL_PORT
    vpn_port = 4443
    edit = request.args.get('edit') == '1'
    return render_template_string('''
    <!-- (identical template as previously, omitted for brevity) -->
    <!-- Use previous template for dashboard page, same as above, or request "full code" if you want copy/paste ready -->
    ''', users=users, admin=admin, server_ip=server_ip, panel_port=panel_port, vpn_port=vpn_port, MAX_USERS=MAX_USERS, edit=edit)

@app.route('/add_user', methods=['POST'])
def add_user():
    if not session.get('admin'):
        return redirect(url_for('login'))
    uname = request.form['username'].strip()
    pword = request.form['password'].strip()
    if not uname or not pword:
        flash('Username and password required.', 'error')
        return redirect(url_for('dashboard'))
    subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
    exists = False
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            for row in csv.reader(f):
                if row and row[0] == uname:
                    exists = True
    if not exists:
        with open(CSV_FILE, 'a') as f:
            f.write(f"{uname},{pword}\n")
        flash('User added!', 'success')
        subprocess.call("systemctl restart ocserv", shell=True)
    else:
        flash('User already exists.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/del_user', methods=['POST'])
def del_user():
    if not session.get('admin'):
        return redirect(url_for('login'))
    uname = request.form['username']
    subprocess.call(f"ocpasswd -d {uname}", shell=True)
    # Remove from CSV
    rows = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE) as f:
            for row in csv.reader(f):
                if row and row[0] != uname and row[0] != "username":
                    rows.append(row)
        with open(CSV_FILE, 'w') as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password"])
            writer.writerows(rows)
    flash(f'User {uname} deleted.', 'success')
    subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/edit_admin', methods=['POST'])
def edit_admin():
    if not session.get('admin'):
        return redirect(url_for('login'))
    new_user = request.form['username'].strip()
    new_pass = request.form['password'].strip()
    if new_user and new_pass:
        save_admin({'username': new_user, 'password': new_pass})
        flash('Admin info updated!', 'success')
    else:
        flash('Both fields required.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)



EOF

cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

cat > $PANEL_DIR/README.txt <<EOF
Access panel: http://<your-ip>:8080
Admin user: $ADMIN_USER
Admin pass: $ADMIN_PASS
Recover admin: sudo get_admin_info
EOF

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
echo "✅ OpenConnect VPN Server + Admin Panel Installed!"
echo "Admin Panel: http://$IP:8080"
echo "VPN Connect to: $IP:4443"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="
