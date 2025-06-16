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

# Self-signed cert (skip if exists)
mkdir -p $CERT_DIR
if [ ! -f "$CERT_DIR/server.crt" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')"
fi

# Create ocserv.conf with all required options (***ONE SETTING PER LINE!***)
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

# Open VPN firewall
echo "[*] Opening firewall for VPN port $VPN_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

# Enable IP forwarding and NAT (for VPN internet access)
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true

# Save iptables rule (persistent)
netfilter-persistent save

# User database file setup
touch "$USER_FILE"
chmod 600 "$USER_FILE"

# Ensure VPN users CSV file
if [ ! -f "$CSV_FILE" ]; then
    echo "username,password" > "$CSV_FILE"
fi
chmod 666 "$CSV_FILE"

# Flask Admin Panel Installation
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

# Flask app.py
cat > $PANEL_DIR/app.py <<"EOF"
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
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
                if row and row[0] == 'username':
                    continue
                if len(row) >= 2:
                    users.append({'username': row[0], 'password': row[1]})
    return users

def add_user_csv(username, password):
    exists = False
    users = []
    with open(CSV_FILE) as f:
        for row in csv.reader(f):
            if row and row[0] == username:
                exists = True
            users.append(row)
    if not exists:
        with open(CSV_FILE, 'a') as f:
            f.write(f"{username},{password}\n")
    return not exists

def delete_user_csv(username):
    if not os.path.exists(CSV_FILE): return
    rows = []
    with open(CSV_FILE) as f:
        for row in csv.reader(f):
            if row and row[0] == 'username':
                rows.append(row)
            elif row and row[0] != username:
                rows.append(row)
    with open(CSV_FILE, 'w') as f:
        writer = csv.writer(f)
        writer.writerows(rows)

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'admin' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        creds = load_admin()
        if request.form['username'] == creds['username'] and request.form['password'] == creds['password']:
            session['admin'] = True
            return redirect(url_for('dashboard'))
        flash('Login failed.', 'error')
    return render_template_string('''
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>VPN Admin Login</title>
      <style>
        body{background:#191f2a;font-family:Inter,sans-serif;margin:0;}
        .login-card{max-width:400px;margin:9vh auto 0 auto;background:#fff;border-radius:18px;padding:40px 26px;box-shadow:0 8px 32px #0003;}
        h2{margin-top:0;color:#161c2a;font-weight:800;}
        input{margin-bottom:16px;width:100%;padding:14px;border-radius:8px;border:1px solid #c6c6d6;font-size:1.1em;}
        button{width:100%;padding:13px;border:0;border-radius:8px;background:#1e89e7;color:#fff;font-weight:bold;font-size:1.13em;transition:all .2s;}
        button:hover{background:#1466b0;}
        .toast{color:#e9435b;margin-top:12px;text-align:center;font-weight:600;}
        @media(max-width:600px){.login-card{padding:20px 6px;}}
      </style>
    </head>
    <body>
      <form class="login-card" method=post>
        <h2>OpenConnect<br>Admin Login</h2>
        <input name=username placeholder="admin" required>
        <input name=password type=password placeholder="password" required>
        <button>Login</button>
        <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
      </form>
    </body>
    </html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session: return redirect(url_for('login'))
    users = get_users()
    admin = load_admin()
    server_ip = get_ip()
    panel_port = PANEL_PORT
    return render_template_string('''
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>VPN Admin Panel</title>
      <link rel="preconnect" href="https://fonts.googleapis.com">
      <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
      <style>
        body{background:#171d2b;font-family:Inter,sans-serif;margin:0;min-height:100vh;}
        .main-card{max-width:680px;margin:32px auto;background:#fff;border-radius:24px;padding:40px 30px 36px 30px;box-shadow:0 8px 40px #0004;}
        h2{color:#1e2b48;font-size:2.1em;font-weight:800;margin-bottom:12px;}
        .server-row{display:flex;flex-wrap:wrap;align-items:center;gap:13px;margin-bottom:22px;}
        .tag{background:#f3f7ff;color:#1366c4;padding:7px 14px;border-radius:24px;font-weight:600;margin-right:10px;display:inline-block;}
        .copy-btn{margin-left:5px;padding:5px 9px 5px 8px;border:none;border-radius:5px;background:#f1f6ff;color:#1766df;font-weight:600;font-size:1.01em;cursor:pointer;transition:all .2s;}
        .copy-btn:active{background:#d2e3fa;}
        .form-row{display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;}
        .form-row input{flex:1;}
        .form-row button{white-space:nowrap;}
        table{width:100%;margin-top:12px;border-collapse:collapse;}
        th,td{padding:13px 6px;text-align:left;}
        th{background:#f7f9fb;}
        tr:nth-child(even){background:#f2f6fa;}
        .delbtn{background:#e9435b;color:#fff;padding:7px 16px;border:0;border-radius:6px;font-weight:bold;}
        .delbtn:active{background:#bd2737;}
        .change-admin-form{display:flex;gap:8px;margin-top:12px;}
        .change-admin-form input{flex:1;}
        .logout{position:absolute;top:18px;right:34px;background:#fff2;padding:6px 18px;border-radius:18px;font-weight:700;color:#c31d33;border:none;}
        .toast{padding:10px 0;text-align:center;border-radius:8px;font-size:1.09em;margin-bottom:16px;}
        .success{background:#c2ffd0;color:#0b6117;}
        .error{background:#ffd2d2;color:#a31a2a;}
        .info{background:#e8f5ff;color:#2271b3;}
        @media(max-width:750px){.main-card{padding:16px 3vw;}.server-row{flex-direction:column;align-items:flex-start;}.logout{right:10px;}}
      </style>
    </head>
    <body>
      <form method="post" action="/logout"><button class="logout">Logout</button></form>
      <div class="main-card">
        <h2>OpenConnect VPN Admin Panel</h2>
        <div class="server-row">
          <div class="tag">Server IP</div>
          <div>
            <span id="ipcopy">{{server_ip}}</span>
            <button class="copy-btn" onclick="copyText('{{server_ip}}')">Copy</button>
          </div>
          <div class="tag">VPN Port</div>
          <div>
            <span id="portcopy">{{panel_port}}</span>
            <button class="copy-btn" onclick="copyText('{{panel_port}}')">Copy</button>
          </div>
        </div>
        {% for cat,msg in get_flashed_messages(with_categories=true) %}
          <div class="toast {{cat}}">{{msg}}</div>
        {% endfor %}
        <div class="form-row">
          <form method="post" action="/add_user" style="display:flex;gap:6px;width:100%;">
            <input name="username" placeholder="username" required minlength=2>
            <input name="password" placeholder="password" required minlength=3>
            <button>Add User</button>
          </form>
        </div>
        <b style="font-weight:700;">All VPN Users</b>
        <table>
          <tr><th>Username</th><th>Password</th><th>Delete</th></tr>
          {% for user in users %}
          <tr>
            <td>{{user.username}}</td>
            <td>{{user.password}}</td>
            <td>
              <form method="post" action="/del_user" style="display:inline;">
                <input type="hidden" name="username" value="{{user.username}}">
                <button class="delbtn">Delete</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </table>
        <div style="margin-top:18px;">
          <b>Change Admin Password:</b>
          <form method="post" action="/change_admin" class="change-admin-form">
            <input name="oldpass" type="password" placeholder="Old (5 chars)" required minlength=5 maxlength=5>
            <input name="newpass" type="password" placeholder="New (2UC+3NUM)" required minlength=5 maxlength=5>
            <button>Change</button>
          </form>
        </div>
        <div style="margin-top:16px;font-size:.97em;color:#888;">
          <b>Panel:</b> {{admin.username}} <br>
          Max Users: <b>{{max_users}}</b> (fixed) <br>
          Recover admin: <code>sudo get_admin_info</code>
        </div>
      </div>
      <script>
        function copyText(text) {
          navigator.clipboard.writeText(text);
          alert('Copied: ' + text);
          return false;
        }
      </script>
    </body>
    </html>
    ''', users=users, max_users=MAX_USERS, admin=admin, server_ip=server_ip, panel_port=panel_port)

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'admin' not in session: return redirect(url_for('login'))
    uname = request.form['username'].strip()
    pword = request.form['password'].strip()
    if not uname or not pword:
        flash('Username and password required.', 'error')
        return redirect(url_for('dashboard'))
    subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
    added = add_user_csv(uname, pword)
    if added:
        flash('User added!', 'success')
        subprocess.call("systemctl restart ocserv", shell=True)
    else:
        flash('User already exists.', 'error')
    return redirect(url_for('dashboard'))

@app.route('/del_user', methods=['POST'])
def del_user():
    if 'admin' not in session: return redirect(url_for('login'))
    uname = request.form['username']
    if uname:
        subprocess.call(f"ocpasswd -d {uname}", shell=True)
        delete_user_csv(uname)
        flash(f'User {uname} deleted.', 'success')
        subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/change_admin', methods=['POST'])
def change_admin():
    if 'admin' not in session: return redirect(url_for('login'))
    old = request.form['oldpass'].strip()
    new = request.form['newpass'].strip()
    admin = load_admin()
    if old == admin['password']:
        if len(new) == 5 and new[:2].isupper() and new[2:].isdigit():
            admin['password'] = new
            save_admin(admin)
            flash('Password changed.', 'success')
        else:
            flash('Password must be 2 capital letters + 3 numbers (eg: AB123)', 'error')
    else:
        flash('Old password wrong', 'error')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PANEL_PORT)

EOF

# admin info recovery CLI
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

# systemd service for admin panel
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
