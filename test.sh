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

# Create ocserv.conf
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $VPN_PORT
udp-port = $VPN_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
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

netfilter-persistent save

touch "$USER_FILE"
chmod 600 "$USER_FILE"

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

cat > $PANEL_DIR/app.py <<"EOF"
import os, json, subprocess, csv, socket
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
CSV_FILE = '/root/vpn_users.csv'
USER_FILE = '/etc/ocserv/ocpasswd'
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
    <html><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VPN Admin Login</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter:400,700&display=swap">
    <style>
    body{background:#191f2a;font-family:Inter,sans-serif;}
    .login{max-width:350px;margin:80px auto;background:#fff;border-radius:14px;padding:32px;box-shadow:0 6px 24px #0002;}
    h2{margin-top:0;color:#1e2b48;}
    input{margin-bottom:12px;width:100%;padding:12px;border-radius:6px;border:1px solid #c4c4c4;}
    button{width:100%;padding:12px;border:0;border-radius:6px;background:#1e89e7;color:#fff;font-weight:bold;font-size:1.1em;}
    .toast{color:red;margin-top:10px;text-align:center;}
    @media(max-width:600px){.login{padding:18px;}}
    </style>
    </head><body>
      <form class="login" method=post autocomplete="off">
        <h2>VPN Admin Login</h2>
        <input name=username placeholder="admin" required>
        <input name=password type=password placeholder="password" required>
        <button>Login</button>
        <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
      </form>
    </body></html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session: return redirect(url_for('login'))
    users = get_users()
    admin = load_admin()
    server_ip = get_ip()
    panel_port = PANEL_PORT
    messages = []
    for cat,msg in list(getattr(session, '_flashes', []) or []):
        messages.append((cat,msg))
    session._flashes = []
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en"><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OpenConnect Admin Panel</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Inter:400,700&display=swap">
    <style>
    body{margin:0;background:#eef2fa;font-family:Inter,sans-serif;}
    .header{background:#183153;color:#fff;padding:18px 0 10px 0;text-align:center;box-shadow:0 4px 16px #0002;}
    .container{max-width:520px;margin:36px auto;padding:22px 16px;background:#fff;border-radius:22px;box-shadow:0 4px 32px #0002;}
    .row{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:18px;}
    .title{font-size:2em;font-weight:700;letter-spacing:-1px;margin:0 0 10px 0;}
    .input,select{padding:10px 12px;border-radius:7px;border:1px solid #b0b7c3;width:100%;margin-bottom:0;}
    .btn{background:#1669f0;color:#fff;border:0;padding:9px 18px;border-radius:8px;font-weight:700;font-size:1em;transition:.2s;}
    .btn:hover{background:#124eaa;}
    .delbtn{background:#e9435b;}
    .delbtn:hover{background:#b93333;}
    .copybtn{background:#f7f7f7;border:1px solid #bcd;width:32px;height:32px;border-radius:8px;padding:0;margin-left:7px;cursor:pointer;}
    .copybtn:active{background:#eef;}
    .field{font-size:1.13em;}
    table{width:100%;margin-top:14px;border-collapse:collapse;}
    th,td{padding:9px 6px;text-align:left;}
    tr:nth-child(even){background:#f4f6fa;}
    th{background:#e7e9f0;}
    .card{background:#f9fbfe;padding:17px;border-radius:14px;margin-bottom:14px;box-shadow:0 2px 12px #0001;}
    .toast{padding:10px 0;text-align:center;border-radius:8px;font-size:1.06em;margin-bottom:9px;}
    .success{background:#b0faad;color:#20621d;}
    .error{background:#ffd3d3;color:#b93333;}
    @media (max-width:600px){
        .container{padding:10px;}
        .row{flex-direction:column;gap:7px;}
        .title{font-size:1.4em;}
    }
    </style>
    <script>
    function copyText(id) {
        const inp = document.getElementById(id);
        navigator.clipboard.writeText(inp.innerText||inp.value||'');
        const btn = document.getElementById('btn-'+id);
        btn.innerHTML = '✓';
        setTimeout(()=>{btn.innerHTML='📋'}, 1000);
    }
    </script>
    </head>
    <body>
      <div class="header">
        <div class="title">OpenConnect VPN Admin</div>
        <form style="position:absolute;top:20px;right:22px;" method="post" action="/logout">
          <button class="btn" style="padding:6px 12px;font-size:.97em;">Logout</button>
        </form>
      </div>
      <div class="container">
      {% for cat,msg in messages %}
        <div class="toast {{cat}}">{{msg}}</div>
      {% endfor %}
      <div class="card">
        <div class="row">
          <div class="field"><b>Server IP</b>: <span id="clip-ip">{{server_ip}}</span>
            <button class="copybtn" id="btn-clip-ip" onclick="copyText('clip-ip')" title="Copy IP">📋</button>
          </div>
          <div class="field"><b>Port</b>: <span id="clip-port">{{panel_port}}</span>
            <button class="copybtn" id="btn-clip-port" onclick="copyText('clip-port')" title="Copy Port">📋</button>
          </div>
        </div>
      </div>
      <div class="card" style="margin-bottom:22px;">
        <div style="font-weight:500;margin-bottom:10px;">Add VPN User:</div>
        <form method="post" action="/add_user" class="row" style="gap:8px;">
          <input name="username" class="input" placeholder="username" required minlength=2 style="max-width:180px;">
          <input name="password" class="input" placeholder="password" required minlength=3 style="max-width:180px;">
          <button class="btn">Add</button>
        </form>
      </div>
      <div class="card">
        <b style="font-size:1.12em;">All Users</b>
        <table>
          <tr><th>Username</th><th>Password</th><th>Copy</th><th>Delete</th></tr>
          {% for user in users %}
          <tr>
            <td><span id="clip-u{{loop.index}}">{{user.username}}</span></td>
            <td><span id="clip-p{{loop.index}}">{{user.password}}</span></td>
            <td>
              <button class="copybtn" id="btn-clip-u{{loop.index}}" onclick="copyText('clip-u{{loop.index}}')" title="Copy Username">📋</button>
              <button class="copybtn" id="btn-clip-p{{loop.index}}" onclick="copyText('clip-p{{loop.index}}')" title="Copy Password">📋</button>
            </td>
            <td>
              <form method="post" action="/del_user" style="display:inline;">
                <input type="hidden" name="username" value="{{user.username}}">
                <button class="delbtn btn" style="padding:6px 14px;">Delete</button>
              </form>
            </td>
          </tr>
          {% endfor %}
        </table>
      </div>
      <div class="card">
        <b>Change Admin Password:</b>
        <form method="post" action="/change_admin" class="row" style="gap:7px;">
          <input name="oldpass" class="input" type="password" placeholder="Old (5 chars)" required minlength=5 maxlength=5>
          <input name="newpass" class="input" type="password" placeholder="New (2UC+3NUM)" required minlength=5 maxlength=5>
          <button class="btn">Change</button>
        </form>
        <div style="margin-top:7px;font-size:.97em;color:#888;">
          Panel: <b>{{admin.username}}</b> <br>
          <span>To recover admin: <code>sudo get_admin_info</code></span>
        </div>
      </div>
      </div>
    </body>
    </html>
    ''', users=users, admin=admin, server_ip=server_ip, panel_port=panel_port, messages=messages)

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
