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

# Create ocserv.conf
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

# Firewall
echo "[*] Opening firewall for VPN port $VPN_PORT..."
if command -v ufw &>/dev/null; then
    ufw allow $VPN_PORT/tcp || true
    ufw allow $VPN_PORT/udp || true
    ufw reload || true
else
    iptables -I INPUT -p tcp --dport $VPN_PORT -j ACCEPT || true
    iptables -I INPUT -p udp --dport $VPN_PORT -j ACCEPT || true
fi

# Enable IP forwarding and NAT
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE || true
netfilter-persistent save

# User database
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

# Flask app.py (responsive modern UI, copy, single/mass delete, no connected users)
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
def delete_all_users():
    with open(CSV_FILE, 'w') as f:
        f.write("username,password\n")
    subprocess.call(f"> {USER_FILE}", shell=True)
    subprocess.call("systemctl restart ocserv", shell=True)

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
    <style>
    body{background:#161B22;font-family:sans-serif;}
    .login{max-width:350px;margin:80px auto;background:#222C36;border-radius:16px;padding:32px;box-shadow:0 8px 40px #0006;}
    h2{margin-top:0;color:#5EA3F7;}
    input{margin-bottom:12px;width:100%;padding:12px;border-radius:6px;border:1px solid #222;}
    button{width:100%;padding:12px;border:0;border-radius:6px;background:#4F8CFF;color:#fff;font-weight:bold;font-size:1.15em;}
    .toast{color:red;margin-top:10px;text-align:center;}
    @media(max-width:600px){.login{padding:18px;}}
    </style>
    </head><body>
      <form class="login" method=post>
        <h2>Admin Login</h2>
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
    return render_template_string('''
    <html><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>OpenConnect Admin Panel</title>
    <style>
    body{margin:0;background:#171D2A;color:#EEE;font-family:sans-serif;}
    .container{max-width:540px;margin:0 auto;padding:18px;}
    .card{background:#232E40;padding:26px 18px 18px 18px;border-radius:20px;box-shadow:0 4px 32px #0005;}
    h2{color:#6FB5FF;margin:0 0 18px 0;}
    .info-box{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;}
    .ipcopy{background:#2D3A51;padding:9px 12px;border-radius:7px;display:flex;align-items:center;gap:7px;}
    .copybtn{background:#3D8BFF;color:#fff;border:0;padding:6px 12px;border-radius:6px;font-weight:bold;cursor:pointer;font-size:.95em;}
    .table-wrap{overflow-x:auto;margin-bottom:18px;}
    table{width:100%;margin:0;border-collapse:collapse;font-size:.98em;}
    th,td{padding:7px 3px;text-align:left;}
    tr:nth-child(even){background:#232E40;}
    th{background:#293448;}
    .delbtn{background:#FF4757;color:#fff;padding:5px 15px;border:0;border-radius:5px;cursor:pointer;}
    .massdel{background:#F84B8A;padding:8px 18px;font-weight:bold;border-radius:7px;float:right;}
    input{padding:8px;border-radius:6px;border:1px solid #2D3A51;}
    button{padding:8px 18px;border-radius:6px;border:0;background:#54A0FF;color:#fff;font-weight:bold;margin-left:6px;}
    .logout{float:right;margin-top:-6px;background:#2C3E5C;}
    .msg{margin:10px 0;color:#5EF574;}
    @media (max-width:700px){.container{padding:4px;}.card{padding:14px 3px 8px 3px;}}
    </style>
    <script>
    function copyText(text){
        navigator.clipboard.writeText(text);
        alert('Copied: '+text);
    }
    function delAllUsers(){
        if(confirm('Delete ALL VPN users? This cannot be undone!')) {
            fetch('/delete_all_users', {method:'POST'}).then(()=>{window.location.reload();});
        }
    }
    </script>
    </head><body>
    <div class="container">
    <form method="post" action="/logout"><button class="logout">Logout</button></form>
    <div class="card">
    <h2>OpenConnect Admin Panel</h2>
    <div class="info-box">
      <div>
        <b>Server IP:</b> <span class="ipcopy">{{server_ip}}:<b>{{panel_port}}</b>
        <button type="button" class="copybtn" onclick="copyText('{{server_ip}}:{{panel_port}}')">Copy</button></span>
      </div>
    </div>
    <div style="margin-bottom:18px;"><b>VPN Address:</b>
      <span class="ipcopy">{{server_ip}}:<b>{{vpn_port}}</b>
        <button type="button" class="copybtn" onclick="copyText('{{server_ip}}:{{vpn_port}}')">Copy</button></span>
    </div>
    <form method="post" action="/add_user" style="display:flex;gap:6px;margin-bottom:14px;">
      <input name="username" placeholder="username" required minlength=2>
      <input name="password" placeholder="password" required minlength=3>
      <button>Add User</button>
    </form>
    <div class="table-wrap">
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
    </div>
    <button class="massdel" type="button" onclick="delAllUsers()">Delete All Users</button>
    <div style="margin-top:16px;font-size:.93em;color:#8bc;">
      <b>Panel:</b> {{admin.username}}<br>
      Max Users: <b>{{max_users}}</b> (fixed)<br>
      To recover admin: <code>sudo get_admin_info</code>
    </div>
    </div></div>
    </body></html>
    ''', users=users, admin=admin, server_ip=server_ip, panel_port=panel_port, vpn_port=VPN_PORT, max_users=MAX_USERS)

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
        subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/del_user', methods=['POST'])
def del_user():
    if 'admin' not in session: return redirect(url_for('login'))
    uname = request.form['username']
    if uname:
        subprocess.call(f"ocpasswd -d {uname}", shell=True)
        delete_user_csv(uname)
        subprocess.call("systemctl restart ocserv", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/delete_all_users', methods=['POST'])
def delete_all_users_route():
    if 'admin' not in session: return redirect(url_for('login'))
    delete_all_users()
    return ('', 204)

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
echo "Admin Panel: http://$IP:$PANEL_PORT"
echo "VPN Connect to: $IP:$VPN_PORT"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="
