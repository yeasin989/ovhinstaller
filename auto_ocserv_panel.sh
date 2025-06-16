#!/bin/bash
# OpenConnect + Modern Admin Panel Automated Installer
# Make this file executable on GitHub (chmod +x) or run via bash <(curl...)

set -e
PANEL_PORT=8080
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
ADMIN_INFO="$PANEL_DIR/admin.json"
PYTHON_BIN="/usr/bin/python3"

echo "[*] Installing dependencies..."
apt update
apt install -y ocserv python3 python3-pip python3-venv curl iproute2 openssl pwgen

echo "[*] Creating admin panel directory..."
mkdir -p $PANEL_DIR

echo "[*] Creating Python virtual environment..."
cd $PANEL_DIR
$PYTHON_BIN -m venv venv
source venv/bin/activate

echo "[*] Installing Flask..."
pip install flask flask-login flask-wtf

# Generate initial admin info
cat > $ADMIN_INFO <<EOF
{
    "username": "$ADMIN_USER",
    "password": "$ADMIN_PASS"
}
EOF

# Generate get_admin_info recovery tool
cat > /usr/local/bin/get_admin_info <<EOF
#!/bin/bash
cat $ADMIN_INFO
EOF
chmod +x /usr/local/bin/get_admin_info

# Create requirements.txt
cat > $PANEL_DIR/requirements.txt <<EOF
flask
flask-login
flask-wtf
EOF

# Write Flask admin panel (see below for code)
cat > $PANEL_DIR/app.py <<"EOF"
# [FLASK ADMIN PANEL CODE BELOW, DO NOT MODIFY THIS LINE]
import os, json, subprocess
from flask import Flask, render_template_string, request, redirect, url_for, session, flash

ADMIN_INFO = '/opt/ocserv-admin/admin.json'
USER_FILE = '/etc/ocserv/ocpasswd'
CONF_FILE = '/etc/ocserv/ocserv.conf'
SECRET_KEY = os.urandom(24)

app = Flask(__name__)
app.secret_key = SECRET_KEY

def load_admin():
    with open(ADMIN_INFO) as f:
        return json.load(f)
def save_admin(admin):
    with open(ADMIN_INFO, 'w') as f:
        json.dump(admin, f)
def get_stats():
    max_clients = 0
    with open(CONF_FILE) as f:
        for line in f:
            if line.strip().startswith('max-clients'):
                max_clients = int(line.split()[2])
    connected = int(subprocess.getoutput("occtl show users | grep -c Username || true"))
    return type('obj', (object,), {"max_clients": max_clients, "connected": connected})

def get_users():
    users = []
    with open(USER_FILE) as f:
        for line in f:
            if ':' in line:
                users.append(line.split(':')[0])
    return users

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'admin' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        creds = load_admin()
        if (request.form['username'] == creds['username'] and request.form['password'] == creds['password']):
            session['admin'] = True
            return redirect(url_for('dashboard'))
        flash('Login failed.')
    return render_template_string('''
    <html>
    <head><title>OpenConnect Admin Login</title>
    <style>
      body{background:#191f2a;font-family:sans-serif;}
      .login{max-width:330px;margin:80px auto;background:#fff;border-radius:14px;padding:32px;box-shadow:0 6px 24px #0002;}
      h2{margin-top:0;color:#1e2b48;}
      input{margin-bottom:12px;width:100%;padding:12px;border-radius:6px;border:1px solid #c4c4c4;}
      button{width:100%;padding:12px;border:0;border-radius:6px;background:#1e89e7;color:#fff;font-weight:bold;font-size:1.1em;}
    </style>
    </head>
    <body>
      <form class="login" method=post>
        <h2>VPN Admin Login</h2>
        <input name=username placeholder="admin" required>
        <input name=password type=password placeholder="password" required>
        <button>Login</button>
        <p style="color:red;">{% with messages = get_flashed_messages() %}{% for m in messages %}{{m}}{% endfor %}{% endwith %}</p>
      </form>
    </body></html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session: return redirect(url_for('login'))
    stats = get_stats()
    users = get_users()
    with open(ADMIN_INFO) as f: admin = json.load(f)
    return render_template_string('''
    <html>
    <head>
    <title>OpenConnect VPN Dashboard</title>
    <style>
      body{background:#f6f8fa;font-family:sans-serif;}
      .card{background:#fff;padding:32px 28px;border-radius:18px;box-shadow:0 4px 32px #0002;max-width:530px;margin:30px auto;}
      .row{display:flex;gap:24px;justify-content:space-between;}
      h2{color:#1e2b48;}
      input,select{padding:9px 10px;border-radius:6px;border:1px solid #ccd;}
      button{background:#1e89e7;color:#fff;border:0;padding:10px 24px;border-radius:6px;font-weight:bold;margin-left:6px;}
      .logout{position:absolute;top:30px;right:60px;}
      @media (max-width:600px){.card{padding:15px;}.row{flex-direction:column;}}
    </style>
    </head>
    <body>
      <form method="post" action="/logout"><button class="logout">Logout</button></form>
      <div class="card">
      <h2>OpenConnect VPN Dashboard</h2>
      <div class="row">
        <div>
          <b>Users:</b> {{stats.connected}} / {{stats.max_clients}}
        </div>
        <div>
          <form method="post" action="/edit_max_users" style="display:inline;">
            <input name="max_clients" value="{{stats.max_clients}}" size=6>
            <button>Set Max Users</button>
          </form>
        </div>
      </div>
      <div style="margin:16px 0;">
        <b>All VPN Users:</b>
        <ul>
          {% for u in users %}
          <li style="margin:3px 0;">
            <form method="post" action="/del_user" style="display:inline;">
              <input type="hidden" name="username" value="{{u}}">
              {{u}}
              <button style="background:#e9435b;">Delete</button>
            </form>
          </li>
          {% endfor %}
        </ul>
      </div>
      <div>
        <b>Add New User:</b>
        <form method="post" action="/add_user" class="row">
          <input name="username" placeholder="username" required>
          <input name="password" placeholder="password" required>
          <button>Add User</button>
        </form>
      </div>
      <div style="margin-top:24px;">
        <b>Change Admin Password:</b>
        <form method="post" action="/change_admin" class="row">
          <input name="oldpass" type="password" placeholder="Old Password" required>
          <input name="newpass" type="password" placeholder="New Password" required>
          <button>Change</button>
        </form>
      </div>
      <div style="margin-top:28px;font-size:.92em;color:#777;">
        Panel running as <b>{{admin.username}}</b>.<br>
        CLI admin info: <code>sudo get_admin_info</code>
      </div>
      </div>
    </body></html>
    ''', stats=stats, users=users, admin=admin)

@app.route('/add_user', methods=['POST'])
def add_user():
    if 'admin' not in session: return redirect(url_for('login'))
    uname = request.form['username'].strip()
    pword = request.form['password'].strip()
    if not uname or not pword: return redirect(url_for('dashboard'))
    subprocess.call(f"echo '{pword}\n{pword}' | ocpasswd -g default {uname}", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/del_user', methods=['POST'])
def del_user():
    if 'admin' not in session: return redirect(url_for('login'))
    uname = request.form['username']
    if uname: subprocess.call(f"ocpasswd -d {uname}", shell=True)
    return redirect(url_for('dashboard'))

@app.route('/edit_max_users', methods=['POST'])
def edit_max_users():
    if 'admin' not in session: return redirect(url_for('login'))
    val = request.form['max_clients'].strip()
    try:
        num = int(val)
        lines = []
        changed = False
        with open(CONF_FILE) as f:
            for line in f:
                if line.strip().startswith('max-clients'):
                    lines.append(f"max-clients = {num}\n")
                    changed = True
                else:
                    lines.append(line)
        if not changed:
            lines.append(f"max-clients = {num}\n")
        with open(CONF_FILE, "w") as f: f.writelines(lines)
        subprocess.call("systemctl restart ocserv", shell=True)
    except Exception: pass
    return redirect(url_for('dashboard'))

@app.route('/change_admin', methods=['POST'])
def change_admin():
    if 'admin' not in session: return redirect(url_for('login'))
    old = request.form['oldpass'].strip()
    new = request.form['newpass'].strip()
    admin = load_admin()
    if old == admin['password'] and len(new) >= 6:
        admin['password'] = new
        save_admin(admin)
    else:
        flash('Old password wrong or new too short (min 6)')
    return redirect(url_for('dashboard'))

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('admin', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
EOF

echo "[*] Creating systemd service..."
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
systemctl enable --now ocserv-admin

# Output info
IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
echo "========================================="
echo "✅ OpenConnect Admin Panel Installed!"
echo "URL: http://$IP:8080"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="
