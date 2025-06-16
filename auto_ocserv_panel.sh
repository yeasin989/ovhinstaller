#!/bin/bash
set -e

PANEL_PORT=8080
PANEL_DIR="/opt/ocserv-admin"
ADMIN_USER="admin"
ADMIN_PASS=$(tr -dc 'A-Z' </dev/urandom | head -c2)$(tr -dc '0-9' </dev/urandom | head -c3)
ADMIN_INFO="$PANEL_DIR/admin.json"
CSV_FILE="/root/vpn_users.csv"
USER_FILE="/etc/ocserv/ocpasswd"

echo "[*] Installing dependencies..."
apt update
apt install -y python3 python3-pip python3-venv ocserv curl

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

# --- FIX: Always create CSV with header if missing ---
if [ ! -f "$CSV_FILE" ]; then
    echo "username,password" > "$CSV_FILE"
fi
chmod 666 "$CSV_FILE"

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
        # Reliable external IP detection
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
            # Always skip header row, even if double
            for row in reader:
                if row and row[0] == 'username':
                    continue
                if len(row) >= 2:
                    users.append({'username': row[0], 'password': row[1]})
    return users
def get_connected():
    try:
        out = subprocess.check_output("occtl show users | grep Username | awk '{print $2}'", shell=True)
        names = out.decode().split()
        return len(names), names
    except:
        return 0, []

def add_user_csv(username, password):
    exists = False
    users = []
    # Read all users, skip header
    with open(CSV_FILE) as f:
        for row in csv.reader(f):
            if row and row[0] == username:
                exists = True
            users.append(row)
    if not exists:
        # Append new user
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
        <div class="toast">{% with messages = get_flashed_messages(with_categories=true) %}
            {% for cat,msg in messages %}{% if cat=='error' %}{{msg}}{% endif %}{% endfor %}{% endwith %}</div>
      </form>
    </body></html>
    ''')

@app.route('/dashboard')
def dashboard():
    if 'admin' not in session: return redirect(url_for('login'))
    users = get_users()
    connected_count, connected_users = get_connected()
    admin = load_admin()
    server_ip = get_ip()
    panel_port = PANEL_PORT
    # get toasts
    toast = None
    toast_cat = None
    messages = []
    for cat,msg in list(getattr(session, '_flashes', []) or []):
        messages.append((cat,msg))
    session._flashes = []
    return render_template_string('''
    <html><head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>VPN Admin Panel</title>
    <style>
    body{background:#f6f8fa;font-family:sans-serif;margin:0;}
    .card{background:#fff;padding:24px 18px;border-radius:18px;box-shadow:0 4px 32px #0002;max-width:540px;margin:30px auto;}
    .row{display:flex;gap:22px;flex-wrap:wrap;}
    h2{color:#1e2b48;margin-bottom:12px;}
    input,select{padding:8px 8px;border-radius:6px;border:1px solid #ccd;}
    button{background:#1e89e7;color:#fff;border:0;padding:8px 20px;border-radius:6px;font-weight:bold;margin-left:4px;}
    .logout{position:absolute;top:16px;right:24px;}
    table{width:100%;margin:12px 0 0 0;border-collapse:collapse;}
    th,td{padding:9px 4px;text-align:left;}
    tr:nth-child(even){background:#f4f6fa;}
    th{background:#e7e9f0;}
    .delbtn{background:#e9435b;}
    .toast{padding:10px;text-align:center;border-radius:8px;font-size:1.08em;margin-bottom:10px;}
    .success{background:#b0faad;color:#20621d;}
    .error{background:#ffd3d3;color:#b93333;}
    .info{background:#e4f1fd;color:#2271b3;}
    @media (max-width:650px){.card{padding:10px;}.row{flex-direction:column;}}
    </style>
    </head>
    <body>
      <form method="post" action="/logout"><button class="logout">Logout</button></form>
      <div class="card">
      <h2>OpenConnect VPN Admin Panel</h2>
      <div style="margin-bottom:12px;">
        <b>Server IP:</b> <code>{{server_ip}}:{{panel_port}}</code>
      </div>
      {% for cat,msg in messages %}
        <div class="toast {{cat}}">{{msg}}</div>
      {% endfor %}
      <div class="row" style="margin-bottom:12px;">
        <div><b>Connected users:</b> {{connected_count}} / {{max_users}}</div>
        <div><b>Now connected:</b> {% for u in connected_users %} <code>{{u}}</code> {% endfor %}</div>
      </div>
      <div class="row" style="margin-bottom:15px;">
        <b>Add VPN User:</b>
        <form method="post" action="/add_user" style="display:flex;gap:6px;">
          <input name="username" placeholder="username" required minlength=2>
          <input name="password" placeholder="password" required minlength=3>
          <button>Add</button>
        </form>
      </div>
      <b>All Users:</b>
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
        <form method="post" action="/change_admin" style="display:flex;gap:5px;">
          <input name="oldpass" type="password" placeholder="Old (5 chars)" required minlength=5 maxlength=5>
          <input name="newpass" type="password" placeholder="New (2UC+3NUM)" required minlength=5 maxlength=5>
          <button>Change</button>
        </form>
      </div>
      <div style="margin-top:16px;font-size:.92em;color:#888;">
        <b>Panel:</b> {{admin.username}} <br>
        Max Users: <b>{{max_users}}</b> (fixed) <br>
        To recover admin: <code>sudo get_admin_info</code>
      </div>
      </div>
    </body></html>
    ''', users=users, connected_count=connected_count, connected_users=connected_users, max_users=MAX_USERS, admin=admin, server_ip=server_ip, panel_port=panel_port, messages=messages)

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

# systemd service
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
sudo systemctl restart ocserv-admin

IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
echo "========================================="
echo "✅ OpenConnect Admin Panel Installed!"
echo "URL: http://$IP:8080"
echo "Admin Username: $ADMIN_USER"
echo "Admin Password: $ADMIN_PASS"
echo "Recover admin: sudo get_admin_info"
echo "========================================="
