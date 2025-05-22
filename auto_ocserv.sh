#!/bin/bash
set -e

NUM_USERS=5000
USER_FILE="/etc/ocserv/ocpasswd"
CSV_FILE="/root/vpn_users.csv"
OCSERV_PORT=4443    # No conflict with OpenVPN default
SOCKET_FILE="/run/ocserv.socket"

# Install ocserv and tools
apt-get update
apt-get install -y ocserv openssl pwgen curl iproute2

# Get public IP
IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')

# Detect default network interface (used for NAT)
IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [ -z "$IFACE" ]; then
    echo "Could not detect default network interface. Please check manually."
    exit 1
fi

# Enable IP forwarding
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-ocserv-forward.conf
sysctl -w net.ipv4.ip_forward=1

# Setup NAT/Masquerading
iptables -t nat -A POSTROUTING -s 192.168.150.0/24 -o "$IFACE" -j MASQUERADE
# Save iptables rule
apt-get install -y iptables-persistent
netfilter-persistent save

# Generate self-signed cert
CERT_DIR="/etc/ocserv/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$IP"

# Create ocserv.conf with all required options (socket-file, device, etc)
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $OCSERV_PORT
udp-port = $OCSERV_PORT
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

# Open firewall for OpenConnect port
if command -v ufw &>/dev/null; then
    ufw allow ${OCSERV_PORT}/tcp > /dev/null 2>&1
    ufw allow ${OCSERV_PORT}/udp > /dev/null 2>&1
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --add-port=${OCSERV_PORT}/tcp --permanent
    firewall-cmd --add-port=${OCSERV_PORT}/udp --permanent
    firewall-cmd --reload
else
    iptables -I INPUT -p tcp --dport ${OCSERV_PORT} -j ACCEPT
    iptables -I INPUT -p udp --dport ${OCSERV_PORT} -j ACCEPT
fi

# Create users (First uppercase, 2-4 lowercase, last digit; total 4-6 chars)
> "$USER_FILE"
echo "username,password" > "$CSV_FILE"

for i in $(seq 1 $NUM_USERS); do
    uname_first=$(tr -dc 'A-Z' < /dev/urandom | head -c1)
    uname_middle=$(tr -dc 'a-z' < /dev/urandom | head -c$((RANDOM%3+2)))  # 2 to 4
    uname_last=$(tr -dc '0-9' < /dev/urandom | head -c1)
    uname="${uname_first}${uname_middle}${uname_last}"

    pass_first=$(tr -dc 'A-Z' < /dev/urandom | head -c1)
    pass_middle=$(tr -dc 'a-z' < /dev/urandom | head -c$((RANDOM%3+2)))
    pass_last=$(tr -dc '0-9' < /dev/urandom | head -c1)
    pass="${pass_first}${pass_middle}${pass_last}"

    if [[ $i -eq 1 ]]; then
        ocpasswd -c "$USER_FILE" -g default "$uname" <<<"$pass"$'\n'"$pass"
        FIRST_USER="$uname"
        FIRST_PASS="$pass"
    else
        ocpasswd -g default "$uname" <<<"$pass"$'\n'"$pass"
    fi
    echo "$uname,$pass" >> "$CSV_FILE"
done

systemctl restart ocserv
systemctl enable ocserv

# === Admin status tool ===
cat >/usr/local/bin/server_status <<'EOSTATUS'
#!/bin/bash
CSV_FILE="/root/vpn_users.csv"
CONF_FILE="/etc/ocserv/ocserv.conf"

USER_COUNT=$(($(wc -l < $CSV_FILE) - 1))
MAX_CLIENTS=$(grep max-clients $CONF_FILE | awk '{print $3}')
OCSERV_PORT=$(grep tcp-port $CONF_FILE | awk '{print $3}')
IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')
CONNECTED=$(sudo occtl show users | grep -c Username)
UPTIME=$(uptime -p)
MEMORY=$(free -h | awk '/^Mem/ {print $3 "/" $2}')
DISK=$(df -h / | awk '$NF=="/"{print $3 "/" $2 " (" $5 " used)"}')
CONNECTED_USERS=$(sudo occtl show users | grep Username | awk '{print $2}' | tr '\n' ' ')

echo ""
echo "========== OpenConnect VPN Server Status =========="
echo "Server IP                 : $IP"
echo "OpenConnect Port          : $OCSERV_PORT"
echo "Total user accounts       : $USER_COUNT"
echo "Maximum simultaneous users: $MAX_CLIENTS"
echo "Currently connected users : $CONNECTED"
echo "Connected usernames       : $CONNECTED_USERS"
echo "Server uptime             : $UPTIME"
echo "RAM usage                 : $MEMORY"
echo "Disk usage (root)         : $DISK"
echo "Config file               : $CONF_FILE"
echo "Users file (CSV)          : $CSV_FILE"
echo "==================================================="
echo ""
EOSTATUS

chmod +x /usr/local/bin/server_status

clear
echo ""
echo "✅ OpenConnect (ocserv) Installed!"
echo "======================================="
echo "Server IP   : $IP"
echo "Port        : $OCSERV_PORT"
echo "Username    : $FIRST_USER"
echo "Password    : $FIRST_PASS"
echo "======================================="
echo ""
echo "• Connect using any OpenConnect client."
echo "• To see all users, check: $CSV_FILE"
echo ""
echo "• To check server status at any time, run: server_status"
echo ""
echo "• You can safely install OpenVPN Access Server as usual."
echo "   It will use UDP 1194 for VPN and TCP 943/9443 for web."
echo ""
echo "Enjoy dual VPN hosting! Update 2025"
