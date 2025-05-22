#!/bin/bash
set -e

NUM_USERS=5000
USER_FILE="/etc/ocserv/ocpasswd"
CSV_FILE="/root/vpn_users.csv"

# Update & install
apt-get update
apt-get install -y ocserv openssl pwgen

# Server IP detection
IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')

# Generate cert
CERT_DIR="/etc/ocserv/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$IP"

# Basic config
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = 443
udp-port = 443
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

# Open firewall
if command -v ufw &>/dev/null; then
    ufw allow 443/tcp
    ufw allow 443/udp
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --add-port=443/tcp --permanent
    firewall-cmd --add-port=443/udp --permanent
    firewall-cmd --reload
else
    iptables -I INPUT -p tcp --dport 443 -j ACCEPT
    iptables -I INPUT -p udp --dport 443 -j ACCEPT
fi

# Create users
> "$USER_FILE"
echo "username,password" > "$CSV_FILE"

# Generate random users (user+pass: 4-6 chars, letters+digits)
for i in $(seq 1 $NUM_USERS); do
    uname=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c$((RANDOM%3+4)))
    pass=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c$((RANDOM%3+4)))
    ocpasswd -c "$USER_FILE" -g default -B "$uname" <<<"$pass"$'\n'"$pass"
    echo "$uname,$pass" >> "$CSV_FILE"
    if [[ $i -eq 1 ]]; then
        FIRST_USER="$uname"
        FIRST_PASS="$pass"
    fi
done

systemctl restart ocserv
systemctl enable ocserv

clear
echo ""
echo "✅ OpenConnect VPN Installed!"
echo "=============================="
echo "Server IP      : $IP"
echo "Username       : $FIRST_USER"
echo "Password       : $FIRST_PASS"
echo "=============================="
echo ""
echo "To see all users, check $CSV_FILE"
echo ""
echo "You can now connect using any OpenConnect client!"
