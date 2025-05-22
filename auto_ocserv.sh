#!/bin/bash
set -e

NUM_USERS=5000
USER_FILE="/etc/ocserv/ocpasswd"
CSV_FILE="/root/vpn_users.csv"
OCSERV_PORT=4443    # recommended port for OpenConnect when OpenVPN is also installed

# Install ocserv and tools
apt-get update
apt-get install -y ocserv openssl pwgen curl

# Get public IP
IP=$(curl -s ipv4.icanhazip.com || hostname -I | awk '{print $1}')

# Generate self-signed cert
CERT_DIR="/etc/ocserv/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -subj "/C=US/ST=NA/L=NA/O=NA/CN=$IP"

# Create ocserv.conf with custom port
cat >/etc/ocserv/ocserv.conf <<EOF
auth = "plain[/etc/ocserv/ocpasswd]"
tcp-port = $OCSERV_PORT
udp-port = $OCSERV_PORT
server-cert = $CERT_DIR/server.crt
server-key = $CERT_DIR/server.key
max-clients = 6000
max-same-clients = 1
default-domain = vpn
ipv4-network = 192.168.150.0/24
dns = 8.8.8.8
dns = 1.1.1.1
EOF

# Open firewall for OpenConnect port
if command -v ufw &>/dev/null; then
    ufw allow ${OCSERV_PORT}/tcp
    ufw allow ${OCSERV_PORT}/udp
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --add-port=${OCSERV_PORT}/tcp --permanent
    firewall-cmd --add-port=${OCSERV_PORT}/udp --permanent
    firewall-cmd --reload
else
    iptables -I INPUT -p tcp --dport ${OCSERV_PORT} -j ACCEPT
    iptables -I INPUT -p udp --dport ${OCSERV_PORT} -j ACCEPT
fi

# Create users (4-6 char random user/pass, a-z0-9)
> "$USER_FILE"
echo "username,password" > "$CSV_FILE"

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
echo "• You can safely install OpenVPN Access Server as usual."
echo "   It will use UDP 1194 for VPN and TCP 943/9443 for web."
echo ""
echo "Enjoy dual VPN hosting!"
