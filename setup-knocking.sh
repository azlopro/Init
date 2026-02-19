#!/bin/bash
################################################################################
# Secure fwknop (Single Packet Authorization) Setup Script
#
# This script installs and configures fwknop-server to protect the SSH port.
# WARNING: This will drop all incoming SSH connections until an SPA packet is sent.
# Must be run as root.
################################################################################

set -o errexit
set -o nounset
set -o pipefail

export PATH="/usr/sbin:/sbin:$PATH"

# Configuration
SSH_PORT="${SSH_PORT:-20069}" # Configurable via env var or defaults to 20069

log_info() { echo -e "\n\033[1;34m[INFO]: $1\033[0m"; }
log_error() { echo -e "\n\033[1;31m[ERROR]: $1\033[0m" >&2; }
log_warn() { echo -e "\n\033[1;33m[WARN]: $1\033[0m" >&2; }

# Ensure script is run as root
if [[ "$(id -u)" -ne 0 ]]; then
    log_error "Script must be run as root!"
    exit 1
fi

log_info "Installing fwknop-server and dependencies..."
apt-get update
# Non-interactive install for fwknop-server
DEBIAN_FRONTEND=noninteractive apt-get install -y fwknop-server fwknop-client libpcap-dev

log_info "Generating fwknop keys..."
# Run fwknop key generator to use HMAC (removed the connection flags)
KEY_OUTPUT=$(fwknop --key-gen --use-hmac 2>&1 || true)

# Extract keys using grep and awk
KEY_BASE64=$(echo "$KEY_OUTPUT" | grep 'KEY_BASE64' | awk '{print $2}' || true)
HMAC_KEY_BASE64=$(echo "$KEY_OUTPUT" | grep 'HMAC_KEY_BASE64' | awk '{print $2}' || true)

if [[ -z "$KEY_BASE64" || -z "$HMAC_KEY_BASE64" ]]; then
    log_error "Failed to generate keys!"
    echo "$KEY_OUTPUT"
    exit 1
fi

# Try to autodetect primary interface, default to eth0
PRIMARY_IFACE=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1 || true)
if [[ -z "$PRIMARY_IFACE" ]]; then
    log_warn "Could not autodetect primary interface. Defaulting to eth0."
    PRIMARY_IFACE="eth0"
fi

log_info "Configuring fwknop-server on interface: $PRIMARY_IFACE"

# Removed semicolons!
cat << EOF > /etc/fwknop/fwknopd.conf
# fwknopd configuration
PCAP_INTF                   $PRIMARY_IFACE
ENABLE_IPT_FORWARDING       N
MAX_SPA_PACKET_AGE          120
SYSLOG_IDENTITY             fwknopd
SYSLOG_FACILITY             LOG_DAEMON
ENABLE_SPA_PACKET_AGING     Y
ENABLE_DIGEST_PERSISTENCE   Y
CMD_EXEC_TIMEOUT            30
EOF

# Removed semicolons and added OPEN_PORTS!
cat << EOF > /etc/fwknop/access.conf
# fwknop access configuration
SOURCE                      ANY
OPEN_PORTS                  tcp/$SSH_PORT
REQUIRE_USERNAME            ANY
KEY_BASE64                  $KEY_BASE64
HMAC_KEY_BASE64             $HMAC_KEY_BASE64
FW_ACCESS_TIMEOUT           60
EOF

chmod 600 /etc/fwknop/access.conf
chmod 600 /etc/fwknop/fwknopd.conf

log_info "Restarting fwknop-server..."
systemctl restart fwknop-server
systemctl enable fwknop-server

log_info "Updating UFW to block SSH ($SSH_PORT) by default..."
# Remove the allow rule if it exists, don't fail if it doesn't
ufw delete allow ${SSH_PORT}/tcp || true
ufw deny ${SSH_PORT}/tcp || true
ufw reload

log_info "======================================================"
log_info "      fwknop Setup Complete! SAVE THESE KEYS!         "
log_info "======================================================"
echo ""
echo "KEY_BASE64=$KEY_BASE64"
echo "HMAC_KEY_BASE64=$HMAC_KEY_BASE64"
echo ""
log_warn "--- TO CONNECT FROM YOUR CLIENT ---"
echo "1. Install fwknop-client on your local machine."
echo "2. Save the keys in your local ~/.fwknoprc (or pass them via command line)."
echo ""
echo "Command to open port ${SSH_PORT}:"
echo "  fwknop -n myserver -A tcp/${SSH_PORT} --use-hmac --key-base64-hmac \$HMAC_KEY_BASE64 --key-base64 \$KEY_BASE64 -a <your_client_ip> -D <server_ip>"
echo ""
echo "Then connect via SSH (within 60 seconds):"
echo "  ssh -p ${SSH_PORT} <user>@<server_ip>"
log_info "======================================================"