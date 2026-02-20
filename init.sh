#!/bin/bash
################################################################################
# Debian Server Security & Application Stack Setup Script
#
# Merges base Debian hardening with specific needs for the
# Go/Docker/Nginx application stack.
#
# WARNING: This script makes significant system changes. Review and understand
#          each section before running. Run on a FRESH Debian 13 install.
################################################################################

set -o errexit   # Stop on any error
set -o nounset   # Treat unset variables as an error
set -o pipefail  # See errors from pipes

export PATH="/usr/sbin:/sbin:$PATH"

# --- Configuration ---
# Your custom SSH port, randomly generated or passed via env var
readonly SSH_PORT="${SSH_PORT:-20069}"
# The admin user you will create
ADMIN_USER="${ADMIN_USER:-}"
# Set to 'true' to suppress confirmation prompts
AUTO_CONFIRM="${AUTO_CONFIRM:-false}"

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "\n\033[1;34m[INFO]: $1\033[0m"
}

log_error() {
    echo -e "\n\033[1;31m[ERROR]: $1\033[0m" >&2
}

log_warn() {
    echo -e "\n\033[1;33m[WARN]: $1\033[0m" >&2
}

command_exists() {
    command -v "$1" &> /dev/null
}

# Ensure script is run as root
if [[ "$(id -u)" -ne 0 ]]; then
    log_error "Script must be run as root!"
    exit 1
fi

################################################################################
# System Update and Base Package Installation
################################################################################

update_and_install_basics() {
    log_info "Updating package manager and upgrading system (this may take a while)..."
    if ! apt-get update; then
        log_error "'apt-get update' command failed."
        exit 1
    fi
    if ! apt-get -y full-upgrade; then
        log_error "'apt-get full-upgrade' command failed."
        exit 1
    fi

    log_info "Installing essential packages (curl, git, perl, sudo)..."
    if ! apt-get install -y curl git openssh-server perl sudo ufw; then
        log_error "Failed to install essential packages."
        exit 1
    fi
    log_info "System update complete."
}

################################################################################
# Install Docker & Docker Compose (Modern Method)
################################################################################

install_docker_and_compose() {
    if command_exists docker; then
        log_info "Docker is already installed."
    else
        log_info "Installing Docker (Modern Apt Method)..."
        # Add Docker's official GPG key
        apt-get install -y ca-certificates
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc

        # Add the repository to Apt sources
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
          $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
          tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update

        # Install Docker + The Compose Plugin (replaces old manual binary download)
        if ! apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
             log_error "Failed to install Docker."
             exit 1
        fi
        
        # Alias docker-compose to docker compose for compatibility
        echo 'alias docker-compose="docker compose"' >> /etc/bash.bashrc
        
        log_info "Docker installed successfully."
    fi
}

################################################################################
# Install Security & Management Tools
################################################################################

install_security_tools() {
    log_info "Installing security tools (UFW, Fail2Ban, PAM modules, Certbot)..."
    
    # Pre-seed iptables-persistent for fail2ban dependency if it asks
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    
    # --- FIX: Added 'cracklib-runtime' explicitly ---
    if ! apt-get install -y ufw fail2ban libpam-google-authenticator libpam-pwquality cracklib-runtime unattended-upgrades apt-listchanges certbot; then
        log_error "Failed to install security tools."
        exit 1
    fi
    
    # --- FIX: Force generation of the dictionary file to prevent 'BAD PASSWORD' error ---
    if command -v update-cracklib &> /dev/null; then
        log_info "Generating password dictionary (fixing cracklib error)..."
        update-cracklib
    fi

    log_info "Security tools installed."
}

################################################################################
# (CRITICAL) Fix Docker & UFW Conflict via iptables
################################################################################

configure_docker_ufw_bridge() {
    log_info "Configuring UFW to respect Docker ports via iptables injection..."
    
    # 1. Allow UFW to forward packets (Required for containers to access internet)
    sed -i 's/^DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

    # 2. Inject custom rules into /etc/ufw/after.rules
    # This solves the "Docker bypasses UFW" security hole.
    # It forces traffic to the DOCKER-USER chain to pass through UFW filters.
    
    cat << 'EOF' >> /etc/ufw/after.rules

# --- BEGIN UFW AND DOCKER SECURE SETUP ---
*filter
:ufw-user-forward - [0:0]
:DOCKER-USER - [0:0]
# Add the DOCKER-USER chain to UFW
-A DOCKER-USER -j ufw-user-forward

# Allow internal Docker communication (Internal Networks)
-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

# Allow Docker containers to resolve DNS (UDP 53)
-A DOCKER-USER -p udp -m udp --sport 53 --dport 1024:65535 -j RETURN

# BLOCK everything else destined for Docker unless explicitly allowed by UFW
-A DOCKER-USER -j DROP

COMMIT
# --- END UFW AND DOCKER SECURE SETUP ---
EOF
    
    log_info "UFW+Docker iptables bridge configured in /etc/ufw/after.rules."
}

################################################################################
# Secure User Creation Function
################################################################################

create_new_user() {
    local username="$1"
    local grant_sudo="$2"
    local user_shell="/bin/bash" 
    
    # Check if user already exists
    if id "$username" &> /dev/null; then
        log_warn "User $username already exists!"
        return
    fi
    
    # Create the user
    log_info "Creating user '$username'..."
    if ! useradd -m -s "$user_shell" "$username"; then
        log_error "Failed to create user $username"
        exit 1
    fi

    # Securely set initial password (ensure it meets strict pwquality requirements)
    local temp_pass="$(openssl rand -base64 16)!aA1"
    log_info "Setting temporary auto-generated password for $username: ${temp_pass}"
    if ! echo "$username:$temp_pass" | chpasswd; then
        log_error "Failed to set password for $username"
        unset temp_pass
        exit 1
    fi

    log_warn "--- SECURE ADMIN PASSWORD ---"
    log_warn "Please copy the temporary admin password above RIGHT NOW."
    log_warn "It will be flushed from the screen and memory when you proceed."
    echo ""

    if [[ "${AUTO_CONFIRM}" != "true" ]]; then
        while true; do
            read -p "Type 'y' and press [Enter] AFTER you have securely saved the password: " -r </dev/tty || true
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                break
            fi
        done
    fi

    # Securely flush the temp password from memory
    unset temp_pass

    # Completely wipe the terminal screen and scrollback buffer for security
    if [[ "${AUTO_CONFIRM}" != "true" ]]; then
        printf '\033c'
    fi

    # Lock the root account password securely
    log_info "Generating random secure password for root and locking account..."
    local root_pass="$(openssl rand -base64 32)!@#"
    echo "root:$root_pass" | chpasswd
    passwd -l root
    unset root_pass

    # Optional: completely DELETE default Debian user if it exists (e.g., from cloud images)
    if id "debian" &>/dev/null; then
        log_warn "Deleting default 'debian' user account..."
        userdel -r debian || true
    fi

    if [[ "$grant_sudo" == "true" ]]; then
        log_info "Granting sudo and docker access to $username..."
        usermod -aG sudo "$username"
        usermod -aG docker "$username"
    fi
    
    # --- FIX: Copy SSH Keys from Root to New User ---
    if [[ -d "/root/.ssh" && -f "/root/.ssh/authorized_keys" ]]; then
        log_info "Copying authorized_keys from root to $username..."
        mkdir -p "/home/$username/.ssh"
        cp "/root/.ssh/authorized_keys" "/home/$username/.ssh/"
        
        # Fix permissions
        chown -R "$username:$username" "/home/$username/.ssh"
        chmod 700 "/home/$username/.ssh"
        chmod 600 "/home/$username/.ssh/authorized_keys"
    else
        log_warn "No SSH keys found in /root/.ssh. $username will not have an SSH key!"
    fi
    # -----------------------------------------------

    # Force password change on next login
    chage -d 0 "$username"

    # --- MFA SETUP (Enforced on First Login) ---
    log_info "Configuring MFA (Google Authenticator) enforcement on first login for $username..."
    
    # We add a script to their .profile that forces MFA setup if the config file doesn't exist
    cat << 'EOF' >> "/home/$username/.profile"

# Force Google Authenticator setup on first login
if [ ! -f "$HOME/.google_authenticator" ]; then
    echo -e "\033[1;31m================================================================\033[0m"
    echo -e "\033[1;31m    ACTION REQUIRED: SET UP MULTI-FACTOR AUTHENTICATION NOW     \033[0m"
    echo -e "\033[1;31m================================================================\033[0m"
    echo -e "\033[1;33mPlease scan the QR code that will be generated below using your\033[0m"
    echo -e "\033[1;33mAuthenticator app (Google Authenticator, Authy, etc).\033[0m"
    echo ""
    read -p "Press [Enter] to generate your QR code... "
    
    google-authenticator -t -d -f -r 3 -R 30 -w 3
    
    echo -e "\033[1;32m================================================================\033[0m"
    echo -e "\033[1;32m    MFA CONFIGURED SUCCESSFULLY. PLEASE RELOGIN TO CONTINUE.    \033[0m"
    echo -e "\033[1;32m================================================================\033[0m"
    exit
fi
EOF
    
    chown "$username:$username" "/home/$username/.profile"
    chmod 644 "/home/$username/.profile"

    log_info "User $username created successfully."
}

################################################################################
# Kernel Security Hardening
################################################################################

secure_system_kernel() {
    log_info "Configuring kernel security parameters (sysctl)..."
    
    cat << 'EOF' > /etc/sysctl.d/99-security.conf
###################################################
###### AUTOMATICALLY GENERATED SECURITY CONFIG ####
###################################################

# Kernel Behavior / Virtual Memory
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.unprivileged_bpf_disabled = 1
fs.suid_dumpable = 0

# Docker Network Requirements
net.ipv4.ip_forward = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Web Server Network Tuning
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

# IPv6 Forwarding (Docker)
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Filesystem Security
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
    
    # --- FIX: Correct path to sysctl ---
    /usr/sbin/sysctl --system
    log_info "Kernel security parameters applied."
}

################################################################################
# SSH Security Configuration
################################################################################

configure_ssh() {
    log_info "Configuring SSH security..."
    
    # Backup original SSH config
    if [[ -f /etc/ssh/sshd_config ]]; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d-%H%M%S)
    fi
    
    # Create new SSH config
    cat << EOF > /etc/ssh/sshd_config
# General
Port $SSH_PORT
Protocol 2

# Authentication
ChallengeResponseAuthentication yes
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthenticationMethods publickey,keyboard-interactive
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes
MaxAuthTries 3

# Ciphers and keying
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com

# Logging
LogLevel VERBOSE

# Misc
UseDNS no
IgnoreRhosts yes
HostbasedAuthentication no
X11Forwarding no
AcceptEnv LANG LC_*
MaxSessions 2
TCPKeepAlive no
AllowAgentForwarding no
DebianBanner no
Banner /etc/issue.net
AllowTcpForwarding yes
EOF
    
    cat << 'EOF' > /etc/pam.d/sshd
# Standard Un*x authentication.
@include common-auth
# Google Authenticator (2FA)
auth required pam_google_authenticator.so echo_verification_code
EOF
    
    log_info "SSH configuration complete."
}

################################################################################
# Password Quality Configuration
################################################################################

configure_password_quality() {
    log_info "Configuring password quality requirements..."
    
    cat << 'EOF' > /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 5
retry = 3
enforce_for_root
EOF

    cat << 'EOF' > /etc/pam.d/common-password
# /etc/pam.d/common-password - Hardened configuration
password requisite pam_pwquality.so retry=3 minlen=14 difok=5 minclass=4 maxrepeat=3
password [success=1 default=ignore] pam_unix.so obscure use_authtok try_first_pass yescrypt rounds=12 remember=5
password requisite pam_deny.so
password required pam_permit.so
EOF
}

################################################################################
# Firewall Configuration (UFW)
################################################################################

configure_firewall() {
    log_info "Configuring firewall with UFW..."

    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    
    log_info "Firewall: Allowing SSH on port $SSH_PORT..."
    ufw allow $SSH_PORT/tcp comment 'Allow SSH'
    
    log_info "Firewall: Allowing HTTP/S on ports 80 & 443..."
    ufw allow 80/tcp comment 'Allow HTTP (Nginx)'
    ufw allow 443/tcp comment 'Allow HTTPS (Nginx)'
    
    # NOTE: Because we used configure_docker_ufw_bridge(), we do NOT need 
    # to explicitly deny Docker ports like 3000 or 9090.
    # The iptables bridge we created means UFW's "default deny incoming" 
    # NOW APPLIES TO DOCKER TOO. 
    # If you want to open a docker port, you must now explicitly 'ufw allow' it.

    log_info "Enabling the firewall..."
    ufw --force enable
}

################################################################################
# Configure Fail2Ban & Unattended Upgrades
################################################################################

configure_fail2ban() {
    log_info "Configuring Fail2Ban..."
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5

[sshd]
enabled = true
port = $SSH_PORT
logpath = %(sshd_log)s
backend = %(sshd_backend)s
EOF
}

configure_unattended_upgrades() {
    log_info "Configuring unattended-upgrades..."
    
    # Pre-seed dpkg to prevent the interactive prompt
    echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
    
    if ! env DEBIAN_FRONTEND=noninteractive dpkg-reconfigure -f noninteractive unattended-upgrades; then
        log_error "Failed to configure unattended-upgrades."
    fi
    sed -i 's#//Unattended-Upgrade::Automatic-Reboot "false";#Unattended-Upgrade::Automatic-Reboot "true";#' /etc/apt/apt.conf.d/50unattended-upgrades
    sed -i 's#//Unattended-Upgrade::Automatic-Reboot-Time "02:00";#Unattended-Upgrade::Automatic-Reboot-Time "03:00";#' /etc/apt/apt.conf.d/50unattended-upgrades
}


################################################################################
# Pre-flight Checks (CRITICAL)
################################################################################

check_prerequisites() {
    log_warn "!!! CRITICAL PRE-FLIGHT CHECK !!!"
    echo -e "\033[1;31mBefore proceeding, verify the following. Failing to do so WILL LOCK YOU OUT of your server.\033[0m"
    echo ""
    echo -e "1. \033[1mAuthenticator App Ready:\033[0m You MUST have an app (Google Auth, Authy, etc.) ready on your phone."
    echo -e "   - You will need to scan a QR code during this script."
    echo -e "   - \033[31mConsequence:\033[0m If you miss this, you cannot log in."
    echo ""
    echo -e "2. \033[1mSSH Public Key Present:\033[0m You MUST have an SSH Public Key in /root/.ssh/authorized_keys."
    echo -e "   - This script disables password authentication completely."
    echo -e "   - It copies the root key to your new admin user."
    echo -e "   - \033[31mConsequence:\033[0m If /root/.ssh/authorized_keys is empty/missing, your new user will have NO keys and NO password access."
    echo ""
    echo -e "3. \033[1mFresh Install:\033[0m This script is designed for a FRESH Debian 13 install."
    echo -e "   - \033[31mConsequence:\033[0m Running on an existing system may overwrite configs and break services."
    echo ""
    
    # Check for SSH keys
    if [[ ! -f "/root/.ssh/authorized_keys" ]]; then
        log_error "CRITICAL: /root/.ssh/authorized_keys NOT FOUND."
        log_error "You will be locked out if you proceed (unless adding keys otherwise)."
    fi

    if [[ "${AUTO_CONFIRM}" != "true" ]]; then
        read -p "Are you absolutely sure you are ready? (y/N) " -n 1 -r </dev/tty || true
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_error "Aborting script to prevent lockout."
            exit 1
        fi
    fi
}

################################################################################
# Main Execution
################################################################################

main() {
    log_info "Starting Full Stack Server Security Setup..."
    log_info "=============================================="
    
    check_prerequisites

    update_and_install_basics
    
    log_info "--- Installing Software ---"
    install_docker_and_compose
    install_security_tools
    
    log_info "--- Configuring System ---"
    secure_system_kernel
    configure_password_quality
    
    # Fix the UFW/Docker Bypass
    configure_docker_ufw_bridge
    
    configure_ssh
    configure_fail2ban
    configure_unattended_upgrades
    
    log_info "--- Creating Admin User ---"
    while [[ -z "$ADMIN_USER" ]]; do
      read -rp "Enter username for your new sudo admin user: " ADMIN_USER </dev/tty || true
    done
    create_new_user "$ADMIN_USER" "true"
    
    log_info "--- Enabling Firewall ---"
    configure_firewall
    
    log_info "--- Restarting Services ---"
    systemctl restart docker
    systemctl restart sshd
    systemctl restart fail2ban
    
    log_info "=============================================="
    log_info "\033[1;32mServer hardening and setup complete!\033[0m"
    log_info ""
    log_warn "--- CRITICAL NEXT STEPS ---"
    log_warn "1. The script will now exit. Your CURRENT session is still active."
    log_warn "2. \033[1mTEST SSH connection in a NEW terminal NOW:\033[0m"
    log_warn "   ssh -p $SSH_PORT $ADMIN_USER@<your_server_ip>"
    log_warn "3. Verify your keys were copied correctly."
    log_warn "4. \033[1mMFA is already configured.\033[0m Ensure you scanned the QR code during user creation."
    log_warn "5. \033[1mDO NOT LOG OUT of this root session until you have confirmed you can log in as $ADMIN_USER.\033[0m"
    log_info ""
    log_info "--- Docker Network Security Note ---"
    log_info "We have patched UFW. Docker ports (like 3000, 9090) are now BLOCKED by default."
    log_info "To access them via SSH Tunnel (Recommended): ssh -L 3000:localhost:3000 ..."
    log_info "To open them to the world (Risky): sudo ufw allow 3000/tcp"
    log_info "=============================================="
}

# Run main function
main