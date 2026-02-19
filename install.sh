#!/bin/bash
################################################################################
# Automated Setup Entrypoint
# Run via: curl -fsSL https://raw.githubusercontent.com/user/my-repo/main/install.sh | bash
################################################################################
set -e

# Default source location (Change this to your actual repository)
export REPO_URL="${REPO_URL:-https://github.com/your-org/your-repo.git}"
export REPO_BRANCH="${REPO_BRANCH:-main}"
export SETUP_SCRIPTS_RAW_URL="${SETUP_SCRIPTS_RAW_URL:-https://raw.githubusercontent.com/your-org/your-repo/refs/heads/${REPO_BRANCH}}"

# Environment variable prep
export SSH_PORT="${SSH_PORT:-$((RANDOM % 40000 + 10240))}"
export AUTO_CONFIRM="${AUTO_CONFIRM:-true}"

echo -e "\033[1;36m============================================================\033[0m"
echo -e "\033[1;36m               Automated Server Setup Starting                \033[0m"
echo -e "\033[1;36m============================================================\033[0m"
echo ""

# Check if we have the admin user defined
if [[ -z "$ADMIN_USER" ]]; then
    read -rp "Enter the new admin username to create: " ADMIN_USER </dev/tty || true
    echo ""
    export ADMIN_USER
fi

# We'll also prompt for domain and email here so we don't have to later
if [[ -z "$DOMAIN_NAME" ]]; then
    read -rp "Enter the domain name (for SSL): " DOMAIN_NAME </dev/tty || true
    export DOMAIN_NAME
fi
if [[ -z "$EMAIL_ADDR" ]]; then
    read -rp "Enter email address (for SSL alerts): " EMAIL_ADDR </dev/tty || true
    export EMAIL_ADDR
fi

echo -e "\033[1;34m[INFO]\033[0m Using SSH_PORT=$SSH_PORT"
echo ""

download_script() {
    local script_name="$1"
    if [[ -f "./$script_name" ]]; then
        echo -e "\033[1;34m[INFO]\033[0m Using local ./$script_name"
        cp "./$script_name" "/tmp/$script_name"
    else
        echo -e "\033[1;34m[INFO]\033[0m Downloading $script_name from $SETUP_SCRIPTS_RAW_URL..."
        curl -fsSL "$SETUP_SCRIPTS_RAW_URL/$script_name" -o "/tmp/$script_name"
    fi
    chmod +x "/tmp/$script_name"
}

download_script "init.sh"
download_script "setup-knocking.sh"
download_script "admin-install.sh"

echo -e "\033[1;34m[INFO]\033[0m Starting phase 1: init.sh"
/tmp/init.sh

echo -e "\033[1;34m[INFO]\033[0m Starting phase 2: setup-knocking.sh"
/tmp/setup-knocking.sh

echo -e "\033[1;34m[INFO]\033[0m Starting phase 3: admin-install.sh (as user: $ADMIN_USER)"
sudo -u "$ADMIN_USER" -E bash -c '/tmp/admin-install.sh'

echo -e "\033[1;32m============================================================\033[0m"
echo -e "\033[1;32m SETUP COMPLETE! \033[0m"
echo -e "\033[1;32m============================================================\033[0m"
echo -e "You can now connect to your server using:"
echo -e "  ssh -p ${SSH_PORT} $ADMIN_USER@<server-ip>"
echo -e ""
echo -e "REMEMBER: If you generated MFA or fwknop keys, they have been logged above! Be sure to save them before you close the terminal!"
