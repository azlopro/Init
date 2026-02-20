#!/bin/bash
################################################################################
# Automated Setup Entrypoint
# Run via: curl -fsSL https://raw.githubusercontent.com/user/my-repo/main/install.sh | bash
################################################################################
set -e

# Default source location (Change this to your actual repository)
export REPO_URL="${REPO_URL:-https://github.com/azlopro/Init.git}"
export REPO_BRANCH="${REPO_BRANCH:-main}"
export SETUP_SCRIPTS_RAW_URL="${SETUP_SCRIPTS_RAW_URL:-https://raw.githubusercontent.com/azlopro/Init/refs/heads/${REPO_BRANCH}}"

# Environment variable prep
export SSH_PORT="${SSH_PORT:-$((RANDOM % 40000 + 10240))}"
export AUTO_CONFIRM="${AUTO_CONFIRM:-false}"
export INSTALL_STACK="${INSTALL_STACK:-}"

echo -e "\033[1;36m============================================================\033[0m"
echo -e "\033[1;36m               Automated Server Setup Starting                \033[0m"
echo -e "\033[1;36m============================================================\033[0m"
echo ""

if [[ -z "$INSTALL_STACK" ]]; then
    echo -e "Which application stack would you like to install after base setup?"
    echo -e "  \033[1m1) admin-install\033[0m (Default Azlo template)"
    echo -e "  \033[1m2) none\033[0m (Base server hardening & docker only)"
    read -rp "Select an option [1-2, default 1]: " STACK_CHOICE </dev/tty || true
    case "$STACK_CHOICE" in
        2) export INSTALL_STACK="none" ;;
        *) export INSTALL_STACK="admin-install" ;;
    esac
fi
echo -e "\033[1;34m[INFO]\033[0m Will deploy stack: $INSTALL_STACK"
echo ""

# Check if we have the admin user defined
if [[ -z "$ADMIN_USER" ]]; then
    read -rp "Enter the new admin username to create: " ADMIN_USER </dev/tty || true
    echo ""
    export ADMIN_USER
fi

# We'll also prompt for domain and email here so we don't have to later, if a stack is selected
if [[ "$INSTALL_STACK" != "none" ]]; then
    if [[ -z "$DOMAIN_NAME" ]]; then
        read -rp "Enter the domain name (for SSL): " DOMAIN_NAME </dev/tty || true
        export DOMAIN_NAME
    fi
    if [[ -z "$EMAIL_ADDR" ]]; then
        read -rp "Enter email address (for SSL alerts): " EMAIL_ADDR </dev/tty || true
        export EMAIL_ADDR
    fi
fi

echo -e "\033[1;34m[INFO]\033[0m Using SSH_PORT=$SSH_PORT"
echo ""

# Create a safe workspace
WORKSPACE=$(mktemp -d)
echo -e "\033[1;34m[INFO]\033[0m Created temporary workspace at $WORKSPACE"

download_script() {
    local script_name="$1"
    if [[ -f "./$script_name" ]]; then
        echo -e "\033[1;34m[INFO]\033[0m Using local ./$script_name"
        cp "./$script_name" "$WORKSPACE/$script_name"
    else
        echo -e "\033[1;34m[INFO]\033[0m Downloading $script_name from $SETUP_SCRIPTS_RAW_URL..."
        if ! curl -fsSL "$SETUP_SCRIPTS_RAW_URL/$script_name" > "$WORKSPACE/$script_name"; then
            echo -e "\033[1;31m[ERROR]\033[0m Failed to download $script_name! Using curl fallback..."
            # Try without silent fail to see error if it happens again
            curl -SL "$SETUP_SCRIPTS_RAW_URL/$script_name" -o "$WORKSPACE/$script_name"
        fi
    fi
    chmod +x "$WORKSPACE/$script_name"
}

download_script "init.sh"
download_script "setup-knocking.sh"

if [[ "$INSTALL_STACK" == "admin-install" ]]; then
    download_script "admin-install.sh"
fi

echo -e "\033[1;34m[INFO]\033[0m Starting phase 1: init.sh"
"$WORKSPACE/init.sh"

echo -e "\033[1;34m[INFO]\033[0m Starting phase 2: setup-knocking.sh"
"$WORKSPACE/setup-knocking.sh"

if [[ "$INSTALL_STACK" == "admin-install" ]]; then
    echo -e "\033[1;34m[INFO]\033[0m Starting phase 3: admin-install.sh (as user: $ADMIN_USER)"
    sudo -u "$ADMIN_USER" -E bash -c "$WORKSPACE/admin-install.sh"
else
    echo -e "\033[1;34m[INFO]\033[0m Skipping application stack installation (INSTALL_STACK=$INSTALL_STACK)"
fi

echo -e "\033[1;32m============================================================\033[0m"
echo -e "\033[1;32m SETUP COMPLETE! \033[0m"
echo -e "\033[1;32m============================================================\033[0m"
echo -e "You can now connect to your server using:"
echo -e "  ssh -p ${SSH_PORT} $ADMIN_USER@<server-ip>"
echo -e ""
echo -e "REMEMBER: Your MFA and fwknop keys were securely displayed during installation. Ensure you have saved them!"
