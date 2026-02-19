#!/bin/bash
################################################################################
# Application Deployment Script (Zip Version)
#
# This script should be run AFTER the main security script.
# It should be run by the non-root ADMIN_USER created during setup.
#
# PRE-REQUISITE: You must have 'b.zip' in the current directory!
################################################################################

set -o errexit   # Stop on any error
set -o nounset   # Treat unset variables as an error
set -o pipefail  # See errors from pipes

# --- Configuration ---
DOMAIN_NAME="${DOMAIN_NAME:-}"
EMAIL_ADDR="${EMAIL_ADDR:-}"
REPO_URL="${REPO_URL:-https://github.com/your-org/your-repo.git}"
REPO_BRANCH="${REPO_BRANCH:-main}"
PROJECT_DIR="${PROJECT_DIR:-azlo-template}"
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

# Ensure script is NOT run as root
if [[ "$(id -u)" -eq 0 ]]; then
    log_error "This script must be run by your non-root admin user, not by root!"
    exit 1
fi

# Ensure user has sudo
if ! sudo -v &> /dev/null; then
    log_error "This script requires sudo privileges."
    log_error "Please ensure your user is in the 'sudo' group and you've logged in again."
    exit 1
fi

# Ensure user is in the docker group
if ! groups "$(whoami)" | grep -q '\bdocker\b'; then
    log_error "Your user '$(whoami)' is not in the 'docker' group."
    log_error "Run 'sudo usermod -aG docker $(whoami)' and then log out and log back in."
    exit 1
fi

################################################################################
# Main Deployment Functions
################################################################################

# 1. Check for dependencies
check_dependencies() {
    log_info "Checking for required commands..."
    
    # Check for git, install if missing
    if ! command_exists git; then
        log_warn "'git' command not found. Installing it..."
        sudo apt-get update && sudo apt-get install -y git
    fi

    if ! command_exists docker || ! command_exists certbot; then
        log_error "Missing dependencies (docker or certbot). Please run the server security script first."
        exit 1
    fi
    log_info "Dependencies found."
}

# 2. Get Domain and Email
get_user_inputs() {
    while [[ -z "$DOMAIN_NAME" ]]; do
      read -rp "Enter the domain name for this server (e.g., app.example.com): " DOMAIN_NAME </dev/tty || true
    done

    while [[ -z "$EMAIL_ADDR" ]]; do
      read -rp "Enter email for SSL renewal notifications: " EMAIL_ADDR </dev/tty || true
    done
}

# 3. Download Application
extract_application() {
    log_info "Cloning application from $REPO_URL (branch: $REPO_BRANCH)..."
    
    if [[ -d "$PROJECT_DIR" ]]; then
        log_warn "Directory '$PROJECT_DIR' already exists. Removing it..."
        sudo rm -rf "$PROJECT_DIR"
    fi

    if ! git clone -b "$REPO_BRANCH" "$REPO_URL" "$PROJECT_DIR"; then
        log_error "Failed to clone repository!"
        exit 1
    fi

    cd "$PROJECT_DIR"
    log_info "Entered directory '$(pwd)'"
}

# 4. Get SSL Certificate
get_ssl_certs() {
    log_info "Getting SSL certificate for $DOMAIN_NAME..."
    log_warn "Certbot will temporarily use port 80 (HTTP)."
    
    # Check if cert already exists to avoid hitting rate limits
    if sudo test -d "/etc/letsencrypt/live/$DOMAIN_NAME"; then
        log_info "Certificate for $DOMAIN_NAME already exists. Skipping request."
    else
        if ! sudo certbot certonly --standalone -d "$DOMAIN_NAME" --non-interactive --agree-tos --email "$EMAIL_ADDR"; then
            log_error "Certbot failed to get a certificate."
            log_error "Please check that your domain's A record points to this server's IP and try again."
            exit 1
        fi
        log_info "SSL certificate obtained successfully."
    fi
}

# 5. Update Nginx Configuration
update_nginx_config() {
    log_info "Updating nginx.conf to use Let's Encrypt certificate..."
    
    local NGINX_CONF_PATH="nginx/nginx.conf"
    local NGINX_BAK_PATH="nginx/nginx.conf.bak"
    
    if [[ ! -f "$NGINX_CONF_PATH" ]]; then
        log_error "Could not find '$NGINX_CONF_PATH'. Are you in the right directory?"
        exit 1
    fi
    
    # Create a backup
    cp "$NGINX_CONF_PATH" "$NGINX_BAK_PATH"
    
    # Use sed to replace the self-signed cert paths with the new Let's Encrypt paths
    sed -i "s|/etc/nginx/certs/cert.pem|/etc/letsencrypt/live/$DOMAIN_NAME/fullchain.pem|g" "$NGINX_CONF_PATH"
    sed -i "s|/etc/nginx/certs/key.pem|/etc/letsencrypt/live/$DOMAIN_NAME/privkey.pem|g" "$NGINX_CONF_PATH"
    
    log_info "Nginx config updated. Backup saved to '$NGINX_BAK_PATH'."
}

# 6. Set up .env file
setup_environment() {
    log_info "Setting up .env file..."
    if [[ -f ".env" ]]; then
        log_warn ".env file already exists. Skipping creation."
    else
        if [[ -f ".env.example" ]]; then
            cp .env.example .env
            log_info "Copied '.env.example' to '.env'."
            
            # Generate secure random passwords
            local pg_pass=$(openssl rand -hex 16)
            local redis_pass=$(openssl rand -hex 16)
            local grafana_pass=$(openssl rand -hex 16)
            
            # Auto-replace passwords in .env
            sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${pg_pass}/" .env
            sed -i "s/^REDIS_PASSWORD=.*/REDIS_PASSWORD=${redis_pass}/" .env
            sed -i "s/^GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=${grafana_pass}/" .env
            
            log_info "Auto-generated secure passwords for POSTGRES, REDIS, and GRAFANA in .env."
        else
            log_error ".env.example not found! Cannot create .env."
            exit 1
        fi
    fi
}

# 7. Fix Tempo Permissions
fix_tempo_permissions() {
    log_info "Fixing permissions for Tempo data directory..."
    # 10001 is the default UID for the Grafana/Tempo user in Docker
    if ! sudo mkdir -p ./tempo/data; then
        log_error "Failed to create tempo/data directory."
        exit 1
    fi
    
    if ! sudo chown -R 10001:10001 ./tempo/data; then
        log_error "Failed to set permissions for tempo/data."
        exit 1
    fi
    log_info "Tempo permissions fixed (owned by 10001:10001)."
}

# 8. Create Docker Secrets
create_secrets() {
    log_info "Creating Docker secrets..."
    if [[ ! -f "migrate.sh" ]]; then
        log_error "migrate.sh not found!"
        exit 1
    fi
    
    chmod +x migrate.sh
    if ! ./migrate.sh; then
        log_error "Failed to create secrets."
        exit 1
    fi
    log_info "Docker secrets created successfully."
}

# 9. Verify Docker Volumes (CRITICAL STEP)
verify_ssl_volume() {
    log_info "Verifying docker-compose.prod.yml volumes..."
    
    if [[ ! -f "docker-compose.prod.yml" ]]; then
         log_error "docker-compose.prod.yml not found!"
         exit 1
    fi

    # Check if the LetsEncrypt volume is mounted. 
    if ! grep -q "/etc/letsencrypt:/etc/letsencrypt" docker-compose.prod.yml; then
        log_warn "-------------------------------------------------------------"
        log_warn "CRITICAL WARNING: SSL VOLUME MISSING"
        log_warn "Your nginx.conf points to /etc/letsencrypt, but I don't see"
        log_warn "host mapping for '/etc/letsencrypt' in docker-compose.prod.yml."
        log_warn "The Nginx container will likely crash."
        log_warn "-------------------------------------------------------------"
        if [[ "${AUTO_CONFIRM}" != "true" ]]; then
            read -rp "Press Enter to continue anyway (or Ctrl+C to stop and fix it)..." </dev/tty || true
        fi
    fi
}

# 10. Launch the Application
launch_application() {
    log_info "Building and launching the application stack..."
    log_warn "This will use 'docker-compose.prod.yml'..."
    
    # Use 'docker compose' (v2)
    if ! docker compose -f docker-compose.prod.yml up -d --build; then
        log_error "Docker Compose failed to start!"
        log_error "Run 'docker compose -f docker-compose.prod.yml logs' to check for errors."
        exit 1
    fi
    
    log_info "\n\033[1;32m🚀 Deployment Complete! 🚀\033[0m"
    log_info "Your application should be available at https://$DOMAIN_NAME"
    log_info "Run 'docker compose -f docker-compose.prod.yml ps' to see running services."
}


################################################################################
# Main Execution
################################################################################

main() {
    log_info "Starting Application Deployment..."
    log_info "==================================="
    
    check_dependencies
    get_user_inputs
    extract_application
    
    # --- We are now inside the 'azlo-template' directory ---
    
    setup_environment
    get_ssl_certs
    update_nginx_config
    fix_tempo_permissions
    create_secrets
    
    verify_ssl_volume 
    
    launch_application
    
    log_info "==================================="
    log_info "All steps finished."
}

# Run main function
main