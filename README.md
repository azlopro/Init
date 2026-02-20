# Automated Debian Server Setup for Application Stack

This repository contains robust setup scripts designed to initialize, harden, and deploy a secure Debian server environment specifically configured for a Docker/Go/Nginx application stack.

## Getting Started

> [!CAUTION]
> **CRITICAL PRE-FLIGHT CHECK**
> Before running the script, verify the following. Failing to do so **WILL LOCK YOU OUT** of your server:
> 1. **Authenticator App Ready**: You MUST have an app (Google Auth, Authy, etc.) ready on your phone. You will need to scan a QR code during this script. If you miss this, you cannot log in.
> 2. **SSH Public Key Present**: You MUST have an SSH Public Key in `/root/.ssh/authorized_keys`. This script disables password authentication completely and copies the root key to your new admin user. If `/root/.ssh/authorized_keys` is empty/missing, your new user will have NO keys and NO password access.
> 3. **Fresh Install**: This script is designed for a FRESH Debian 13 install. Running on an existing system may overwrite configs and break services.

To initialize your server, simply run the following command as `root` on a fresh Debian 13 installation:

```bash
curl -fsSL https://raw.githubusercontent.com/azlopro/Init/main/install.sh | bash
```

### What This Does:
The wrapper `install.sh` acts as an orchestrator:
1. It prompts you for which application stack to install (e.g., `admin-install` or `none`).
2. It reads or randomly generates an `SSH_PORT` (if not provided).
3. It prompts you for an admin username, and if you selected a stack, a domain name, and email for SSL.
4. It downloads the necessary setup scripts (`init.sh`, `setup-knocking.sh`, and optionally `admin-install.sh`).
5. **Phase 1 (`init.sh`)**: Hardens your system, configures Docker networking safely with UFW, sets up port knocking, and creates your new admin user with mandatory MFA.
6. **Phase 2 (`setup-knocking.sh`)**: Configures Single Packet Authorization (`fwknop`) to hide your new SSH port.
7. **Phase 3 (Optional Stack)**: Executed as the newly created user, it clones your application template repository, auto-generates secure passwords, sets up SSL, and launches Docker Compose.

> [!WARNING]
> Please remember to save the output logs at the end of the script! It contains your temporary randomly generated SSH port, as well as the `KEY_BASE64` and `HMAC_KEY_BASE64` values required to connect to the server.

---

## Modifying Defaults via Environment

You can script the execution fully by passing environment variables before running the curl command:

```bash
export SSH_PORT=50222
export ADMIN_USER=myadmin
export INSTALL_STACK=admin-install
export DOMAIN_NAME=app.example.com
export EMAIL_ADDR=admin@example.com
export AUTO_CONFIRM=true # Set to true to bypass interactive prompts and pauses (like MFA QR code)
curl -fsSL https://raw.githubusercontent.com/azlopro/Init/main/install.sh | bash
```

## Branching Strategy (e.g., Docker Swarm vs Standalone)

This repository is designed to be fully modular! If you want a different setup (like Docker Swarm initialization), you can build it in a separate branch on this repository.

1. Create a new branch: `git checkout -b swarm-setup`
2. Modify `admin-install.sh` in the new branch to execute `docker swarm init` and deploy a stack instead of standard `docker compose`.
3. Push the branch to GitHub.
4. When you execute the script on a new machine, just tell `install.sh` to pull from the specific branch by overriding the `REPO_BRANCH` environment variable:

```bash
export REPO_BRANCH="swarm-setup"
curl -fsSL https://raw.githubusercontent.com/azlopro/Init/main/install.sh | bash
```
