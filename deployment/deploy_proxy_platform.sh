#!/bin/bash

# ==============================================================================
# Deploy Secure Proxy Platform (HAProxy, Sing-Box, Flask Subscription App)
#
# Version: 1.0
# Author: AI Assistant (Based on User Requirements)
# Date: $(date +%Y-%m-%d)
#
# Features:
# - VLESS (HTTPUpgrade/TLS) + Hysteria2 (UDP) via Sing-Box
# - HAProxy frontend (TLS termination, path routing, rate limiting)
# - Obscured subscription website (Flask) and API via Base64 paths
# - Automated SSL Certificates via Certbot + Cloudflare DNS
# - Aggressive connection dropping for invalid requests
# - Fail2ban integration for automated IP blocking
# - Command-line VLESS user management script
# - Runtime services run as non-root users (singbox, subapp)
# ==============================================================================

# --- Script Setup ---
# Exit on error, treat unset vars as error, print commands (optional)
set -euo pipefail
# set -x # Uncomment for detailed debugging during development/testing

# --- Configuration Variables (Defaults/Placeholders) ---
# Domains & Email (User Input)
MAIN_DOMAIN=""
SUBSCRIPTION_DOMAIN=""
CLOUDFLARE_EMAIL=""
# Cloudflare Credentials (User Input - Secure)
CLOUDFLARE_API_TOKEN="" # Preferred
CLOUDFLARE_API_KEY=""   # Alternative
# Ports (Defaults)
HYSTERIA2_PORT="31216"
VLESS_HTTPUPGRADE_PORT="8443"
SUBSCRIPTION_SITE_PORT="443"
SINGBOX_VLESS_LISTEN_PORT="10001"
SINGBOX_HYSTERIA2_LISTEN_PORT="10002"
SUBSCRIPTION_APP_LISTEN_PORT="5000"
# Generated Secrets (Auto-Generated)
VLESS_UUID=""
VLESS_PATH=""
HYSTERIA2_PASSWORD=""
SUBSCRIPTION_SECRET_STRING=""
SUBSCRIPTION_BASE64_PATH=""
API_BASE64_PATH_PREFIX=""
# Paths (System/Internal)
HAPROXY_CERT_DIR="/etc/haproxy/certs"
LETSENCRYPT_LIVE_DIR="/etc/letsencrypt/live"
SINGBOX_INSTALL_DIR="/usr/local/bin"
SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_CERT_DIR="/etc/sing-box/certs"
SINGBOX_USER_MAP_FILE="/etc/sing-box/user_map.txt"
SINGBOX_BACKUP_DIR="/etc/sing-box/backups"
SUBSCRIPTION_APP_DIR="/var/www/subscription_app"
MANAGEMENT_SCRIPT_PATH="/usr/local/sbin/manage_proxy_users"
CLOUDFLARE_INI_TEMP="./cloudflare.ini" # Temporary file location
# Fail2ban Settings (Defaults)
FAIL2BAN_MAXRETRY=5
FAIL2BAN_FINDTIME="10m"
FAIL2BAN_BANTIME="1h"
# Service Users/Groups
SINGBOX_USER="singbox"
SINGBOX_GROUP="singbox"
SUBAPP_USER="subapp"
SUBAPP_GROUP="subapp"
HAPROXY_USER="haproxy" # Usually exists from package install
HAPROXY_GROUP="haproxy"

# --- Helper Functions ---
log_info() { echo "[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }
log_error() { echo "[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1" >&2; }
log_warn() { echo "[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1"; }
check_command() { if ! command -v "$1" &>/dev/null; then log_error "$1 command not found. Please install required dependencies."; exit 1; fi }
check_root() { if [[ $EUID -ne 0 ]]; then log_error "This script must be run as root (or using sudo)."; exit 1; fi }
generate_random_string() { LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "${1:-32}" | head -n 1; }
generate_urlsafe_base64() { echo -n "$1" | base64 | tr -d '=' | tr '/+' '_-'; }
cleanup_exit() {
    log_info "Running cleanup..."
    rm -f "${CLOUDFLARE_INI_TEMP}" # Ensure temp credential file is removed on exit
    log_info "Exiting script."
    exit "${1:-1}" # Exit with code 1 by default, or provided code
}
# Trap errors and exit signals for cleanup
trap 'cleanup_exit $?' EXIT SIGHUP SIGINT SIGQUIT SIGTERM

# --- Step 1: Pre-flight Checks & User Input ---
pre_flight_checks() {
    check_root
    log_info "Starting pre-flight checks and gathering information..."
    # Check essential commands needed early
    for cmd in curl jq uuidgen python3 base64 tr head fold date systemctl apt-get useradd groupadd getent install find tar touch read select; do
        check_command "$cmd"
    done

    # Gather Domains & Email
    read -rp "Enter main domain for proxy services (e.g., proxy.yourdomain.com): " MAIN_DOMAIN
    read -rp "Enter domain for subscription website (e.g., subscribe.yourdomain.com): " SUBSCRIPTION_DOMAIN
    read -rp "Enter Cloudflare account email (for Let's Encrypt): " CLOUDFLARE_EMAIL
    # Rudimentary validation
    if [[ -z "$MAIN_DOMAIN" || -z "$SUBSCRIPTION_DOMAIN" || -z "$CLOUDFLARE_EMAIL" ]]; then
        log_error "Domains and email cannot be empty."
        cleanup_exit
    fi
    if [[ "$MAIN_DOMAIN" == "$SUBSCRIPTION_DOMAIN" ]]; then
        log_error "Main proxy domain and subscription domain must be different."
        cleanup_exit
    fi

    # Gather Cloudflare Credentials & Create secure .ini file
    log_info "Choose Cloudflare API credential type:"
    # Ensure PS3 is set for select prompt
    PS3="Select credential type (1 or 2): "
    select cred_type in "API Token (Recommended)" "Global API Key"; do
        if [[ "$cred_type" == "API Token (Recommended)" ]]; then
            read -rsp "Enter Cloudflare API Token (ensure permissions: Zone:Read, DNS:Edit): " CLOUDFLARE_API_TOKEN; echo ""
            if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then log_error "API Token cannot be empty."; cleanup_exit; fi
            log_info "Writing API Token to ${CLOUDFLARE_INI_TEMP}..."
            echo "dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}" > "${CLOUDFLARE_INI_TEMP}"; break
        elif [[ "$cred_type" == "Global API Key" ]]; then
            read -rsp "Enter Cloudflare Global API Key: " CLOUDFLARE_API_KEY; echo ""
            if [[ -z "$CLOUDFLARE_API_KEY" ]]; then log_error "API Key cannot be empty."; cleanup_exit; fi
            log_info "Writing API Key to ${CLOUDFLARE_INI_TEMP}..."
            # Use cat for multi-line to avoid echo interpretation issues
            cat << EOF_INI > "${CLOUDFLARE_INI_TEMP}"
dns_cloudflare_email = ${CLOUDFLARE_EMAIL}
dns_cloudflare_api_key = ${CLOUDFLARE_API_KEY}
EOF_INI
            break
        else echo "Invalid choice. Please select 1 or 2."; fi
    done
    # Secure credentials file immediately
    chmod 400 "${CLOUDFLARE_INI_TEMP}"
    log_info "Created ${CLOUDFLARE_INI_TEMP} with permissions 400 (owner read-only)."

    # Generate Secrets
    VLESS_UUID=$(uuidgen)
    VLESS_PATH="/$(generate_random_string 16)"
    HYSTERIA2_PASSWORD=$(generate_random_string 24)
    SUBSCRIPTION_SECRET_STRING="sub-$(generate_random_string 20)"
    SUBSCRIPTION_BASE64_PATH="/$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-page")"
    API_BASE64_PATH_PREFIX="/$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-api")"

    # Confirmation Prompt
    echo "----------------------------------------"
    log_info "Configuration Summary:"
    echo "  Main Proxy Domain:        ${MAIN_DOMAIN}"
    echo "  Subscription Domain:      ${SUBSCRIPTION_DOMAIN}"
    echo "  Cloudflare Email:         ${CLOUDFLARE_EMAIL}"
    echo "  VLESS Port (TCP):         ${VLESS_HTTPUPGRADE_PORT}"
    echo "  VLESS Path:               ${VLESS_PATH}"
    echo "  VLESS UUID (Initial):     ${VLESS_UUID}"
    echo "  Hysteria2 Port (UDP):     ${HYSTERIA2_PORT}"
    echo "  Hysteria2 Password:       ${HYSTERIA2_PASSWORD} (SAVE THIS!)"
    echo "  Subscription Port (TCP):  ${SUBSCRIPTION_SITE_PORT}"
    echo "  Subscription Page Path:   ${SUBSCRIPTION_BASE64_PATH} (SAVE THIS!)"
    echo "  Subscription API Prefix:  ${API_BASE64_PATH_PREFIX} (SAVE THIS!)"
    echo "  Fail2ban Ban Time:        ${FAIL2BAN_BANTIME}"
    echo "  Runtime Users:            ${SINGBOX_USER}, ${SUBAPP_USER}"
    echo "  Cloudflare creds file:    ${CLOUDFLARE_INI_TEMP} (will be deleted after use)"
    echo "----------------------------------------"
    read -rp "DNS records MUST point to this server. Proceed? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then log_info "Deployment aborted by user."; cleanup_exit 0; fi # Exit gracefully if user aborts
}

# --- Step 2: Install Dependencies & Create Users ---
install_dependencies() {
    log_info "Updating package lists and installing dependencies..."
    # Use non-interactive mode for apt-get to avoid prompts
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y \
        haproxy \
        certbot python3-certbot-dns-cloudflare \
        python3-pip python3-venv \
        fail2ban \
        jq curl unzip coreutils uuid-runtime \
        rsyslog || { log_error "Failed to install dependencies."; cleanup_exit; }

    # Create dedicated users and groups if they don't exist
    log_info "Creating service users/groups: ${SINGBOX_USER}, ${SUBAPP_USER}"
    for group in "$SINGBOX_GROUP" "$SUBAPP_GROUP"; do
        if ! getent group "$group" > /dev/null; then groupadd --system "$group" || { log_error "Failed to create group $group"; cleanup_exit; }; log_info "Group '$group' created.";
        else log_info "Group '$group' already exists."; fi
    done
    if ! id -u "$SINGBOX_USER" > /dev/null 2>&1; then
        useradd --system --gid "$SINGBOX_GROUP" --home-dir /var/lib/singbox --no-create-home --shell /usr/sbin/nologin "$SINGBOX_USER" || { log_error "Failed to create user $SINGBOX_USER"; cleanup_exit; }
        log_info "User '$SINGBOX_USER' created."; mkdir -p /var/lib/singbox && chown "$SINGBOX_USER":"$SINGBOX_GROUP" /var/lib/singbox
    else log_info "User '$SINGBOX_USER' already exists."; fi
    if ! id -u "$SUBAPP_USER" > /dev/null 2>&1; then
        # Ensure parent directory exists before creating user with home dir
        mkdir -p "$(dirname "$SUBSCRIPTION_APP_DIR")"
        useradd --system --gid "$SUBAPP_GROUP" --home-dir "$SUBSCRIPTION_APP_DIR" --no-create-home --shell /usr/sbin/nologin "$SUBAPP_USER" || { log_error "Failed to create user $SUBAPP_USER"; cleanup_exit; }
        log_info "User '$SUBAPP_USER' created.";
    else log_info "User '$SUBAPP_USER' already exists."; fi

    log_info "Enabling core services (HAProxy, Fail2ban)..."
    systemctl enable haproxy || log_warn "Failed to enable haproxy service."
    systemctl start haproxy || log_warn "Failed to start haproxy service initially." # Start early
    systemctl enable fail2ban || log_warn "Failed to enable fail2ban service."
    systemctl start fail2ban || log_warn "Failed to start fail2ban service."

    log_info "Installing Python packages globally (Flask, Gunicorn)..."
    # Use pip from python3 explicitly
    python3 -m pip install --upgrade pip || log_warn "Failed to upgrade pip."
    python3 -m pip install Flask gunicorn || { log_error "Failed to install Python packages."; cleanup_exit; }
}

# --- Step 3: Setup SSL Certificates ---
setup_certificates() {
    log_info "Setting up SSL certificates via Certbot/Cloudflare..."
    mkdir -p "${HAPROXY_CERT_DIR}" "${SINGBOX_CERT_DIR}"
    if [[ ! -f "${CLOUDFLARE_INI_TEMP}" ]]; then log_error "${CLOUDFLARE_INI_TEMP} missing. This should not happen."; cleanup_exit; fi

    # Obtain/Renew cert for Main Domain
    log_info "Processing certificate for ${MAIN_DOMAIN}..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "${MAIN_DOMAIN}" \
        --email "${CLOUDFLARE_EMAIL}" \
        --agree-tos --non-interactive --preferred-challenges dns \
        --keep-until-expiring --renew-with-new-domains \
        || { log_error "Certbot failed for ${MAIN_DOMAIN}. Check DNS records and Cloudflare permissions."; cleanup_exit; }
    # Process for HAProxy
    cat "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem" "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem" > "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"
    chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"
    chmod 640 "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"
    # Process for Sing-Box
    cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem"
    cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    chmod 640 "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    log_info "Certificates for ${MAIN_DOMAIN} processed for HAProxy and Sing-Box."

    # Obtain/Renew cert for Subscription Domain
    log_info "Processing certificate for ${SUBSCRIPTION_DOMAIN}..."
    certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "${SUBSCRIPTION_DOMAIN}" \
        --email "${CLOUDFLARE_EMAIL}" \
        --agree-tos --non-interactive --preferred-challenges dns \
        --keep-until-expiring --renew-with-new-domains \
        || { log_error "Certbot failed for ${SUBSCRIPTION_DOMAIN}. Check DNS records and Cloudflare permissions."; cleanup_exit; }
    # Process for HAProxy
    cat "${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/fullchain.pem" "${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/privkey.pem" > "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"
    chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"
    chmod 640 "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"
    log_info "Certificate for ${SUBSCRIPTION_DOMAIN} processed for HAProxy."

    # Securely remove credentials file NOW that certbot is done
    log_info "Removing temporary Cloudflare credentials file: ${CLOUDFLARE_INI_TEMP}"
    rm -f "${CLOUDFLARE_INI_TEMP}"

    # Setup Certbot Renewal Hook (Ensure variables are correctly expanded)
    log_info "Setting up Certbot auto-renewal hook..."
    RENEWAL_HOOK_SCRIPT="/etc/letsencrypt/renewal-hooks/deploy/process_certs_and_reload.sh"
    # Use single quotes for the outer heredoc marker to prevent immediate expansion
    mkdir -p "$(dirname "$RENEWAL_HOOK_SCRIPT")"
    # We need the variables from the main script's scope inside the hook script
    cat << EOF > "$RENEWAL_HOOK_SCRIPT"
#!/bin/bash
# This script is executed by Certbot upon successful renewal.
# It processes the renewed certificates and reloads relevant services.
set -euo pipefail

# Configuration Variables (Passed from deploy script)
HAPROXY_CERT_DIR="${HAPROXY_CERT_DIR}"
HAPROXY_GROUP="${HAPROXY_GROUP}"
SINGBOX_CERT_DIR="${SINGBOX_CERT_DIR}"
SINGBOX_USER="${SINGBOX_USER}"
SINGBOX_GROUP="${SINGBOX_GROUP}"
LETSENCRYPT_LIVE_DIR="${LETSENCRYPT_LIVE_DIR}"
MAIN_DOMAIN="${MAIN_DOMAIN}"
SUBSCRIPTION_DOMAIN="${SUBSCRIPTION_DOMAIN}"

# Logging helper for hooks (uses systemd-cat if available, otherwise logger)
log_hook() {
    local level="\$1" # notice, err, warning, info
    local message="\$2"
    if command -v systemd-cat >/dev/null; then
        echo "[CERT-HOOK] \${message}" | systemd-cat -t certbot-hook -p "\${level}"
    else
        logger -t certbot-hook -p "daemon.\${level}" "[CERT-HOOK] \${message}"
    fi
}

process_cert() {
    local domain="\$1"
    local purpose="\$2" # "haproxy" or "singbox"
    local combined_pem_path=""
    local cert_path=""
    local key_path=""
    local success=0

    log_hook info "Processing certificate renewal for \${domain} (\${purpose})..."
    local live_fullchain_path="\${LETSENCRYPT_LIVE_DIR}/\${domain}/fullchain.pem"
    local live_privkey_path="\${LETSENCRYPT_LIVE_DIR}/\${domain}/privkey.pem"

    # Check if the specific renewed cert files exist (Certbot sets RENEWED_LINEAGE)
    # This check prevents unnecessary processing if only one domain was renewed.
    if [[ -z "\${RENEWED_LINEAGE:-}" ]] || [[ "\${RENEWED_LINEAGE}" != *"\${domain}"* ]]; then
         log_hook info "Certificate for \${domain} not part of this renewal event. Skipping."
         return 0 # Not an error, just skip
    fi
     if [[ ! -f "\${live_fullchain_path}" || ! -f "\${live_privkey_path}" ]]; then
        log_hook warning "Missing renewed cert files for \${domain} in \${LETSENCRYPT_LIVE_DIR}. Skipping."
        return 1
    fi

    # Create temporary files for atomic operations
    local tmp_combined="\$(mktemp)"
    local tmp_cert="\$(mktemp)"
    local tmp_key="\$(mktemp)"
    trap 'rm -f "\${tmp_combined}" "\${tmp_cert}" "\${tmp_key}"' RETURN # Cleanup temps

    if [[ "\${purpose}" == "haproxy" ]]; then
        combined_pem_path="\${HAPROXY_CERT_DIR}/\${domain}.pem"
        log_hook info "Combining certs for HAProxy: \${combined_pem_path}"
        cat "\${live_fullchain_path}" "\${live_privkey_path}" > "\${tmp_combined}" && \\
            chown root:"\${HAPROXY_GROUP}" "\${tmp_combined}" && \\
            chmod 640 "\${tmp_combined}" && \\
            mv "\${tmp_combined}" "\${combined_pem_path}" && success=1 || \\
            log_hook err "Failed to process HAProxy cert for \${domain}"

    elif [[ "\${purpose}" == "singbox" ]]; then
        cert_path="\${SINGBOX_CERT_DIR}/hysteria2.cert.pem" # Assuming main domain used for Hy2
        key_path="\${SINGBOX_CERT_DIR}/hysteria2.key.pem"
        log_hook info "Copying certs for Sing-Box: \${cert_path}, \${key_path}"
        cp "\${live_fullchain_path}" "\${tmp_cert}" && \\
            cp "\${live_privkey_path}" "\${tmp_key}" && \\
            chown "\${SINGBOX_USER}":"\${SINGBOX_GROUP}" "\${tmp_cert}" "\${tmp_key}" && \\
            chmod 640 "\${tmp_cert}" "\${tmp_key}" && \\
            mv "\${tmp_cert}" "\${cert_path}" && \\
            mv "\${tmp_key}" "\${key_path}" && success=1 || \\
            log_hook err "Failed to process Sing-Box certs from \${domain}"
    fi

    # Return success status (0 for success, 1 for failure)
    [[ \$success -eq 1 ]]; return \$?
}

# --- Main Hook Logic ---
HAD_ERRORS=0
HAPROXY_NEEDS_RELOAD=0
SINGBOX_NEEDS_RESTART=0

process_cert "\${MAIN_DOMAIN}" "haproxy" && HAPROXY_NEEDS_RELOAD=1 || HAD_ERRORS=1
process_cert "\${MAIN_DOMAIN}" "singbox" && SINGBOX_NEEDS_RESTART=1 || HAD_ERRORS=1
process_cert "\${SUBSCRIPTION_DOMAIN}" "haproxy" && HAPROXY_NEEDS_RELOAD=1 || HAD_ERRORS=1

# Reload/Restart services only if certs were updated successfully AND needed
if [[ \$HAD_ERRORS -eq 0 ]]; then
    if [[ \$HAPROXY_NEEDS_RELOAD -eq 1 ]]; then
        log_hook notice "Reloading HAProxy due to certificate renewal..."
        systemctl reload haproxy || log_hook err "Failed to reload HAProxy"
    fi
    if [[ \$SINGBOX_NEEDS_RESTART -eq 1 ]]; then
        log_hook notice "Restarting Sing-Box due to certificate renewal..."
        systemctl restart sing-box || log_hook err "Failed to restart Sing-Box"
    fi
else
    log_hook warning "Errors occurred during certificate processing. Service reload/restart skipped."
fi

log_hook notice "Certbot renewal hook finished."
exit 0
EOF
    chmod +x "$RENEWAL_HOOK_SCRIPT"
    log_info "Created Certbot renewal hook: $RENEWAL_HOOK_SCRIPT"
    # Ensure Certbot timer is active
    if ! systemctl list-timers | grep -q 'certbot.timer'; then
        log_info "Certbot timer not found or inactive, attempting to enable/start.";
        systemctl enable certbot.timer &>/dev/null || log_warn "Could not enable certbot.timer";
        systemctl start certbot.timer &>/dev/null || log_warn "Could not start certbot.timer";
    else
        log_info "Certbot timer appears to be active."
    fi
}

# --- Step 4: Setup Sing-Box ---
setup_singbox() {
    log_info "Setting up Sing-Box..."
    mkdir -p "${SINGBOX_INSTALL_DIR}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    # Set ownership early and correctly for dirs
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    chmod 750 "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"

    # Download and Install Sing-Box Binary
    log_info "Getting latest Sing-Box URL for linux-amd64..."
    LATEST_SINGBOX_URL=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.assets[] | select(.name | contains("linux-amd64")) | .browser_download_url')
    if [ -z "$LATEST_SINGBOX_URL" ] || [ "$LATEST_SINGBOX_URL" == "null" ]; then log_error "Could not determine latest Sing-Box URL."; cleanup_exit; fi
    log_info "Downloading Sing-Box from ${LATEST_SINGBOX_URL}..."
    curl -Lo sing-box.tar.gz "${LATEST_SINGBOX_URL}" || { log_error "Failed to download Sing-Box."; cleanup_exit; }

    # Extract carefully, find executable, install
    SINGBOX_TMP_EXTRACT="singbox_extract_tmp"; mkdir -p "$SINGBOX_TMP_EXTRACT"
    tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT" --strip-components=1 || tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT" # Try stripping, if fails try without
    SINGBOX_EXEC_PATH=$(find "$SINGBOX_TMP_EXTRACT" -maxdepth 1 -name 'sing-box' -type f -print -quit)
    if [ -n "$SINGBOX_EXEC_PATH" ]; then
        # Use install command for setting permissions and owner directly if possible
        # install -m 755 -o root -g root "$SINGBOX_EXEC_PATH" "${SINGBOX_INSTALL_DIR}/sing-box" # Installs as root:root
        install -m 755 "$SINGBOX_EXEC_PATH" "${SINGBOX_INSTALL_DIR}/sing-box" # Keep simple executable permission
    else
        log_error "Sing-box executable not found after extraction. Check archive format.";
        rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz; cleanup_exit;
    fi
    rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz
    log_info "Sing-Box installed to ${SINGBOX_INSTALL_DIR}/sing-box"

    # Create Sing-Box Configuration
    log_info "Creating Sing-Box configuration: ${SINGBOX_CONFIG_DIR}/config.json"
    # Note: Initial VLESS users array is empty. Add users via manage_proxy_users.sh
    cat << EOF > "${SINGBOX_CONFIG_DIR}/config.json"
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "127.0.0.1",
      "listen_port": ${SINGBOX_VLESS_LISTEN_PORT},
      "users": [], // Initial empty array - MANAGE USERS WITH SCRIPT
      "transport": {
        "type": "http",
        "path": "${VLESS_PATH}"
      }
    },
    {
      "type": "hysteria2",
      "tag": "hysteria2-in",
      "listen": "127.0.0.1",
      "listen_port": ${SINGBOX_HYSTERIA2_LISTEN_PORT},
      "up_mbps": 100, // Adjust as needed
      "down_mbps": 500, // Adjust as needed
      "password": "${HYSTERIA2_PASSWORD}",
      "tls": {
        "enabled": true,
        "server_name": "${MAIN_DOMAIN}",
        "alpn": ["h3"], // Hysteria2 often uses h3
        "certificate_path": "${SINGBOX_CERT_DIR}/hysteria2.cert.pem",
        "key_path": "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct-out"
    },
    {
      "type": "block",
      "tag": "block-out"
    }
  ],
  "route": {
    "rules": [
      {
        "inbound": ["vless-in", "hysteria2-in"],
        "outbound": "direct-out"
      }
    ]
  }
}
EOF
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}/config.json"
    chmod 640 "${SINGBOX_CONFIG_DIR}/config.json"

    # Create User Map File
    touch "${SINGBOX_USER_MAP_FILE}"
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_USER_MAP_FILE}"
    chmod 640 "${SINGBOX_USER_MAP_FILE}"

    # Create User Management Script (Embedded)
    log_info "Creating user management script: ${MANAGEMENT_SCRIPT_PATH}"
    # Use single quotes for EOF marker to prevent variable expansion within the script body
    cat << 'EOF_MGMT_SCRIPT' > "${MANAGEMENT_SCRIPT_PATH}"
#!/bin/bash
# Simple script to manage VLESS users in Sing-Box config
set -euo pipefail

# --- Configuration ---
SINGBOX_CONFIG="/etc/sing-box/config.json"
USER_MAP_FILE="/etc/sing-box/user_map.txt"
BACKUP_DIR="/etc/sing-box/backups"
SINGBOX_USER="singbox" # Must match service user
SINGBOX_GROUP="singbox"

# --- Helper Functions ---
log_info() { echo "[INFO] $(date +'%Y%m%d_%H%M%S') - $1"; }
log_error() { echo "[ERROR] $(date +'%Y%m%d_%H%M%S') - $1" >&2; }
check_root() { if [[ $EUID -ne 0 ]]; then log_error "This script must be run as root (or using sudo)."; exit 1; fi; }
check_deps() {
    command -v jq >/dev/null 2>&1 || { log_error "jq is required (apt install jq)."; exit 1; }
    command -v uuidgen >/dev/null 2>&1 || { log_error "uuidgen is required (apt install uuid-runtime)."; exit 1; }
}
backup_config() {
    mkdir -p "$BACKUP_DIR" # Ensure backup dir exists
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$BACKUP_DIR" # Ensure correct ownership
    chmod 750 "$BACKUP_DIR"
    local backup_file="${BACKUP_DIR}/config.json_$(date +%Y%m%d_%H%M%S)"
    cp "$SINGBOX_CONFIG" "$backup_file"
    log_info "Config backed up to $backup_file";
}
reload_singbox() {
    log_info "Reloading Sing-Box service..."
    if systemctl restart sing-box; then
        log_info "Sing-Box restarted successfully."
        return 0
    else
        log_error "Failed to restart Sing-Box after config change."
        log_error "Check config syntax and service status ('journalctl -u sing-box')."
        log_error "Attempting to restore previous config from latest backup..."
        local LATEST_BACKUP
        LATEST_BACKUP=$(ls -t "${BACKUP_DIR}/config.json_"* | head -n 1)
        if [ -n "$LATEST_BACKUP" ] && [ -f "$LATEST_BACKUP" ]; then
            cp "$LATEST_BACKUP" "$SINGBOX_CONFIG"
            chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$SINGBOX_CONFIG" # Restore ownership too
            chmod 640 "$SINGBOX_CONFIG"
            log_info "Restored config from $LATEST_BACKUP."
            log_info "Attempting restart again with restored config..."
            systemctl restart sing-box || log_error "Failed to restart Sing-Box even after restore. MANUAL INTERVENTION REQUIRED."
        else
             log_error "No backup found to restore. MANUAL INTERVENTION REQUIRED."
        fi
        return 1 # Indicate failure
    fi
}
set_ownership_perms() {
    chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "$SINGBOX_CONFIG" "$USER_MAP_FILE"
    chmod 640 "$SINGBOX_CONFIG" "$USER_MAP_FILE"
}

# --- Command Functions ---
add_user() {
    local username="$1"; if [ -z "$username" ]; then log_error "Username cannot be empty."; usage; exit 1; fi
    if ! [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]; then log_error "Invalid username format (alphanumeric, -, _ )."; exit 1; fi
    if grep -q "^${username}:" "$USER_MAP_FILE"; then log_error "Username '$username' already exists in map file."; exit 1; fi

    local new_uuid; new_uuid=$(uuidgen)
    # Check if UUID somehow already exists in config (highly unlikely but good practice)
    if jq -e --arg uuid "$new_uuid" '(.inbounds[] | select(.tag == "vless-in").users[] | select(.uuid == $uuid))' "$SINGBOX_CONFIG" > /dev/null; then
        log_error "Generated UUID $new_uuid already exists in config? Retrying might help."; exit 1;
    fi

    log_info "Adding user '$username' with UUID: $new_uuid"
    # Add to map file first
    echo "${username}:${new_uuid}" >> "$USER_MAP_FILE"
    set_ownership_perms # Ensure map file perms are correct after adding

    # Add to Sing-Box config using jq
    backup_config
    local temp_config; temp_config=$(mktemp)
    # Add the new user object to the vless-in users array
    jq --arg uuid "$new_uuid" '
        (.inbounds[] | select(.tag == "vless-in").users) += [{"uuid": $uuid, "flow": ""}]
    ' "$SINGBOX_CONFIG" > "$temp_config" && mv "$temp_config" "$SINGBOX_CONFIG"

    if [ $? -ne 0 ]; then
         log_error "Failed to update $SINGBOX_CONFIG using jq. Check JSON syntax if manually edited."; rm -f "$temp_config";
         reload_singbox # Attempt reload, likely fails but triggers restore logic
         exit 1
    fi
    set_ownership_perms # Set ownership/perms on the updated config
    log_info "Successfully added user to config file."
    if reload_singbox; then log_info "User '$username' added."; else log_error "User add failed due to service reload issue."; fi
}
list_users() {
    log_info "--- User List ---"
    log_info "Format: Username:UUID (from ${USER_MAP_FILE})"
    if [ -s "$USER_MAP_FILE" ]; then cat "$USER_MAP_FILE"; else log_info "No users found in map file."; fi
    echo # Blank line for separation
    log_info "UUIDs currently in Sing-Box config (${SINGBOX_CONFIG}):"
    if jq -e '.inbounds[] | select(.tag == "vless-in") | .users | length > 0' "$SINGBOX_CONFIG" > /dev/null; then
       jq -r '.inbounds[] | select(.tag == "vless-in") | .users[] .uuid' "$SINGBOX_CONFIG"
    else log_info "No VLESS users found in Sing-Box config."; fi
    log_info "--- End List ---"
}
delete_user() {
    local identifier="$1"; local uuid_to_delete=""; local username_to_delete=""
    if [ -z "$identifier" ]; then log_error "Username or UUID must be provided for deletion."; usage; exit 1; fi

    # Determine if identifier is UUID or username
    if [[ "$identifier" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        uuid_to_delete="$identifier"; log_info "Attempting to delete by UUID: $uuid_to_delete";
        # Find associated username in map for logging/completeness
        username_to_delete=$(grep ":${uuid_to_delete}$" "$USER_MAP_FILE" | cut -d':' -f1)
    else
        username_to_delete="$identifier"; log_info "Attempting to delete by username: $username_to_delete";
        local found_line; found_line=$(grep "^${username_to_delete}:" "$USER_MAP_FILE")
        if [ -n "$found_line" ]; then uuid_to_delete=$(echo "$found_line" | cut -d':' -f2); log_info "Found UUID: $uuid_to_delete";
        else log_error "Username '$username_to_delete' not found in map file $USER_MAP_FILE."; exit 1; fi
    fi

    # Confirm UUID exists in config before proceeding
    if ! jq -e --arg uuid "$uuid_to_delete" '(.inbounds[] | select(.tag == "vless-in").users[] | select(.uuid == $uuid))' "$SINGBOX_CONFIG" > /dev/null; then
         log_error "UUID $uuid_to_delete not found in Sing-Box config $SINGBOX_CONFIG. Already deleted?"
         # Check if it was maybe deleted from config but not map (cleanup)
          if grep -q ":${uuid_to_delete}$" "$USER_MAP_FILE"; then
              log_info "UUID found in map file. Removing dangling map entry for $username_to_delete ($uuid_to_delete)..."
              sed -i.bak "/:${uuid_to_delete}$/d" "$USER_MAP_FILE"; rm -f "${USER_MAP_FILE}.bak"
              set_ownership_perms; log_info "Map entry removed.";
          fi
         exit 1
     fi

    log_info "Deleting user '$username_to_delete' (UUID: $uuid_to_delete)"

    # Delete from map file first
    if grep -q ":${uuid_to_delete}$" "$USER_MAP_FILE"; then
        log_info "Removing entry from map file...";
        sed -i.bak "/:${uuid_to_delete}$/d" "$USER_MAP_FILE"; rm -f "${USER_MAP_FILE}.bak";
        set_ownership_perms
    else log_info "UUID $uuid_to_delete not found in map file (maybe added manually or already removed?)."; fi

    # Delete from Sing-Box config using jq
    backup_config
    local temp_config; temp_config=$(mktemp)
    jq --arg uuid "$uuid_to_delete" '
        (.inbounds[] | select(.tag == "vless-in").users) |= map(select(.uuid != $uuid))
    ' "$SINGBOX_CONFIG" > "$temp_config" && mv "$temp_config" "$SINGBOX_CONFIG"

    if [ $? -ne 0 ]; then
        log_error "Failed to update $SINGBOX_CONFIG using jq."; rm -f "$temp_config";
        reload_singbox; exit 1;
    fi
    set_ownership_perms
    log_info "Successfully removed user from config file."
    if reload_singbox; then log_info "User '$username_to_delete' deleted."; else log_error "User delete failed due to service reload issue."; fi
}
usage() {
  echo "Usage: $0 <command> [options]"
  echo "Commands:"
  echo "  add <username>     Add a new VLESS user (generates UUID)."
  echo "  del <username|uuid> Delete a VLESS user by username or UUID."
  echo "  list               List users from map & UUIDs from config."
  echo "Example:"
  echo "  sudo $0 add myuser"
  echo "  sudo $0 list"
  echo "  sudo $0 del myuser"
  echo "  sudo $0 del a1b2c3d4-..."
}

# --- Main Script Logic ---
check_root
check_deps
# Ensure map file exists with correct permissions before commands run
touch "$USER_MAP_FILE"; set_ownership_perms

if [ $# -eq 0 ]; then usage; exit 1; fi
COMMAND=$1; shift # Remove command from arguments

case $COMMAND in
  add) add_user "$@" ;;
  del | delete) delete_user "$@" ;;
  list | ls) list_users ;; # Added ls alias
  *) log_error "Unknown command: $COMMAND"; usage; exit 1 ;;
esac
exit 0
EOF_MGMT_SCRIPT
    chmod +x "${MANAGEMENT_SCRIPT_PATH}"
    log_info "User management script created: ${MANAGEMENT_SCRIPT_PATH}"

    # Create Sing-Box Systemd Service File (runs as non-root)
    log_info "Creating Sing-Box systemd service file..."
    cat << EOF > /etc/systemd/system/sing-box.service
[Unit]
Description=Sing-Box Service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=${SINGBOX_USER}
Group=${SINGBOX_GROUP}
WorkingDirectory=${SINGBOX_CONFIG_DIR}
# Standard sing-box execution
ExecStart=${SINGBOX_INSTALL_DIR}/sing-box run -c ${SINGBOX_CONFIG_DIR}/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

# Security Hardening Options
# NoNewPrivileges=true # Prevent escalation
# ProtectSystem=strict # Mount /usr, /boot, /etc read-only
# ProtectHome=true     # Hide home directories
# PrivateTmp=true      # Use private /tmp, /var/tmp
# PrivateDevices=true  # Restrict device access
CapabilityBoundingSet= # Clear default capabilities
AmbientCapabilities= # Clear default capabilities

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box || log_warn "Failed to enable sing-box service."
    log_info "Sing-Box setup complete."
}

# --- Step 5: Setup Subscription Flask App ---
setup_subscription_app() {
    log_info "Setting up Python Flask subscription application..."
    mkdir -p "${SUBSCRIPTION_APP_DIR}/templates" "${SUBSCRIPTION_APP_DIR}/static"
    # Set ownership early
    chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"
    chmod 750 "${SUBSCRIPTION_APP_DIR}"

    # Create Python virtual environment and install dependencies
    log_info "Creating Python virtual environment for subscription app..."
    # Create venv as root, then chown. Ensures correct base python used.
    python3 -m venv "${SUBSCRIPTION_APP_DIR}/venv" || { log_error "Failed to create venv."; cleanup_exit; }
    chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}/venv"
    log_info "Installing Flask/Gunicorn into virtual environment..."
    # Run pip from the created venv
    "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install --upgrade pip || log_warn "Failed to upgrade pip in venv."
    "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install Flask gunicorn || { log_error "Failed to install Flask/Gunicorn in venv."; cleanup_exit; }
    log_info "Flask/Gunicorn installed in venv."

    # Create Flask App Script (subscription_app.py)
    log_info "Creating Flask application script: ${SUBSCRIPTION_APP_DIR}/app.py"
    # Use app.py as conventional name
    # Use single quotes for EOF to prevent premature variable expansion inside the Python code
    cat << 'EOF_FLASK_APP' > "${SUBSCRIPTION_APP_DIR}/app.py"
import os
import json
from flask import Flask, render_template, Response, request, abort

app = Flask(__name__)

# --- Configuration from Environment Variables ---
# Load config once at startup
try:
    MAIN_DOMAIN = os.environ['MAIN_DOMAIN']
    SUBSCRIPTION_DOMAIN = os.environ['SUBSCRIPTION_DOMAIN']
    SUBSCRIPTION_BASE64_PATH = os.environ['SUBSCRIPTION_BASE64_PATH']
    API_BASE64_PATH_PREFIX = os.environ['API_BASE64_PATH_PREFIX']
    VLESS_PORT = os.environ['VLESS_PORT']
    VLESS_UUID = os.environ['VLESS_UUID'] # This is the *INITIAL* UUID used in generation
    VLESS_PATH = os.environ['VLESS_PATH']
    HYSTERIA2_PORT = os.environ['HYSTERIA2_PORT']
    HYSTERIA2_PASSWORD = os.environ['HYSTERIA2_PASSWORD']
    # Basic validation
    if not all([MAIN_DOMAIN, SUBSCRIPTION_DOMAIN, SUBSCRIPTION_BASE64_PATH, API_BASE64_PATH_PREFIX,
                VLESS_PORT, VLESS_UUID, VLESS_PATH, HYSTERIA2_PORT, HYSTERIA2_PASSWORD]):
        raise KeyError("One or more required environment variables are missing")
except KeyError as e:
    app.logger.error(f"Missing critical environment variable: {e}")
    # In a real app, might exit or raise a more specific exception
    # For now, log and potentially fail later if routes are called without vars
    pass # Allow app to start but routes might fail

# Route for the main subscription page using the Base64 path
@app.route(os.environ.get('SUBSCRIPTION_BASE64_PATH', '/error-path-not-set'))
def index():
    try:
        return render_template('index.html',
                               subscription_domain=SUBSCRIPTION_DOMAIN,
                               api_base64_path_prefix=API_BASE64_PATH_PREFIX) # Pass prefix to JS
    except Exception as e:
        app.logger.error(f"Error rendering index template: {e}")
        abort(500)

# Route for the API using the Base64 prefix
# Note: API Path includes the prefix already
@app.route(f"{os.environ.get('API_BASE64_PATH_PREFIX', '/error-prefix-not-set')}/<config_name>")
def generate_config(config_name):
    try:
        # Example: config_name = "myuser-VLESS-CLIENT.json" or "myuser-TRJ-CLIENT.json"
        # Basic parsing, no real user validation here, just generates config structure
        parts = config_name.replace('.json', '').split('-')
        if len(parts) < 3:
            app.logger.warning(f"Invalid config name format requested: {config_name}")
            abort(400, "Invalid config name format.")

        username = parts[0]
        protocol_type = parts[1].upper() # VLESS or TRJ

        # --- Generate Sing-Box Client JSON ---
        # IMPORTANT: This generated config uses the *INITIAL* VLESS_UUID.
        # The actual user authentication relies on the *real* UUID list within the running Sing-Box instance.
        # This webpage *DOES NOT* check if the username/UUID is valid in Sing-Box.
        client_config = {
            "log": { "level": "info", "timestamp": True },
            "outbounds": [
                {
                    "type": "vless", "tag": "proxy-vless", "server": MAIN_DOMAIN, "server_port": int(VLESS_PORT),
                    "uuid": VLESS_UUID, # Using the placeholder/initial UUID
                    "tls": { "enabled": True, "server_name": MAIN_DOMAIN, "insecure": False },
                    "transport": { "type": "http", "path": VLESS_PATH }
                },
                {
                    "type": "hysteria2", "tag": "proxy-hysteria2", "server": MAIN_DOMAIN, "server_port": int(HYSTERIA2_PORT),
                    "password": HYSTERIA2_PASSWORD,
                    "tls": { "enabled": True, "server_name": MAIN_DOMAIN, "insecure": False }
                },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": {
                # Simple rule: default to VLESS if requested, otherwise Hy2. Adjust as needed.
                "rules": [ { "outbound": "proxy-vless" if protocol_type == "VLESS" else "proxy-hysteria2", } ],
                "final": "proxy-vless" # Default final outbound
            }
        }

        # Return JSON response
        response_data = json.dumps(client_config, indent=2)
        return Response(response_data, mimetype='application/json')

    except ValueError:
        app.logger.error(f"Invalid port number format from env vars.")
        abort(500)
    except Exception as e:
        app.logger.error(f"Error generating config for {config_name}: {e}")
        abort(500)

# Health check endpoint (optional)
@app.route('/health')
def health_check():
    return "OK", 200

# Run with Gunicorn using the systemd service file, not __main__ block for production.
# if __name__ == '__main__': app.run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))
EOF_FLASK_APP

    # Create HTML Template (templates/index.html) - Minified for brevity in script
    log_info "Creating HTML template: ${SUBSCRIPTION_APP_DIR}/templates/index.html"
    cat << 'EOF_HTML' > "${SUBSCRIPTION_APP_DIR}/templates/index.html"
<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8"><title>SSB Subscription</title><meta name="viewport" content="width=device-width, initial-scale=1">
<script>
const SUBSCRIPTION_DOMAIN="{{subscription_domain}}"; const API_BASE64_PATH_PREFIX="{{api_base64_path_prefix}}"; function getParameterByName(n){n=n.replace(/\[\[\]]/g,"\\$&");var r=new RegExp("[?&]"+n+"(=([^&#]*)|&|#|$)"),e=r.exec(window.location.href);return e?e[2]?decodeURIComponent(e[2].replace(/\+/g," ")):null:""} function fillNameInput(){var n=getParameterByName("name");n&&(document.getElementById("nameInput").value=n)}
function openProfileUrl(t){var n=document.getElementById("nameInput").value.trim();if(!n)return void alert("Пожалуйста, введите имя пользователя.");var e="https://"+SUBSCRIPTION_DOMAIN+API_BASE64_PATH_PREFIX+"/"+encodeURIComponent(n)+"-"+t+"-CLIENT.json",o="sing-box://import-remote-profile?url="+encodeURIComponent(e);console.log("Import URL:",o),window.open(o)} document.addEventListener("DOMContentLoaded",fillNameInput);
</script><style>body{background-color:#fff;background-image:url(/static/background.jpg);background-size:cover;background-repeat:no-repeat;background-position:top left;background-attachment:fixed;text-align:center;font-family:Arial,sans-serif}h2,h3,p,.button,input{font-family:Arial,sans-serif}h2{color:#000;line-height:2.5em}h3{font-weight:400;color:#000;line-height:.1em;margin-top:2em}p{font-size:15px;color:#000}.button{background-color:rgba(25,25,25,.1);color:#000;border:1px solid #000;padding:5px 10px;text-align:center;text-decoration:none;display:inline-block;font-size:14px;margin:8px 4px;cursor:pointer;border-radius:4px;box-shadow:2px 2px 4px rgba(0,0,0,.2)}.button:hover{background-color:rgba(0,0,0,.2)}input[type=text]{padding:5px 10px;font-size:14px;border:1px solid #000;border-radius:4px;width:230px}input[type=text]:hover{background-color:rgba(240,240,240,1)}form{margin-top:1em}</style></head>
<body><h2 style="line-height: 2.5em;">1. Скачать приложение</h2><h3>- Android и iOS -</h3><button class="button" onclick="window.open('https://play.google.com/store/apps/details?id=io.nekohasekai.sfa', '_blank')">Android</button> <button class="button" onclick="window.open('https://apps.apple.com/us/app/sing-box-vt/id6673731168', '_blank')">iOS</button><br><br><h3>- Windows -</h3><button class="button" onclick="window.open('https://github.com/BLUEBL0B/Secret-Sing-Box/blob/main/Docs/Sing-Box-Windows-ru.md', '_blank')">Рекомендуемый способ</button> <button class="button" onclick="window.open('https://github.com/hiddify/hiddify-app/releases/latest', '_blank')">Или скачать Hiddify</button><br><br><h3>- Linux -</h3><button class="button" onclick="window.open('https://github.com/BLUEBL0B/Secret-Sing-Box#%D0%BD%D0%B0%D1%81%D1%82%D1%80%D0%BE%D0%B9%D0%BA%D0%B0-%D0%BA%D0%BB%D0%B8%D0%B5%D0%BD%D1%82%D0%BE%D0%B2', '_blank')">Рекомендуемый способ</button> <button class="button" onclick="window.open('https://github.com/hiddify/hiddify-app/releases/latest', '_blank')">Или скачать Hiddify</button><br><br><h2 style="line-height: 1.2em;">2. Подключиться к серверу</h2><p style="line-height: 2em;"><i>Для Android, iOS и Windows (Hiddify)</i></p><p><form onsubmit="event.preventDefault();"><input type="text" placeholder="Введите имя пользователя..." id="nameInput" required><br><br><button class="button" type="button" onclick="openProfileUrl('TRJ')">Открыть Trojan URL</button> <button class="button" type="button" onclick="openProfileUrl('VLESS')">Открыть VLESS URL</button></form></p><br></body></html>
EOF_HTML
    echo "NOTE: Place background image as ${SUBSCRIPTION_APP_DIR}/static/background.jpg" > "${SUBSCRIPTION_APP_DIR}/static/README.md"

    # Set final ownership and permissions for app files
    chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"
    find "${SUBSCRIPTION_APP_DIR}" -type d -exec chmod 750 {} \;
    find "${SUBSCRIPTION_APP_DIR}" -type f -exec chmod 640 {} \;
    # Ensure venv python and scripts are executable by owner/group
    find "${SUBSCRIPTION_APP_DIR}/venv/bin/" -type f -exec chmod 750 {} \;
    chmod +x "${SUBSCRIPTION_APP_DIR}/venv/bin/activate"* # Activation scripts if needed manually

    # Create Systemd Service File for Flask App (runs as non-root via Gunicorn)
    log_info "Creating systemd service for Flask app..."
    # Use single quotes for EOF to prevent variable expansion here, use env vars inside
    cat << EOF > /etc/systemd/system/subscription-app.service
[Unit]
Description=Subscription Flask App Service (Gunicorn)
After=network.target

[Service]
User=${SUBAPP_USER}
Group=${SUBAPP_GROUP}
WorkingDirectory=${SUBSCRIPTION_APP_DIR}
Environment="PATH=${SUBSCRIPTION_APP_DIR}/venv/bin" # Add venv to PATH for ExecStart
Environment="MAIN_DOMAIN=${MAIN_DOMAIN}"
Environment="SUBSCRIPTION_DOMAIN=${SUBSCRIPTION_DOMAIN}"
Environment="SUBSCRIPTION_BASE64_PATH=${SUBSCRIPTION_BASE64_PATH}"
Environment="API_BASE64_PATH_PREFIX=${API_BASE64_PATH_PREFIX}"
Environment="VLESS_PORT=${VLESS_HTTPUPGRADE_PORT}"
Environment="VLESS_UUID=${VLESS_UUID}" # Passes initial UUID
Environment="VLESS_PATH=${VLESS_PATH}"
Environment="HYSTERIA2_PORT=${HYSTERIA2_PORT}"
Environment="HYSTERIA2_PASSWORD=${HYSTERIA2_PASSWORD}"
Environment="FLASK_APP=app.py" # Point to correct file name
# Use Gunicorn: bind to loopback, log to stderr/stdout for journald capture
ExecStart=${SUBSCRIPTION_APP_DIR}/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT} --access-logfile - --error-logfile - app:app

Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security Hardening Options
NoNewPrivileges=true
ProtectSystem=full # More restrictive than 'strict'
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ReadWritePaths=${SUBSCRIPTION_APP_DIR}/ # Allows writing logs/cache within its dir if needed

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable subscription-app || log_warn "Failed to enable subscription-app service."
    log_info "Subscription Flask app setup complete."
}

# --- Step 6: Setup HAProxy ---
setup_haproxy() {
    log_info "Configuring HAProxy..."

    # Configure rsyslog for HAProxy logging to /var/log/haproxy.log
    HAPROXY_LOG_CONF="/etc/rsyslog.d/49-haproxy.conf"
    if [ ! -f "$HAPROXY_LOG_CONF" ] || ! grep -q '/var/log/haproxy.log' /etc/rsyslog.conf /etc/rsyslog.d/*.conf; then
         log_info "Configuring rsyslog for HAProxy logging to /var/log/haproxy.log..."
         # Basic config: Send local0.* to the file and stop processing for this message
         cat << EOF_RSYSLOG > "$HAPROXY_LOG_CONF"
# Log HAProxy messages (local0) to a dedicated file
local0.*    /var/log/haproxy.log
# Stop processing these messages further down the chain
& stop
EOF_RSYSLOG
         # Ensure log file exists and has permissions (rsyslog might create it, but be sure)
         touch /var/log/haproxy.log
         chown syslog:adm /var/log/haproxy.log # Or appropriate user/group for logs
         chmod 640 /var/log/haproxy.log
         systemctl restart rsyslog || log_warn "Failed to restart rsyslog. HAProxy logs might not appear correctly."
    else
        log_info "Rsyslog configuration for HAProxy already seems to exist."
    fi

    # HAProxy Configuration File (using variables directly)
    log_info "Creating HAProxy configuration file: /etc/haproxy/haproxy.cfg"
    cat << EOF > /etc/haproxy/haproxy.cfg
# ======================================================================
# HAProxy Configuration Generated by Deployment Script
# ======================================================================
global
    log /dev/log local0         # Send to syslog (should be captured by rsyslog)
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners user ${HAPROXY_USER} group ${HAPROXY_GROUP}
    stats timeout 30s
    user ${HAPROXY_USER}
    group ${HAPROXY_GROUP}
    daemon
    # SSL/TLS Defaults
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    tune.ssl.default-dh-param 2048 # Use recommended DH param size

defaults
    log     global
    mode    http                # Default mode
    option  httplog             # Extended logging for Fail2ban
    option  dontlognull         # Don't log health checks/null connections
    option  forwardfor          # Add X-Forwarded-For header
    option  http-server-close   # Close server connection after response (safer)
    timeout connect 5s          # Short connect timeout
    timeout client  30s         # Timeout for client inactivity
    timeout server  30s         # Timeout for server inactivity
    retries 3                   # Retry connection 3 times
    option  redispatch          # Allow redispatching on connection failure

# ----------------------------------------------------------------------
# Frontend: Subscription Website (Port ${SUBSCRIPTION_SITE_PORT}, Obscured)
# ----------------------------------------------------------------------
frontend ft_subscription_site
    bind *:${SUBSCRIPTION_SITE_PORT} ssl crt ${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem alpn h2,http/1.1
    mode http
    option tcplog               # Log TCP connection details

    # ACLs for the *specific* allowed Base64 paths
    acl is_sub_page             path ${SUBSCRIPTION_BASE64_PATH}
    acl is_api_path             path_beg ${API_BASE64_PATH_PREFIX}/
    acl is_health_check         path /health # Allow health check from backend definition

    # Forward ONLY if one of the allowed paths is matched
    use_backend bk_subscription_app if is_sub_page or is_api_path or is_health_check

    # Drop ALL other requests to this port silently AND log it for Fail2ban
    # Note: Dropped requests are still logged due to 'option httplog'
    http-request silent-drop if !is_sub_page and !is_api_path and !is_health_check

# ----------------------------------------------------------------------
# Backend: Subscription App (Flask/Gunicorn)
# ----------------------------------------------------------------------
backend bk_subscription_app
    mode http
    # Health check using the simple /health endpoint in Flask app
    option httpchk GET /health HTTP/1.1\\r\\nHost:\\ ${SUBSCRIPTION_DOMAIN}
    default-server check fall 3 rise 2 inter 5s # Check every 5s
    server sub_app_server 127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT}

# ----------------------------------------------------------------------
# Frontend: VLESS (Port ${VLESS_HTTPUPGRADE_PORT}, Obscured Path)
# ----------------------------------------------------------------------
frontend ft_vless_tls
    bind *:${VLESS_HTTPUPGRADE_PORT} ssl crt ${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem alpn h2,http/1.1
    mode http
    option tcplog

    # ACL for the specific VLESS path
    acl is_vless_path path ${VLESS_PATH}

    # Forward ONLY if the VLESS path is matched
    use_backend bk_vless if is_vless_path

    # Drop ALL other requests to this port silently
    http-request silent-drop if !is_vless_path

# ----------------------------------------------------------------------
# Backend: VLESS (Sing-Box)
# ----------------------------------------------------------------------
backend bk_vless
    mode http
    # No health check defined for VLESS backend easily
    server vless_server 127.0.0.1:${SINGBOX_VLESS_LISTEN_PORT}

# ----------------------------------------------------------------------
# Frontend: Hysteria2 (Port ${HYSTERIA2_PORT}, UDP Rate Limit)
# ----------------------------------------------------------------------
frontend ft_hysteria2
    bind *:${HYSTERIA2_PORT} proto udp
    mode tcp                    # Required for UDP forwarding & state tracking
    option tcplog
    log global

    # Stick table for source IP tracking and connection rate limiting
    stick-table type ip size 1m expire 30s store conn_rate(10s)
    tcp-request connection track-sc0 src
    # Reject new connections if source IP exceeds 10 connections in 10 seconds
    # Adjust rate (10) and period (10s) based on expected traffic/tolerance.
    tcp-request connection reject if { sc0_conn_rate gt 10 }

    # Forward allowed UDP packets to the Hysteria2 backend
    default_backend bk_hysteria2

# ----------------------------------------------------------------------
# Backend: Hysteria2 (Sing-Box)
# ----------------------------------------------------------------------
backend bk_hysteria2
    mode tcp
    # Health checks for UDP backends are complex; relying on Hy2 protocol itself.
    server hysteria2_server 127.0.0.1:${SINGBOX_HYSTERIA2_LISTEN_PORT}
# ======================================================================
# End of HAProxy Configuration
# ======================================================================
EOF

    # Validate HAProxy Config
    log_info "Validating HAProxy configuration..."
    if haproxy -c -f /etc/haproxy/haproxy.cfg; then
        log_info "HAProxy configuration syntax check passed."
    else
        log_error "HAProxy configuration check failed! Please review /etc/haproxy/haproxy.cfg"; cleanup_exit;
    fi
    log_info "HAProxy configuration generation complete."
}

# --- Step 7: Setup Fail2ban ---
setup_fail2ban() {
    log_info "Configuring Fail2ban..."

    # Create Custom Filter (/etc/fail2ban/filter.d/haproxy-custom.conf)
    log_info "Creating Fail2ban filter: /etc/fail2ban/filter.d/haproxy-custom.conf"
    # Use single quotes for EOF to prevent expansion of failregex variables
    cat << 'EOF_FAIL2BAN_FILTER' > /etc/fail2ban/filter.d/haproxy-custom.conf
[Definition]
# Fail2Ban filter for HAProxy logs
# Looks for Silent Drops (SD--) on specific frontends or Rejects (PR--) on UDP frontend

# Log Format Assumption (from 'option httplog'):
# process_name '[' pid ']:' client_ip ':' client_port '[' DD/Mon/YYYY:HH:MM:SS.ms ']' frontend_name '~' backend_name '/' server_name Tq '/' Tw '/' Tc '/' Tr '/' Tt status_code bytes_read captured_request_cookie captured_response_cookie termination_state actconn '/' feconn '/' beconn '/' srv_conn '/' retries srv_queue '/' backend_queue '{' captured_request_headers '}' '{' captured_response_headers '}' '"' http_request '"'
# Example Silent Drop (HTTP):
# Feb 27 12:00:00 host haproxy[1234]: 1.2.3.4:12345 [27/Feb/2024:12:00:00.000] ft_subscription_site~ bk_subscription_app/<NOSRV> -1/-1/-1/-1/0 400 187 - - SD-- 1/1/0/0/0 0/0 "GET /random HTTP/1.1"
# Example Reject (UDP Rate Limit):
# Feb 27 12:01:00 host haproxy[1234]: 1.2.3.5:54321 [27/Feb/2024:12:01:00.000] ft_hysteria2 ft_hysteria2/<NOSRV> -1/-1/-1/-1/0 0 0 - - PR-- 1/1/0/0/0 0/0 "<BADREQ>"

# Regex focuses on Client IP (<HOST>), frontend name, and termination state flags (SD--, PR--)
# Note: The \s+ ensures we match spaces robustly. The .* allow for variability in log fields.
failregex = ^\s*.*\shaproxy\[\d+\]:\s+<HOST>:\d+\s+\[.*?\]\s+ft_(vless_tls|subscription_site)\S*\s+.*\s+SD--\s+.*$
            ^\s*.*\shaproxy\[\d+\]:\s+<HOST>:\d+\s+\[.*?\]\s+ft_hysteria2\S*\s+.*\s+PR--\s+.*$

ignoreregex =

# Notes:
# - Ensure HAProxy logs using 'option httplog'.
# - Ensure HAProxy logs are correctly routed to the 'logpath' defined in the jail (e.g., /var/log/haproxy.log).
# - Test regex using: fail2ban-regex /var/log/haproxy.log /etc/fail2ban/filter.d/haproxy-custom.conf
EOF_FAIL2BAN_FILTER

    # Configure jail definition in jail.d (preferred over jail.local)
    JAIL_CONFIG_FILE="/etc/fail2ban/jail.d/haproxy-custom.conf" # Use .conf in jail.d
    log_info "Configuring Fail2ban jail: ${JAIL_CONFIG_FILE}"
    # Write the jail configuration directly
    cat << EOF > "${JAIL_CONFIG_FILE}"
# Fail2ban jail configuration for custom HAProxy rules

[DEFAULT]
# Default settings can be placed here if needed, but often inherited from jail.conf

[haproxy-http-drop]
enabled  = true
port     = ${SUBSCRIPTION_SITE_PORT},${VLESS_HTTPUPGRADE_PORT} # Ports to ban on
filter   = haproxy-custom       # Use our custom filter definition
logpath  = /var/log/haproxy.log # VERIFY this path is correct and readable by fail2ban
maxretry = ${FAIL2BAN_MAXRETRY}
findtime = ${FAIL2BAN_FINDTIME}
bantime  = ${FAIL2BAN_BANTIME}  # Use variable for consistency
action   = iptables-multiport[name="haproxy-http", port="%(port)s", protocol="tcp"] # Use placeholder

[haproxy-udp-reject]
enabled  = true
port     = ${HYSTERIA2_PORT}    # Port to ban on
filter   = haproxy-custom       # Use our custom filter definition
logpath  = /var/log/haproxy.log # VERIFY this path
maxretry = ${FAIL2BAN_MAXRETRY} # Adjust if different sensitivity needed for UDP
findtime = ${FAIL2BAN_FINDTIME}
bantime  = ${FAIL2BAN_BANTIME}
action   = iptables-multiport[name="haproxy-udp", port="%(port)s", protocol="udp"]
EOF

    # Reload Fail2ban to apply changes
    log_info "Reloading Fail2ban service to apply new configuration..."
    systemctl reload fail2ban || { log_error "Fail2ban reload failed. Check config ('fail2ban-client -d') and logs ('/var/log/fail2ban.log')."; cleanup_exit; }
    log_info "Fail2ban setup complete."
}

# --- Step 8: Setup Firewall ---
setup_firewall() {
    log_info "Configuring firewall (ufw)..."; check_command "ufw"

    log_info "Setting default firewall policies: deny incoming, allow outgoing."
    ufw default deny incoming
    ufw default allow outgoing

    log_info "Allowing essential services: SSH, HAProxy ports."
    ufw allow ssh comment 'Allow SSH access'
    ufw allow "${SUBSCRIPTION_SITE_PORT}/tcp" comment "Subscription Site (HAProxy HTTPS ${SUBSCRIPTION_DOMAIN})"
    ufw allow "${VLESS_HTTPUPGRADE_PORT}/tcp" comment "VLESS (HAProxy HTTPS ${MAIN_DOMAIN})"
    ufw allow "${HYSTERIA2_PORT}/udp" comment "Hysteria2 (HAProxy UDP ${MAIN_DOMAIN})"

    # Explicitly allow loopback traffic (important for HAProxy <-> Backend)
    ufw allow from 127.0.0.1 comment 'Allow all loopback traffic'
    ufw allow to 127.0.0.1

    # Rate limit SSH connections (good practice)
    ufw limit ssh comment 'Rate limit SSH connections'

    # Enable UFW if not already active
    if ! ufw status | grep -qw active; then
        log_info "Enabling firewall..."
        # Use --force to enable without prompt, assuming rules are correct
        ufw --force enable
    else
        log_info "Reloading firewall rules..."
        ufw reload
    fi
    log_info "Current firewall status:"
    ufw status verbose
    log_info "Firewall configuration complete."
}

# --- Step 9: Start/Restart Services ---
start_services() {
    log_info "Starting/Restarting all configured services..."
    # Restart services in a logical order
    # HAProxy depends on backends potentially being available, but needs to bind ports first.
    # Sing-Box and SubApp can start independently. Fail2ban last.
    systemctl restart haproxy || log_warn "Failed to restart haproxy. Check config and logs."
    systemctl restart sing-box || log_warn "Failed to restart sing-box. Check config and logs."
    systemctl restart subscription-app || log_warn "Failed to restart subscription-app. Check config and logs."
    systemctl restart fail2ban || log_warn "Failed to restart fail2ban. Check config and logs." # Restart ensures it picks up jails

    log_info "Waiting briefly for services to potentially initialize..."
    sleep 5

    # Verify Service Statuses
    log_info "Verifying service statuses:"
    local failed_services=0
    for service in haproxy sing-box subscription-app fail2ban; do
        if systemctl is-active --quiet "$service"; then log_info "  - ${service}: Active";
        else log_error "  - ${service}: FAILED or Inactive"; failed_services=$((failed_services + 1)); fi
    done

    # Check local Flask app endpoint via loopback
    local flask_check_url="http://127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT}${SUBSCRIPTION_BASE64_PATH}"
    if curl --fail --silent --head --max-time 5 "${flask_check_url}" &>/dev/null; then
         log_info "  - Subscription app responding locally on: ${flask_check_url}";
    else log_error "  - Subscription app NOT responding locally. Check: journalctl -u subscription-app"; failed_services=$((failed_services + 1)); fi

    if [ $failed_services -gt 0 ]; then
        log_error "One or more critical services failed to start or respond correctly. Please review logs using 'journalctl -u <service_name>'."
        # Do not exit here, allow user to see summary, but highlight failure.
    else
        log_info "All services appear to be running correctly."
    fi
}

# --- Step 10: Main Execution Orchestration ---
main() {
    log_info "Starting Secure Proxy Platform Deployment..."
    pre_flight_checks             # Gather info, generate secrets, confirm
    install_dependencies          # Install packages, create users/groups
    setup_certificates            # Get/renew certs, set permissions, setup hook
    setup_singbox                 # Install binary, config, user script, systemd (non-root)
    setup_subscription_app        # Setup Flask app, template, systemd (non-root)
    setup_haproxy                 # Configure HAProxy (obscurity, dropping, rate limit)
    setup_fail2ban                # Configure Fail2ban filter and jails
    setup_firewall                # Configure UFW
    start_services                # Start/restart services, check status

    # Final Summary Output - Critical Information!
    log_info "--- Deployment Complete ---"
    echo "=============================================================================="
    echo " [IMPORTANT] Configuration Details - SAVE THIS SECURELY!"
    echo "=============================================================================="
    echo ""
    echo " ### Proxy Service (${MAIN_DOMAIN}) ###"
    echo "   - VLESS Port (TCP):        ${VLESS_HTTPUPGRADE_PORT}"
    echo "   - VLESS Path (Secret):     ${VLESS_PATH}"
    echo "   - Hysteria2 Port (UDP):    ${HYSTERIA2_PORT}"
    echo "   - Hysteria2 Password:      ${HYSTERIA2_PASSWORD}"
    echo ""
    echo " ### Subscription Website (${SUBSCRIPTION_DOMAIN}) ###"
    echo "   - ACCESS URL (Use this exact link):"
    echo "     https://${SUBSCRIPTION_DOMAIN}:${SUBSCRIPTION_SITE_PORT}${SUBSCRIPTION_BASE64_PATH}"
    echo "   - API Path Prefix (Internal): ${API_BASE64_PATH_PREFIX}"
    echo ""
    echo " ### VLESS User Management ###"
    echo "   - Script Location: ${MANAGEMENT_SCRIPT_PATH}"
    echo "   - Add User:        sudo ${MANAGEMENT_SCRIPT_PATH} add <username>"
    echo "   - List Users/UUIDs: sudo ${MANAGEMENT_SCRIPT_PATH} list"
    echo "   - Delete User:     sudo ${MANAGEMENT_SCRIPT_PATH} del <username_or_uuid>"
    echo "   - (Client authentication uses the UUIDs managed by this script)"
    echo ""
    echo " ### Security Notes ###"
    echo "   - Runtime services run as non-root: ${SINGBOX_USER}, ${SUBAPP_USER}, ${HAPROXY_USER}."
    echo "   - Subscription/API paths are obscured."
    echo "   - Unmatched requests dropped by HAProxy."
    echo "   - Fail2ban is active. Check status with:"
    echo "     sudo fail2ban-client status haproxy-http-drop"
    echo "     sudo fail2ban-client status haproxy-udp-reject"
    echo ""
    echo " ### Other Information ###"
    echo "   - Ensure DNS A/AAAA records for ${MAIN_DOMAIN} and ${SUBSCRIPTION_DOMAIN} point to this server's IP address."
    echo "   - Place desired background image at: ${SUBSCRIPTION_APP_DIR}/static/background.jpg"
    echo "   - SSL Certificates will auto-renew via Certbot."
    echo "   - Review logs: journalctl -u <service_name>, /var/log/haproxy.log, /var/log/fail2ban.log"
    echo ""
    echo "=============================================================================="
    log_info "Deployment script finished."
}

# --- Run Main Function ---
# Redirect stdout/stderr of the entire script to a log file AND tee to console
# LOG_FILE="deploy_proxy_platform_$(date +%Y%m%d_%H%M%S).log"
# main "$@" | tee "${LOG_FILE}"
# Simpler: Just run main, output goes to console/wherever script is run from
main "$@"

# Cleanup should be handled by trap, final exit is clean.
exit 0
