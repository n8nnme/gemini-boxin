#!/bin/bash

# ==============================================================================
# Deploy Secure Proxy Platform (HAProxy, Sing-Box, Flask Subscription App)
#
# Version: 1.5 (SIGPIPE Debugging Focus, uses external template files)
# Author: AI Assistant (Based on User Requirements)
# Date: $(date +%Y-%m-%d)
# ==============================================================================

# --- Script Setup ---
set -uo pipefail # Exit on unset variables, error in pipelines. -e managed per function.
# set -x # Uncomment for detailed debugging

# --- Determine Project Root ---
SCRIPT_DIR_ABS="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR_ABS")"

# --- Helper Functions ---
log_info() { echo "[INFO] $(date --iso-8601=seconds) - $1"; }
log_error() { echo "[ERROR] $(date --iso-8601=seconds) - $1" >&2; }
log_warn() { echo "[WARN] $(date --iso-8601=seconds) - $1"; }
check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "$1 command not found. Please install required dependencies."
        exit 1 # Trap will call cleanup_exit
    fi
}
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (or using sudo)."
        exit 1
    fi
}
generate_random_string() {
    LC_ALL=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w "${1:-32}" | head -n 1 || {
        log_error "generate_random_string failed (length: ${1:-32})"
        return 1 # Explicitly return error if pipe fails
    }
}
generate_urlsafe_base64() {
    echo -n "$1" | base64 | tr -d '=' | tr '/+' '_-' || {
        log_error "generate_urlsafe_base64 failed for input: $1"
        return 1 # Explicitly return error
    }
}
_cleanup_resources() {
    log_info "Performing resource cleanup..."
    if [ -n "${CLOUDFLARE_INI_TEMP:-}" ] && [ -f "${CLOUDFLARE_INI_TEMP}" ]; then
        rm -f "${CLOUDFLARE_INI_TEMP}"
        log_info "Removed temporary file: ${CLOUDFLARE_INI_TEMP}"
    fi
}
cleanup_exit() {
    local exit_code="${1:-1}"
    _cleanup_resources
    log_info "Exiting script (Code: ${exit_code})."
    # If the exit code is 141, print a specific message
    if [[ "$exit_code" -eq 141 ]]; then
        log_error "Script terminated with SIGPIPE (141). This often indicates an issue with a command in a pipeline."
    fi
    exit "${exit_code}"
}
trap 'cleanup_exit $?' EXIT # Trap all exits

# --- Configuration Variables (Defaults & Placeholders) ---
# (Variables remain the same)
MAIN_DOMAIN="" SUBSCRIPTION_DOMAIN="" CLOUDFLARE_EMAIL=""
CLOUDFLARE_API_TOKEN="" CLOUDFLARE_API_KEY=""
HYSTERIA2_PORT="31216" VLESS_HTTPUPGRADE_PORT="8443" SUBSCRIPTION_SITE_PORT="443"
SINGBOX_VLESS_LISTEN_PORT="10001" SINGBOX_HYSTERIA2_LISTEN_PORT="10002" SUBSCRIPTION_APP_LISTEN_PORT="5000"
VLESS_UUID="" VLESS_PATH="" HYSTERIA2_PASSWORD=""
SUBSCRIPTION_SECRET_STRING="" SUBSCRIPTION_BASE64_PATH="" API_BASE64_PATH_PREFIX=""
HAPROXY_CERT_DIR="/etc/haproxy/certs" LETSENCRYPT_LIVE_DIR="/etc/letsencrypt/live"
SINGBOX_INSTALL_DIR="/usr/local/bin" SINGBOX_CONFIG_DIR="/etc/sing-box"
SINGBOX_CERT_DIR="/etc/sing-box/certs" SINGBOX_USER_MAP_FILE="/etc/sing-box/user_map.txt"
SINGBOX_BACKUP_DIR="/etc/sing-box/backups" SUBSCRIPTION_APP_DIR="/var/www/subscription_app"
MANAGEMENT_SCRIPT_PATH="/usr/local/sbin/manage_proxy_users"
CLOUDFLARE_INI_TEMP="${SCRIPT_DIR_ABS}/cloudflare.ini.deployscript.$$"
FAIL2BAN_MAXRETRY=5 FAIL2BAN_FINDTIME="10m" FAIL2BAN_BANTIME="1h"
SINGBOX_USER="singbox" SINGBOX_GROUP="singbox"
SUBAPP_USER="subapp" SUBAPP_GROUP="subapp"
HAPROXY_USER="haproxy" HAPROXY_GROUP="haproxy"

# --- Paths to Template Files ---
# (Paths remain the same)
TEMPLATE_HAPROXY_CFG="${PROJECT_ROOT}/config_templates/haproxy/haproxy.cfg.template"
TEMPLATE_SINGBOX_SERVICE="${PROJECT_ROOT}/config_templates/systemd/sing-box.service.template"
TEMPLATE_SUBAPP_SERVICE="${PROJECT_ROOT}/config_templates/systemd/subscription-app.service.template"
TEMPLATE_FAIL2BAN_FILTER="${PROJECT_ROOT}/config_templates/fail2ban/filter.d/haproxy-custom.conf"
TEMPLATE_FAIL2BAN_JAIL="${PROJECT_ROOT}/config_templates/fail2ban/jail.d/haproxy-custom.conf"
TEMPLATE_SINGBOX_JSON="${PROJECT_ROOT}/config_templates/sing-box/config.json.template"
TEMPLATE_CERTBOT_HOOK="${PROJECT_ROOT}/config_templates/certbot/renewal-hook.sh.template"
SOURCE_FLASK_APP_PY="${PROJECT_ROOT}/services/subscription_app/app.py"
SOURCE_FLASK_INDEX_HTML="${PROJECT_ROOT}/services/subscription_app/templates/index.html"
SOURCE_FLASK_STATIC_README="${PROJECT_ROOT}/services/subscription_app/static/README.md"
SOURCE_MANAGE_USERS_SCRIPT="${PROJECT_ROOT}/scripts/manage_proxy_users.sh"

# --- Helper Function for Processing Templates ---
process_template() {
    # (Implementation from previous script v1.4 - assumed to be correct for now)
    local template_file="$1"; local output_file="$2"; local temp_processed_file; local var_name; local sed_expressions=""
    if [ ! -f "$template_file" ]; then log_error "Template file not found: $template_file"; return 1; fi
    temp_processed_file=$(mktemp) || { log_error "Failed to create temp file."; return 1; }
    cp "$template_file" "$temp_processed_file" || { log_error "Failed to copy template."; rm -f "$temp_processed_file"; return 1; }
    local vars_to_substitute=( MAIN_DOMAIN SUBSCRIPTION_DOMAIN CLOUDFLARE_EMAIL HYSTERIA2_PORT VLESS_HTTPUPGRADE_PORT SUBSCRIPTION_SITE_PORT SINGBOX_VLESS_LISTEN_PORT SINGBOX_HYSTERIA2_LISTEN_PORT SUBSCRIPTION_APP_LISTEN_PORT VLESS_UUID VLESS_PATH SUBSCRIPTION_BASE64_PATH API_BASE64_PATH_PREFIX HAPROXY_CERT_DIR LETSENCRYPT_LIVE_DIR SINGBOX_INSTALL_DIR SINGBOX_CONFIG_DIR SINGBOX_CERT_DIR SUBSCRIPTION_APP_DIR FAIL2BAN_MAXRETRY FAIL2BAN_FINDTIME FAIL2BAN_BANTIME SINGBOX_USER SINGBOX_GROUP SUBAPP_USER SUBAPP_GROUP HAPROXY_USER HAPROXY_GROUP );
    for var_name in "${vars_to_substitute[@]}"; do local var_value="${!var_name:-}"; if [ -n "$var_value" ]; then local escaped_value; escaped_value=$(echo "$var_value" | sed -e 's/[&@\\]/\\&/g'); sed -i "s@\${${var_name}}@${escaped_value}@g" "$temp_processed_file" || { log_error "Sed failed for \${${var_name}}"; rm -f "$temp_processed_file"; return 1; }; fi; done
    local escaped_hy2_pass; escaped_hy2_pass=$(echo "${HYSTERIA2_PASSWORD}" | sed -e 's/[&@\\]/\\&/g'); sed -i "s@\${HYSTERIA2_PASSWORD}@${escaped_hy2_pass}@g" "$temp_processed_file" || { log_error "Sed failed for HYSTERIA2_PASSWORD"; rm -f "$temp_processed_file"; return 1; }
    mkdir -p "$(dirname "$output_file")" || { log_error "Fld to create dir for $(dirname "$output_file")"; rm -f "$temp_processed_file"; return 1; }
    mv "$temp_processed_file" "$output_file" || { log_error "Fld to move temp to ${output_file}"; rm -f "$temp_processed_file"; return 1; }
    log_info "Processed template '${template_file##*/}' to '${output_file}'"; return 0;
}

# --- Function to run a command and trigger cleanup_exit on failure ---
run_cmd_or_exit() {
    # This function explicitly exits if the command fails.
    "$@"
    local status=$?
    if [ $status -ne 0 ]; then
        log_error "Command failed with status $status: $*"
        # The EXIT trap will handle cleanup. We just exit with the command's status.
        exit $status
    fi
    return 0 # Indicate success for this specific command
}


# --- Step 1: Pre-flight Checks & User Input ---
pre_flight_checks() {
    local prev_opts; prev_opts=$(set +o); set -e # Enable immediate exit on error for THIS function

    check_root
    log_info "Starting pre-flight checks and gathering information..."
    for cmd in curl jq uuidgen python3 base64 tr head fold date systemctl apt-get useradd groupadd getent install find tar touch read select sed mktemp mv cp rm mkdir chmod chown dirname; do
        run_cmd_or_exit check_command "$cmd" # Use run_cmd_or_exit here
    done
    log_info "Gathering domain and Cloudflare information..."
    read -rp "Enter main domain for proxy services (e.g., proxy.yourdomain.com): " MAIN_DOMAIN
    read -rp "Enter domain for subscription website (e.g., subscribe.yourdomain.com): " SUBSCRIPTION_DOMAIN
    read -rp "Enter Cloudflare account email (for Let's Encrypt): " CLOUDFLARE_EMAIL
    if [[ -z "$MAIN_DOMAIN" || -z "$SUBSCRIPTION_DOMAIN" || -z "$CLOUDFLARE_EMAIL" ]]; then log_error "Domains and email cannot be empty."; exit 1; fi
    if [[ "$MAIN_DOMAIN" == "$SUBSCRIPTION_DOMAIN" ]]; then log_error "Main proxy domain and subscription domain must be different."; exit 1; fi

    log_info "Choose Cloudflare API credential type:"
    PS3="Select credential type (1 or 2 then Enter): "
    local cred_choice_done=false
    while ! $cred_choice_done; do
        select cred_type in "API Token (Recommended)" "Global API Key"; do
            # Check $REPLY directly instead of $cred_type from select, as it's more robust
            if [[ "$REPLY" == "1" ]]; then # API Token
                read -rsp "Enter Cloudflare API Token: " CLOUDFLARE_API_TOKEN; echo ""
                if [[ -z "$CLOUDFLARE_API_TOKEN" ]]; then log_error "API Token cannot be empty."; continue; fi # Loop again
                echo "dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}" > "${CLOUDFLARE_INI_TEMP}"; cred_choice_done=true; break
            elif [[ "$REPLY" == "2" ]]; then # Global API Key
                read -rsp "Enter Cloudflare Global API Key: " CLOUDFLARE_API_KEY; echo ""
                if [[ -z "$CLOUDFLARE_API_KEY" ]]; then log_error "API Key cannot be empty."; continue; fi # Loop again
                cat << EOF_INI > "${CLOUDFLARE_INI_TEMP}"
dns_cloudflare_email = ${CLOUDFLARE_EMAIL}
dns_cloudflare_api_key = ${CLOUDFLARE_API_KEY}
EOF_INI
                cred_choice_done=true; break
            else echo "Invalid choice '$REPLY'. Please select 1 or 2."; continue; fi # Loop again for invalid $REPLY
        done
    done
    run_cmd_or_exit chmod 400 "${CLOUDFLARE_INI_TEMP}"; log_info "Created secure Cloudflare credentials file: ${CLOUDFLARE_INI_TEMP}"

    # Generate Secrets
    log_info "Generating secrets..."
    VLESS_UUID=$(uuidgen) || { log_error "uuidgen failed"; exit 1; } # Critical failure
    log_info "  - VLESS_UUID generated: ${VLESS_UUID}"

    VLESS_PATH_TEMP=$(generate_random_string 16) || { log_error "generate_random_string for VLESS_PATH failed"; exit 1; }
    VLESS_PATH="/${VLESS_PATH_TEMP}"
    log_info "  - VLESS_PATH generated: ${VLESS_PATH}"

    HYSTERIA2_PASSWORD=$(generate_random_string 24) || { log_error "generate_random_string for HYSTERIA2_PASSWORD failed"; exit 1; }
    log_info "  - HYSTERIA2_PASSWORD generated."

    SUBSCRIPTION_SECRET_STRING_TEMP=$(generate_random_string 20) || { log_error "generate_random_string for SUBSCRIPTION_SECRET_STRING failed"; exit 1; }
    SUBSCRIPTION_SECRET_STRING="sub-${SUBSCRIPTION_SECRET_STRING_TEMP}"
    log_info "  - SUBSCRIPTION_SECRET_STRING generated."

    SUBSCRIPTION_BASE64_PATH_TEMP=$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-page") || { log_error "generate_urlsafe_base64 for SUBSCRIPTION_BASE64_PATH failed"; exit 1; }
    SUBSCRIPTION_BASE64_PATH="/${SUBSCRIPTION_BASE64_PATH_TEMP}"
    log_info "  - SUBSCRIPTION_BASE64_PATH generated: ${SUBSCRIPTION_BASE64_PATH}"

    API_BASE64_PATH_PREFIX_TEMP=$(generate_urlsafe_base64 "${SUBSCRIPTION_SECRET_STRING}-api") || { log_error "generate_urlsafe_base64 for API_BASE64_PATH_PREFIX failed"; exit 1; }
    API_BASE64_PATH_PREFIX="/${API_BASE64_PATH_PREFIX_TEMP}"
    log_info "  - API_BASE64_PATH_PREFIX generated: ${API_BASE64_PATH_PREFIX}"
    log_info "Secret generation complete."

    log_info "--- Configuration Summary ---"
    echo "  Main Proxy Domain:        ${MAIN_DOMAIN}"; echo "  Subscription Domain:      ${SUBSCRIPTION_DOMAIN}"; echo "  Cloudflare Email:         ${CLOUDFLARE_EMAIL}"; echo "  VLESS Port (TCP):         ${VLESS_HTTPUPGRADE_PORT}"; echo "  VLESS Path:               ${VLESS_PATH}"; echo "  VLESS UUID (Initial):     ${VLESS_UUID}"; echo "  Hysteria2 Port (UDP):     ${HYSTERIA2_PORT}"; echo "  Hysteria2 Password:       ${HYSTERIA2_PASSWORD} (SAVE THIS!)"; echo "  Subscription Port (TCP):  ${SUBSCRIPTION_SITE_PORT}"; echo "  Subscription Page Path:   ${SUBSCRIPTION_BASE64_PATH} (SAVE THIS!)"; echo "  Subscription API Prefix:  ${API_BASE64_PATH_PREFIX} (SAVE THIS!)"; echo "  Fail2ban Ban Time:        ${FAIL2BAN_BANTIME}"; echo "  Cloudflare creds file:    ${CLOUDFLARE_INI_TEMP} (will be auto-deleted)";
    echo "----------------------------------------"
    read -rp "DNS records for both domains MUST point to this server's IP. Proceed? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then log_info "Deployment aborted by user."; exit 0; fi # Clean exit if user aborts

    eval "$prev_opts" # Restore previous shell options (specifically -e)
}

# --- Step 2: Install Dependencies & Create Users ---
install_dependencies() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Updating package lists and installing dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    run_cmd_or_exit apt-get update -y
    run_cmd_or_exit apt-get install -y haproxy certbot python3-certbot-dns-cloudflare python3-pip python3-venv fail2ban jq curl unzip coreutils uuid-runtime rsyslog

    log_info "Creating service users (${SINGBOX_USER}, ${SUBAPP_USER}) and groups..."
    for group_name in "$SINGBOX_GROUP" "$SUBAPP_GROUP"; do
        if ! getent group "$group_name" > /dev/null; then run_cmd_or_exit groupadd --system "$group_name"; log_info "Group '$group_name' created.";
        else log_info "Group '$group_name' already exists."; fi
    done
    if ! id -u "$SINGBOX_USER" > /dev/null 2>&1; then
        run_cmd_or_exit useradd --system --gid "$SINGBOX_GROUP" --home-dir /var/lib/singbox --no-create-home --shell /usr/sbin/nologin "$SINGBOX_USER"
        log_info "User '$SINGBOX_USER' created."; run_cmd_or_exit mkdir -p /var/lib/singbox && run_cmd_or_exit chown "$SINGBOX_USER":"$SINGBOX_GROUP" /var/lib/singbox
    else log_info "User '$SINGBOX_USER' already exists."; fi
    if ! id -u "$SUBAPP_USER" > /dev/null 2>&1; then
        run_cmd_or_exit mkdir -p "$(dirname "$SUBSCRIPTION_APP_DIR")"
        run_cmd_or_exit useradd --system --gid "$SUBAPP_GROUP" --home-dir "$SUBSCRIPTION_APP_DIR" --no-create-home --shell /usr/sbin/nologin "$SUBAPP_USER"
        log_info "User '$SUBAPP_USER' created.";
    else log_info "User '$SUBAPP_USER' already exists."; fi

    log_info "Enabling and starting HAProxy and Fail2ban services..."
    run_cmd_or_exit systemctl enable haproxy; run_cmd_or_exit systemctl start haproxy
    run_cmd_or_exit systemctl enable fail2ban; run_cmd_or_exit systemctl start fail2ban

    log_info "Installing/upgrading Python pip and installing Flask, Gunicorn..."
    run_cmd_or_exit python3 -m pip install --upgrade pip
    run_cmd_or_exit python3 -m pip install Flask gunicorn
    eval "$prev_opts"
}

# --- Steps 3 to 9 (Certificates, Sing-Box, SubApp, HAProxy, Fail2ban, Firewall, Start Services) ---
# These functions will now use run_cmd_or_exit for critical operations.
# process_template already returns 1 on failure which run_cmd_or_exit will catch.
# Copying files also uses run_cmd_or_exit.

# Step 3: Setup SSL Certificates
setup_certificates() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up SSL certificates via Certbot/Cloudflare..."
    run_cmd_or_exit mkdir -p "${HAPROXY_CERT_DIR}" "${SINGBOX_CERT_DIR}"
    if [[ ! -f "${CLOUDFLARE_INI_TEMP}" ]]; then log_error "Cloudflare credentials file missing."; exit 1; fi

    log_info "Obtaining/renewing certificate for Main Domain: ${MAIN_DOMAIN}..."
    run_cmd_or_exit certbot certonly --dns-cloudflare --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" --dns-cloudflare-propagation-seconds 60 -d "${MAIN_DOMAIN}" --email "${CLOUDFLARE_EMAIL}" --agree-tos --non-interactive --preferred-challenges dns --keep-until-expiring --renew-with-new-domains
    run_cmd_or_exit bash -c "cat \"${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem\" \"${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem\" > \"${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem\""
    run_cmd_or_exit chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"; run_cmd_or_exit chmod 640 "${HAPROXY_CERT_DIR}/${MAIN_DOMAIN}.pem"
    run_cmd_or_exit cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/fullchain.pem" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem"; run_cmd_or_exit cp "${LETSENCRYPT_LIVE_DIR}/${MAIN_DOMAIN}/privkey.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"; run_cmd_or_exit chmod 640 "${SINGBOX_CERT_DIR}/hysteria2.cert.pem" "${SINGBOX_CERT_DIR}/hysteria2.key.pem"
    log_info "Certs for ${MAIN_DOMAIN} processed."

    log_info "Obtaining/renewing certificate for Subscription Domain: ${SUBSCRIPTION_DOMAIN}..."
    run_cmd_or_exit certbot certonly --dns-cloudflare --dns-cloudflare-credentials "${CLOUDFLARE_INI_TEMP}" --dns-cloudflare-propagation-seconds 60 -d "${SUBSCRIPTION_DOMAIN}" --email "${CLOUDFLARE_EMAIL}" --agree-tos --non-interactive --preferred-challenges dns --keep-until-expiring --renew-with-new-domains
    run_cmd_or_exit bash -c "cat \"${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/fullchain.pem\" \"${LETSENCRYPT_LIVE_DIR}/${SUBSCRIPTION_DOMAIN}/privkey.pem\" > \"${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem\""
    run_cmd_or_exit chown root:"${HAPROXY_GROUP}" "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"; run_cmd_or_exit chmod 640 "${HAPROXY_CERT_DIR}/${SUBSCRIPTION_DOMAIN}.pem"
    log_info "Certs for ${SUBSCRIPTION_DOMAIN} processed."
    # CLOUDFLARE_INI_TEMP is removed by EXIT trap

    log_info "Setting up Certbot auto-renewal hook from template..."
    RENEWAL_HOOK_SCRIPT_DEST="/etc/letsencrypt/renewal-hooks/deploy/process_certs_and_reload.sh"
    run_cmd_or_exit process_template "${TEMPLATE_CERTBOT_HOOK}" "${RENEWAL_HOOK_SCRIPT_DEST}"
    run_cmd_or_exit chmod +x "$RENEWAL_HOOK_SCRIPT_DEST"
    log_info "Created Certbot renewal hook: $RENEWAL_HOOK_SCRIPT_DEST"
    if ! systemctl list-timers | grep -q 'certbot.timer'; then log_info "Certbot timer not active, enabling/starting."; systemctl enable certbot.timer &>/dev/null || log_warn "Could not enable certbot.timer"; systemctl start certbot.timer &>/dev/null || log_warn "Could not start certbot.timer"; else log_info "Certbot timer active."; fi
    eval "$prev_opts"
}

# Step 4: Setup Sing-Box
setup_singbox() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up Sing-Box..."
    run_cmd_or_exit mkdir -p "${SINGBOX_INSTALL_DIR}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"
    run_cmd_or_exit chmod 750 "${SINGBOX_CONFIG_DIR}" "${SINGBOX_CERT_DIR}" "${SINGBOX_BACKUP_DIR}"

    log_info "Getting latest Sing-Box URL for linux-amd64..."
    LATEST_SINGBOX_URL=$(curl -fsSL "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r '.assets[] | select(.name | contains("linux-amd64")) | .browser_download_url')
    if [ -z "$LATEST_SINGBOX_URL" ] || [ "$LATEST_SINGBOX_URL" == "null" ]; then log_error "Could not get Sing-Box URL."; exit 1; fi
    log_info "Downloading Sing-Box from ${LATEST_SINGBOX_URL}..."; run_cmd_or_exit curl -Lo sing-box.tar.gz "${LATEST_SINGBOX_URL}"
    SINGBOX_TMP_EXTRACT="singbox_extract_tmp_$$"; run_cmd_or_exit mkdir -p "$SINGBOX_TMP_EXTRACT"
    if ! tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT" --strip-components=1 2>/dev/null; then log_info "Stripping failed, trying without..."; run_cmd_or_exit tar -xzf sing-box.tar.gz -C "$SINGBOX_TMP_EXTRACT"; fi
    SINGBOX_EXEC_PATH=$(find "$SINGBOX_TMP_EXTRACT" -maxdepth 2 -name 'sing-box' -type f -print -quit)
    if [ -n "$SINGBOX_EXEC_PATH" ]; then run_cmd_or_exit install -m 755 "$SINGBOX_EXEC_PATH" "${SINGBOX_INSTALL_DIR}/sing-box"; else log_error "Sing-box exec not found."; rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz; exit 1; fi
    rm -rf "$SINGBOX_TMP_EXTRACT" sing-box.tar.gz; log_info "Sing-Box installed."

    log_info "Creating Sing-Box configuration from template..."
    run_cmd_or_exit process_template "${TEMPLATE_SINGBOX_JSON}" "${SINGBOX_CONFIG_DIR}/config.json"
    run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_CONFIG_DIR}/config.json"; run_cmd_or_exit chmod 640 "${SINGBOX_CONFIG_DIR}/config.json"
    run_cmd_or_exit touch "${SINGBOX_USER_MAP_FILE}"; run_cmd_or_exit chown "${SINGBOX_USER}":"${SINGBOX_GROUP}" "${SINGBOX_USER_MAP_FILE}"; run_cmd_or_exit chmod 640 "${SINGBOX_USER_MAP_FILE}"

    log_info "Copying user management script..."
    if [ ! -f "$SOURCE_MANAGE_USERS_SCRIPT" ]; then log_error "Mgmt script not found at ${SOURCE_MANAGE_USERS_SCRIPT}"; exit 1; fi
    run_cmd_or_exit cp "${SOURCE_MANAGE_USERS_SCRIPT}" "${MANAGEMENT_SCRIPT_PATH}"; run_cmd_or_exit chmod +x "${MANAGEMENT_SCRIPT_PATH}"

    log_info "Creating Sing-Box systemd service file..."
    run_cmd_or_exit process_template "${TEMPLATE_SINGBOX_SERVICE}" "/etc/systemd/system/sing-box.service"
    run_cmd_or_exit systemctl daemon-reload; run_cmd_or_exit systemctl enable sing-box || log_warn "Fld to enable sing-box."
    log_info "Sing-Box setup complete."
    eval "$prev_opts"
}

# Step 5: Setup Subscription Flask App
setup_subscription_app() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Setting up Python Flask subscription application..."
    run_cmd_or_exit mkdir -p "${SUBSCRIPTION_APP_DIR}/templates" "${SUBSCRIPTION_APP_DIR}/static"
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"; run_cmd_or_exit chmod 750 "${SUBSCRIPTION_APP_DIR}"

    log_info "Creating Python virtual environment..."; run_cmd_or_exit python3 -m venv "${SUBSCRIPTION_APP_DIR}/venv"
    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}/venv"
    log_info "Installing Flask/Gunicorn into venv..."
    run_cmd_or_exit "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install --upgrade pip
    run_cmd_or_exit "${SUBSCRIPTION_APP_DIR}/venv/bin/pip" install Flask gunicorn

    log_info "Copying Flask application files...";
    if [ ! -f "$SOURCE_FLASK_APP_PY" ]; then log_error "Flask app.py not found."; exit 1; fi; run_cmd_or_exit cp "${SOURCE_FLASK_APP_PY}" "${SUBSCRIPTION_APP_DIR}/app.py"
    if [ ! -f "$SOURCE_FLASK_INDEX_HTML" ]; then log_error "Flask index.html not found."; exit 1; fi; run_cmd_or_exit cp "${SOURCE_FLASK_INDEX_HTML}" "${SUBSCRIPTION_APP_DIR}/templates/index.html"
    if [ -f "$SOURCE_FLASK_STATIC_README" ]; then run_cmd_or_exit cp "${SOURCE_FLASK_STATIC_README}" "${SUBSCRIPTION_APP_DIR}/static/README.md"; else log_warn "Static README for Flask app not found."; fi

    run_cmd_or_exit chown -R "${SUBAPP_USER}":"${SUBAPP_GROUP}" "${SUBSCRIPTION_APP_DIR}"
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}" -type d -exec chmod 750 {} \;
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}" -type f -exec chmod 640 {} \;
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}/venv/bin/" -type f -user "${SUBAPP_USER}" -exec chmod u+x {} \; # Ensure owner can execute
    run_cmd_or_exit find "${SUBSCRIPTION_APP_DIR}/venv/bin/" -type f -perm /g+x -user "${SUBAPP_USER}" -exec chmod g+x {} \; # Ensure group can execute if owner can
    run_cmd_or_exit chmod u+x "${SUBSCRIPTION_APP_DIR}/venv/bin/activate"*

    log_info "Creating systemd service for Flask app..."
    run_cmd_or_exit process_template "${TEMPLATE_SUBAPP_SERVICE}" "/etc/systemd/system/subscription-app.service"
    run_cmd_or_exit systemctl daemon-reload; run_cmd_or_exit systemctl enable subscription-app || log_warn "Fld to enable subscription-app."
    log_info "Subscription Flask app setup complete."
    eval "$prev_opts"
}

# Step 6: Setup HAProxy
setup_haproxy() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring HAProxy..."
    HAPROXY_LOG_CONF="/etc/rsyslog.d/49-haproxy.conf"
    if [ ! -f "$HAPROXY_LOG_CONF" ] || ! grep -q '/var/log/haproxy.log' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
         log_info "Configuring rsyslog for HAProxy..."; run_cmd_or_exit bash -c "echo 'local0.*    /var/log/haproxy.log' > \"$HAPROXY_LOG_CONF\" && echo '& stop' >> \"$HAPROXY_LOG_CONF\""
         run_cmd_or_exit touch /var/log/haproxy.log; run_cmd_or_exit chown syslog:adm /var/log/haproxy.log; run_cmd_or_exit chmod 640 /var/log/haproxy.log
         run_cmd_or_exit systemctl restart rsyslog || log_warn "Fld to restart rsyslog."; else log_info "Rsyslog for HAProxy seems configured."; fi

    log_info "Creating HAProxy configuration file..."
    run_cmd_or_exit process_template "${TEMPLATE_HAPROXY_CFG}" "/etc/haproxy/haproxy.cfg"
    log_info "Validating HAProxy configuration..."
    if haproxy -c -f /etc/haproxy/haproxy.cfg; then log_info "HAProxy config OK.";
    else log_error "HAProxy config check FAILED!"; exit 1; fi
    log_info "HAProxy configuration complete."
    eval "$prev_opts"
}

# Step 7: Setup Fail2ban
setup_fail2ban() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring Fail2ban..."
    FAIL2BAN_FILTER_DEST="/etc/fail2ban/filter.d/haproxy-custom.conf"
    log_info "Copying Fail2ban filter..."; if [ ! -f "$TEMPLATE_FAIL2BAN_FILTER" ]; then log_error "Fail2ban filter template not found."; exit 1; fi
    run_cmd_or_exit mkdir -p "$(dirname "$FAIL2BAN_FILTER_DEST")"; run_cmd_or_exit cp "${TEMPLATE_FAIL2BAN_FILTER}" "${FAIL2BAN_FILTER_DEST}"

    FAIL2BAN_JAIL_DEST="/etc/fail2ban/jail.d/haproxy-custom.conf"
    log_info "Creating Fail2ban jail config..."
    run_cmd_or_exit process_template "${TEMPLATE_FAIL2BAN_JAIL}" "${FAIL2BAN_JAIL_DEST}"
    log_info "Reloading Fail2ban service..."
    run_cmd_or_exit systemctl reload fail2ban || { log_error "Fail2ban reload failed."; exit 1; }
    log_info "Fail2ban setup complete."
    eval "$prev_opts"
}

# Step 8: Setup Firewall
setup_firewall() {
    local prev_opts; prev_opts=$(set +o); set -e
    log_info "Configuring firewall (ufw)..."; check_command "ufw"
    run_cmd_or_exit ufw default deny incoming; run_cmd_or_exit ufw default allow outgoing
    log_info "Allowing essential services..."; run_cmd_or_exit ufw allow ssh comment 'SSH'
    run_cmd_or_exit ufw allow "${SUBSCRIPTION_SITE_PORT}/tcp" comment "Sub Site"
    run_cmd_or_exit ufw allow "${VLESS_HTTPUPGRADE_PORT}/tcp" comment "VLESS"
    run_cmd_or_exit ufw allow "${HYSTERIA2_PORT}/udp" comment "Hysteria2"
    run_cmd_or_exit ufw allow from 127.0.0.1 comment 'Loopback'; run_cmd_or_exit ufw allow to 127.0.0.1
    run_cmd_or_exit ufw limit ssh comment 'Rate Limit SSH'
    if ! ufw status | grep -qw active; then log_info "Enabling firewall..."; run_cmd_or_exit ufw --force enable;
    else log_info "Reloading firewall..."; run_cmd_or_exit ufw reload; fi
    log_info "Current firewall status:"; run_cmd_or_exit ufw status verbose
    log_info "Firewall configured."
    eval "$prev_opts"
}

# Step 9: Start/Restart Services
start_services() {
    # Do not use set -e here, as we want to try starting all services and report individual failures.
    log_info "Starting/Restarting all configured services..."
    systemctl restart haproxy || log_warn "Failed to restart haproxy. Check config and logs."
    systemctl restart sing-box || log_warn "Failed to restart sing-box. Check config and logs."
    systemctl restart subscription-app || log_warn "Failed to restart subscription-app. Check config and logs."
    systemctl restart fail2ban || log_warn "Failed to restart fail2ban. Check config and logs."

    log_info "Waiting briefly for services to initialize..."
    sleep 5
    log_info "Verifying service statuses:"
    local failed_svcs=0
    for svc in haproxy sing-box subscription-app fail2ban; do
        if systemctl is-active --quiet "$svc"; then log_info "  - ${svc}: Active";
        else log_error "  - ${svc}: FAILED or Inactive"; failed_svcs=$((failed_svcs + 1)); fi
    done
    local flask_url="http://127.0.0.1:${SUBSCRIPTION_APP_LISTEN_PORT}${SUBSCRIPTION_BASE64_PATH}"
    if curl --fail --silent --head --max-time 5 "${flask_url}" &>/dev/null; then
         log_info "  - Subscription app responding locally on its obscured path.";
    else log_error "  - Subscription app NOT responding locally. Check: journalctl -u subscription-app"; failed_svcs=$((failed_svcs + 1)); fi

    if [ $failed_svcs -gt 0 ]; then
        log_warn "One or more services may have failed to start or respond correctly. Please review logs using 'journalctl -u <service_name>'."
    else log_info "All services appear to be running correctly."; fi
}

# --- Step 10: Main Execution Orchestration ---
main() {
    # Enable strict error checking for the main execution flow
    local prev_main_opts; prev_main_opts=$(set +o); set -e

    log_info "Starting Secure Proxy Platform Deployment from version 1.5 (SIGPIPE Debugging Focus)..."
    run_cmd_or_exit pre_flight_checks
    run_cmd_or_exit install_dependencies
    run_cmd_or_exit setup_certificates
    run_cmd_or_exit setup_singbox
    run_cmd_or_exit setup_subscription_app
    run_cmd_or_exit setup_haproxy
    run_cmd_or_exit setup_fail2ban
    run_cmd_or_exit setup_firewall
    # start_services handles its own error reporting without exiting script immediately
    start_services
    eval "$prev_main_opts" # Restore options before summary

    log_info "--- Deployment Complete ---"
    # (Final Summary Output - ensure all variables are correctly displayed)
    echo "=============================================================================="
    echo " [IMPORTANT] Configuration Details - SAVE THIS SECURELY!"
    echo "=============================================================================="
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
    echo "   - Ensure DNS records for ${MAIN_DOMAIN} and ${SUBSCRIPTION_DOMAIN} point to this server's IP."
    echo "   - Place desired background image at: ${SUBSCRIPTION_APP_DIR}/static/background.jpg (as per static/README.md)"
    echo "   - SSL Certificates will auto-renew via Certbot."
    echo "   - Review logs: journalctl -u <service_name>, /var/log/haproxy.log, /var/log/fail2ban.log"
    echo "=============================================================================="
    log_info "Deployment script finished successfully."
}

# --- Run Main Function ---
main "$@"

# cleanup_exit is handled by trap, final successful exit is 0 if main completes without error
exit 0
